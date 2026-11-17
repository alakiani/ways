#!/usr/bin/env bash
# deploy-test.sh RELEASE_DIR runs waymate.yml against a throwaway Ubuntu 26.04
# container, through the same waymate/scripts/waymate-ansible the operator
# runs, with a release bundle from waymate/scripts/build-release.sh. It then
# checks the result from inside (test/check.py) and runs the playbook again,
# which must change nothing.
#
# Needs Docker, ansible-playbook and openssl. WAYMATE_TEST_KEEP=1 leaves the
# container (waymate-deploytest) running.
#
# The release is linux/amd64. On an arm64 laptop Docker must be able to run
# amd64 containers, and Ansible then reaches the container through Docker
# (the community.docker collection) instead of SSH: sshd's sandbox does not
# survive emulation.
set -euo pipefail
release_dir="$(cd "$1" && pwd)"
root="$(cd "$(dirname "$0")/.." && pwd)"
domain=chat.waymate.test
name=waymate-deploytest
work="$(mktemp -d)"
cleanup() {
  [[ -n "${WAYMATE_TEST_KEEP:-}" ]] || docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
step() { printf '\n== %s\n' "$*"; }

step "A certificate for $domain, from a throwaway CA the container trusts"
# Python 3.13+ verifies strictly: it wants the key identifiers and key usages
# a public CA always sets.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=WAYMATE test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -keyout "$work/ca.key" -out "$work/ca.crt" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=$domain" -keyout "$work/tls.key" -out "$work/tls.csr" 2>/dev/null
cat > "$work/san.cnf" <<EOF
subjectAltName=DNS:$domain
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
openssl x509 -req -in "$work/tls.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" -CAcreateserial \
  -days 2 -extfile "$work/san.cnf" -out "$work/tls.crt" 2>/dev/null

step "A fresh VM"
docker build -q --platform linux/amd64 -t "$name" "$root/test" >/dev/null
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --privileged --platform linux/amd64 --name "$name" --hostname waymate-01 \
  -p 127.0.0.1::22 --tmpfs /run --tmpfs /run/lock "$name" >/dev/null
port="$(docker port "$name" 22/tcp | head -n1 | sed 's/.*://')"
# Let it finish booting first: systemd mounts a new /tmp on the way up.
for _ in $(seq 120); do
  case "$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)" in running|degraded) break ;; esac
  sleep 1
done
docker exec -i "$name" sh -c 'cat > /usr/local/share/ca-certificates/waymate-test.crt && update-ca-certificates >/dev/null 2>&1' < "$work/ca.crt"
ssh-keygen -q -t ed25519 -N "" -f "$work/key"
if [[ "$(docker version --format '{{.Server.Arch}}')" == amd64 ]]; then
  docker exec -i "$name" sh -c 'mkdir -p /root/.ssh && cat > /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys' < "$work/key.pub"
  ssh_opts=(-i "$work/key" -p "$port" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
  for _ in $(seq 60); do ssh "${ssh_opts[@]}" root@127.0.0.1 true 2>/dev/null && break; sleep 1; done
  ssh "${ssh_opts[@]}" root@127.0.0.1 true
  host="{ansible_host: 127.0.0.1, ansible_port: $port, ansible_user: root}"
else
  host="{ansible_connection: community.docker.docker, ansible_host: $name, ansible_user: root}"
  # Ubuntu 26.04's tar needs openat2(), which Rosetta lacks. Ansible prefers
  # a gtar when it finds one, so it gets 24.04's.
  docker rm -f "$name-tar" >/dev/null 2>&1 || true
  docker create --platform linux/amd64 --name "$name-tar" ubuntu:24.04 >/dev/null
  docker cp -q "$name-tar:/usr/bin/tar" "$work/gtar"
  docker rm "$name-tar" >/dev/null
  docker cp -q "$work/gtar" "$name:/usr/local/bin/gtar"
fi

step "The operator's ~/.waymate"
home="$work/home"
mkdir -p "$home/releases"
ln -s "$release_dir" "$home/releases/ci"
cat > "$home/inventory.yml" <<EOF
all:
  vars:
    ansible_ssh_private_key_file: $work/key
    ansible_ssh_common_args: -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
  children:
    waymate:
      hosts:
        waymate-01: $host
EOF
cat > "$home/waymate.env" <<EOF
WAYMATE_DOMAIN=$domain
WAYMATE_TLS_CERT_FILE=$work/tls.crt
WAYMATE_TLS_KEY_FILE=$work/tls.key
WAYMATE_PUBLIC_IP=203.0.113.10
EOF
play() {
  WAYMATE_HOME="$home" WAYMATE_RELEASE=ci ANSIBLE_FORCE_COLOR=0 ANSIBLE_NOCOLOR=1 \
    "$root/scripts/waymate-ansible" waymate.yml -e '{"waymate_chrony": false}'
}

step "The playbook, on the fresh VM"
play

step "What it deployed"
docker exec -i "$name" python3 - "$domain" < "$root/test/check.py"

step "The playbook again: it must change nothing"
play | tee "$work/second.log"
grep -q 'changed=0 ' "$work/second.log" || { echo "FAIL: the second run changed something" >&2; exit 1; }

step "With a WAYS Device, Synapse's outbound traffic takes it and nothing else changes"
if docker exec "$name" sh -c 'ip link add wgprobe type wireguard 2>/dev/null && ip link del wgprobe'; then
  # A Device config as the panel renders it. No Bridge answers at its
  # endpoint: this checks the routing on the VM, not the tunnel.
  cat > "$work/device.conf" <<EOF
[Interface]
PrivateKey = $(openssl rand -base64 32)
Address = 10.77.0.9/32, fd77::9/128
DNS = 10.77.0.1

[Peer]
PublicKey = $(openssl rand -base64 32)
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 127.0.0.1:61873
PersistentKeepalive = 25
EOF
  cp "$home/waymate.env" "$work/waymate.env.plain"
  echo "WAYMATE_WAYS_DEVICE_CONF=$work/device.conf" >> "$home/waymate.env"
  play
  uid="$(docker exec "$name" id -u matrix-synapse)"
  docker exec "$name" ip route get 203.0.113.1 uid "$uid" | grep -q 'dev ways-out' \
    || { echo "FAIL: Synapse's outbound traffic does not take the WAYS Device" >&2; exit 1; }
  docker exec "$name" ip route get 203.0.113.1 | grep -q 'dev ways-out' \
    && { echo "FAIL: other traffic takes the WAYS Device too" >&2; exit 1; }
  docker exec -i "$name" python3 - "$domain" < "$root/test/check.py"
  cp "$work/waymate.env.plain" "$home/waymate.env"
  play
  docker exec "$name" sh -c '! ip link show ways-out 2>/dev/null && ! ip rule | grep -q 7767' \
    || { echo "FAIL: the WAYS Device was not taken down" >&2; exit 1; }
else
  echo "skipped: this kernel has no WireGuard"
fi

step "With WAYS sign-in configured, MAS sends people to WAYS"
# No OpenID Provider answers at this issuer: this checks that MAS accepts the
# configuration and hands sign-in over, not the sign-in itself.
cat >> "$home/waymate.env" <<EOF
WAYMATE_OIDC_ISSUER=https://ways.waymate.test
WAYMATE_OIDC_CLIENT_SECRET=not-a-real-secret
EOF
play
to="$(docker exec "$name" curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' "https://$domain/auth/login")"
echo "GET /auth/login -> $to"
case "$to" in
  3??" https://$domain/auth/upstream/authorize/01JWAYMATE000000000000WAYS"*) ;;
  *) echo "FAIL: MAS did not send sign-in to the WAYS provider" >&2; exit 1 ;;
esac

printf '\nPASS\n'
