#!/usr/bin/env bash
# build-release.sh VERSION OUTDIR builds one WAYMATE release: the pinned
# upstream packages from waymate/versions.env, each checked against its
# checksum, plus a SHA256SUMS over them. WAYMATE has no code of its own to
# compile; a release is the set of versions the playbook installs together.
#
# WAYMATE_DOWNLOAD_CACHE, if set, keeps the downloads between builds.
set -euo pipefail
version="$1" out="$2"
root="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source-path=SCRIPTDIR source=../versions.env
. "$root/versions.env"
cache="${WAYMATE_DOWNLOAD_CACHE:-$(mktemp -d)}"
mkdir -p "$out" "$cache"

sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

fetch() { # fetch URL SHA256 NAME: download once, check, and copy in as NAME
  local file="$cache/$3"
  if [[ "$(sha256 "$file" 2>/dev/null | cut -d' ' -f1)" != "$2" ]]; then
    echo "downloading $3" >&2
    curl -fsSL --retry 3 -o "$file" "$1"
    [[ "$(sha256 "$file" | cut -d' ' -f1)" == "$2" ]] || { echo "checksum mismatch for $1" >&2; exit 1; }
  fi
  cp "$file" "$out/$3"
}

# The names carry the version and no "+", which GitHub would rewrite in a
# release asset's name.
fetch "https://packages.matrix.org/debian/pool/main/m/matrix-synapse-py3/matrix-synapse-py3_${SYNAPSE_DEB}_amd64.deb" \
  "$SYNAPSE_SHA256" "synapse-$SYNAPSE-amd64.deb"
fetch "https://github.com/element-hq/matrix-authentication-service/releases/download/v$MAS/mas-cli-x86_64-linux.tar.gz" \
  "$MAS_SHA256" "mas-$MAS-x86_64-linux.tar.gz"
fetch "https://github.com/livekit/livekit/releases/download/v$LIVEKIT/livekit_${LIVEKIT}_linux_amd64.tar.gz" \
  "$LIVEKIT_SHA256" "livekit-$LIVEKIT-linux-amd64.tar.gz"
fetch "https://github.com/element-hq/lk-jwt-service/releases/download/v$LK_JWT/lk-jwt-service_linux_amd64" \
  "$LK_JWT_SHA256" "lk-jwt-service-$LK_JWT-linux-amd64"
fetch "https://github.com/element-hq/element-web/releases/download/v$ELEMENT_WEB/element-v$ELEMENT_WEB.tar.gz" \
  "$ELEMENT_WEB_SHA256" "element-web-$ELEMENT_WEB.tar.gz"

cp "$root/versions.env" "$out/versions.env"
echo "$version" > "$out/VERSION"
(cd "$out" && sha256 -- * | grep -v ' SHA256SUMS$' > SHA256SUMS)
echo "built $version in $out"
