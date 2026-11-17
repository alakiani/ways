# WAYMATE

WAYMATE (همراه, "companion" in Farsi) is messaging and video calls for WAYS Users: a private
[Matrix](https://matrix.org) server with [Element Call](https://github.com/element-hq/element-call)
on [LiveKit](https://livekit.io), signed in to with a WAYS account. Messages and calls are
end-to-end encrypted. It talks to no other Matrix server.

WAYMATE lives in this repository but is its own product. It has its own VM, hostname, releases
(`waymate-v*` tags), pipeline (`.github/workflows/waymate-*.yml`) and laptop folder (`~/.waymate`).
Nothing under `waymate/` is built into WAYS, and WAYS builds and releases without it.

## What runs on the VM

Everything is served on one hostname, such as `chat.wayfinder.ir`, by nginx.

| Path | Service | What it does |
| --- | --- | --- |
| `/` | Element Web | The browser client; Element Call is built in |
| `/_matrix/` | Synapse | The Matrix homeserver: accounts, rooms, messages |
| `/auth/` | Matrix Authentication Service (MAS) | Sign-in and sessions; hands sign-in to WAYS |
| `/livekit/jwt/` | MatrixRTC authorization service | Lets a signed-in user into the call of a room they are in |
| `/livekit/sfu/` | LiveKit | Forwards call media between participants |

Synapse and MAS keep their data in PostgreSQL on the same VM. On phones, people use
[Element X](https://element.io/app) and enter the hostname as their server.

A release pins one version of each of these (`versions.env`). WAYMATE has no code of its own to
compile: a release is the upstream packages, checked against their checksums, that the playbook
installs together.

## How it connects to WAYS

**Sign-in.** WAYMATE has no accounts of its own. MAS sends everyone to the WAYS Coordinator, as an
OpenID Connect client, and a WAYS handle becomes a Matrix ID: `@handle:chat.wayfinder.ir`. What the
Coordinator has to provide:

- OpenID Connect discovery at the issuer (`WAYMATE_OIDC_ISSUER`), the authorization code flow with
  PKCE, and ID tokens signed with RS256.
- One client, `waymate`, with a secret (sent as HTTP Basic auth to the token endpoint), and these
  two URLs:
  - redirect: `https://<hostname>/auth/upstream/callback/01JWAYMATE000000000000WAYS`
  - back-channel logout: `https://<hostname>/auth/upstream/backchannel-logout/01JWAYMATE000000000000WAYS`
- Claims for the `openid profile` scopes: `sub`, a User's permanent id; `preferred_username`, their
  handle; and optionally `name`.
- For a Suspended or deleted User: refuse sign-in, and send a back-channel logout, which ends their
  WAYMATE sessions on every device.

**The Coordinator is not an OpenID Provider yet.** Until it is, leave `WAYMATE_OIDC_ISSUER` empty:
WAYMATE then keeps its own passwords, and you create each account on the VM
(`sudo waymate-mas manage register-user`). Accounts made that way keep working after the switch only
if their handles match.

**Tunnels.** Users need nothing new: a domestic WAYMATE VM is an Iranian address, so a Device's
traffic to it already leaves through an Exit tagged `IR`. The VM itself may need WAYS in the other
direction. Phones are woken through Element's push gateway (`matrix.org`), which hands the wake-up to
Apple or Google; a VM inside Iran that can't reach it can be given a WAYS Device
(`WAYMATE_WAYS_DEVICE_CONF`). Only Synapse's outbound traffic then leaves through WAYS, and only the
gateway's name is looked up through the Bridge resolver.

## Deploying

Packages are pushed from the laptop, never pulled by the VM.

1. **Rent the VM:** Ubuntu 26.04, one public IPv4, SSH access; 2 vCPU and 4 GB to start. Open TCP
   80 and 443, TCP 7881 and UDP 7882 (call media).
2. **Point the hostname at it,** and get a certificate for it (the example `waymate.env` shows the
   `acme.sh` commands).
3. **Describe it:** copy `deploy/examples/waymate.env` and `deploy/examples/inventory.yml` to
   `~/.waymate/` and fill them in.
4. **Fetch a release:** `waymate/scripts/fetch-release.sh waymate-v0.1.0` downloads it to
   `~/.waymate/releases/` and checks its SHA256SUMS. It is about 190 MB.
5. **Deploy:** `waymate/scripts/waymate-ansible waymate.yml`.

Rerunning the playbook with a newer release upgrades in place; with the same release it changes
nothing. It first checks every file of the release against `SHA256SUMS`, and it ends by waiting for
every service to answer. `WAYMATE_RELEASE=waymate-v0.1.0` picks a release; the default is the newest
one fetched.

The hostname is also the Matrix server name, the part after the colon in every user ID. **It can
never change after the first run.**

Secrets are made on the VM (`/etc/waymate/secrets`) and never leave it. The only secret on the
laptop is the WAYS sign-in secret, because the Coordinator holds the other half.

## On the VM

| Unit | Service |
| --- | --- |
| `matrix-synapse` | Synapse (from its Ubuntu package; config in `/etc/matrix-synapse/conf.d/waymate.yaml`) |
| `waymate-mas` | Matrix Authentication Service |
| `waymate-livekit` | LiveKit |
| `waymate-lk-jwt` | MatrixRTC authorization service |
| `nginx`, `postgresql` | From Ubuntu |
| `wg-quick@ways-out` | The VM's WAYS Device, if one is configured |

`sudo waymate-mas` runs the MAS command line as the service does: `manage register-user`,
`manage lock-user HANDLE`, `manage kill-sessions HANDLE`, `doctor`.

There is no backup yet. What must survive is the two databases (`synapse`, `mas`), Synapse's media
in `/var/lib/matrix-synapse/media`, and `/etc/waymate/secrets` with
`/etc/matrix-synapse/homeserver.signing.key`.

## Developing

- **A release** is published by pushing a tag: `git tag waymate-v0.1.0 && git push origin waymate-v0.1.0`.
- **To move to a newer upstream version,** change it and its checksum in `versions.env`.
- **The test** (`test/deploy-test.sh RELEASE_DIR`) runs the playbook against an Ubuntu 26.04
  container, then signs a user in and takes them as far as a LiveKit token for a call in their
  room, and runs the playbook again to see that it changes nothing. CI runs it on every change
  under `waymate/`. Locally:

  ```sh
  waymate/scripts/build-release.sh dev /tmp/waymate-dev
  waymate/test/deploy-test.sh /tmp/waymate-dev
  ```

  The release is amd64, so on an Apple Silicon laptop the container is emulated; the script
  adapts to that (its header says how). It also checks the WAYS Device's routing on the VM and
  that MAS hands sign-in to WAYS. It does not cover a real tunnel to a Bridge, a real sign-in
  through the Coordinator, or media flowing in a call.
