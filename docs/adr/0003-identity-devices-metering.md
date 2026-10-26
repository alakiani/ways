---
status: accepted
---

# Identity, Devices, and metering: keys made in the browser, no session history

Device keypairs are generated in the User's browser, so no WAYS server ever holds a private key. Users sign in with built-in credentials, without any third party. The Coordinator keeps usage at a resolution that supports quotas but not a fine record of when someone was online. This refines [ADR 0001](0001-coordinator-architecture.md), which fixed built-in auth and data minimisation, and [ADR 0002](0002-agent-coordinator-protocol.md), which fixed hourly metering buckets on Bridges. Resolved in [Identity, Device issuance, and metering model](https://github.com/alakiani/ways/issues/8).

## Users, Invites, and sign-in

- **Invites:** only an Admin creates them. An Invite is single-use, valid 7 days, and may preset the User's Device cap. The invited person chooses a handle, then registers a passkey, or a password if WebAuthn fails (ADR 0001).
- **Recovery:** with no email or phone, an Admin issues a **recovery Invite** for an existing User. It replaces their credentials and leaves their Devices untouched.
- **Sessions and second factor:** panel sessions last 30 days. TOTP is optional for Users and mandatory for Admins.
- **No third-party sign-in**, whether Google, Apple, Telegram, SMS, or email. Each is unreliable from inside Iran and would tie a User to a real-world identity.
- **User operations:**
  - **Suspend** (reversible): every Device of the User leaves the Bridge snapshots but keeps its key.
  - **Delete:** removes the User, their Devices, and their usage, with no anonymised remainder.

## Devices

- **Who creates them:** Users, self-service, up to a per-User **Device cap** set by an Admin (default 3). This is the only quota in phase one.
- **Key generation happens in the browser.** The panel page generates an X25519 keypair and submits only the public key. It then renders the `.conf` file and QR code locally. Closing the page is the one-time display: the private key never reaches the Coordinator or any Node, so even a seized and tampered Coordinator cannot log keys. No preshared key is used, since it would be a secret held by the Coordinator and every Bridge.
- **Tunnel addresses:**
  - Each Device gets one IPv4 `/32` from a private pool (such as `10.77.0.0/16`), stable for its lifetime and the same on every Bridge. *(Amended by [ADR 0014](0014-abroad-devices.md): ordinary Devices take `10.77.0.0/17` and Abroad Devices `10.77.128.0/17`.)*
  - An address returns to the pool only once that Device's usage data has expired, so metering never mixes two Devices.
- **IPv6 is black-holed, not supported.** Each config claims `::/0` alongside `0.0.0.0/0` and carries one placeholder ULA `/128`. Bridges drop all IPv6. Apps on dual-stack mobile networks (MCI, Irancell) therefore fall back to IPv4 inside the tunnel instead of leaking IPv6 around it. Nothing routes IPv6 anywhere.
- **Lifecycle:**
  - **Revoke**, by the User or an Admin, removes the Device from the next snapshots and erases its public key. Its id, name, and usage remain until retention expires.
  - **There is no rotation.** A lost or leaked config is handled by **Replace**, which issues a new Device and revokes the old one in a single action.
  - A config cannot be downloaded again, because no one has the private key.

## Metering retention on the Coordinator

This supersedes ADR 0001's "hourly for 90 days":

| Resolution | Kept for |
| --- | --- |
| Hourly, per Device per Exit | 7 days (live usage, troubleshooting) |
| Daily, per Device per Exit | 90 days |
| Monthly, per Device | until the User is deleted |

Nothing finer is stored. There are no session records and no connection start or end times. Bridges still keep hourly buckets on disk and upload them as ADR 0002 describes; the Coordinator downsamples as each bucket ages.

## Quota hooks

_[ADR 0010](0010-per-user-usage-and-quota.md) fills these hooks with a per-User Quota and adds a per-User period total to the retention table above._

- **Every Device has an effective state:** `active`, `blocked`, or `throttled(rate)`, plus a `reason`. Snapshots carry it, and Bridges enforce it.
- **A pure policy function in the Coordinator** derives that state from User status, Device status, and the per-User daily and monthly usage totals.
- **Phase one ships a single policy:** a suspended User or a revoked Device is `blocked`, and everything else is `active`. *(Amended by [ADR 0014](0014-abroad-devices.md): an Abroad Device whose User lacks the abroad permission is also `blocked`.)*
- **Room for later:** `throttled` exists in the model, but Bridges implement it only when a quota feature needs it.
- **Accepted limit:** usage arrives hourly, so a future quota may overshoot by up to an hour of traffic.
