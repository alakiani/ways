---
status: accepted; Endpoint Slots and Backups superseded by ADR 0011
---

# Client-hop failover: three domestic Endpoint Slots, one shared Bridge identity, one user action

Stock WireGuard apps never re-resolve an endpoint while the tunnel is up, never report a dead endpoint, and hold one endpoint per config (research for issue #4). Without a provider floating IP, hands-free recovery is therefore impossible on every platform. Instead, each Device carries three configs, one per **Endpoint Slot**. Each slot is a hostname the Coordinator keeps pointed at a healthy domestic Bridge, and every Bridge presents the same WireGuard identity. Recovery is one user action: toggle the tunnel, or switch to a Backup. This replaces the map's earlier "one config per Device" note. Resolved in [Client-hop failover for stock WireGuard](https://github.com/alakiani/ways/issues/10).

## When a Device must hop

Client-hop is needed when a Device's Bridge cannot carry its traffic:
- The Bridge is unreachable from Users (machine down, provider outage, IP blocked, connectivity cut by the provider).
- The Bridge is alive but has no working Path for the default Rule, even through the mesh.

Failures of a Bridge's Links or Exits that the mesh can route around (ADR 0004) never reach the Device.

## Endpoint Slots

> Superseded by [ADR 0011](0011-bridge-address.md): one Bridge Address replaces the three slots and the Backup configs.

- **Three slots, all domestic:** `a.wayfinder.ir`, `b.wayfinder.ir`, `c.wayfinder.ir`. No abroad Bridge ever faces Devices; abroad Nodes holding the Bridge Role serve only as transit inside the mesh. *(Amended by [ADR 0014](0014-abroad-devices.md): Abroad Bridges face Abroad Devices through their own Abroad Bridge Address.)* **Accepted cost:** if every domestic Bridge is unreachable, Devices have no fallback.
- **Slots are global, not per Device.** Each Device resolves the same three names before its tunnel is up, through the ISP's plaintext DNS. Per-Device names would tag a Device to the filter on every connect.
- **Rotation balances load.** At issuance, a Device's configs are labelled Main, Backup 1, and Backup 2, rotated across the slots by Device id (Main is slot `id mod 3`, followed by the next two). Labels are fixed once issued; rebalancing later is done by re-pointing slots.
- **Assignment:** the slots point at different domestic Bridges whenever enough are eligible. With two domestic Bridges, `c` shares one with `a` or `b` until a third exists. When a Bridge fails, its slots move to surviving Bridges, so several slots may share one.
- **Eligibility.** A Bridge may hold a slot only while all three of these hold:
  1. The probe Device's check against it is passing.
  2. Its Agent is reporting.
  3. It has a working default-Rule Path, directly or through the mesh (at least one eligible candidate for the default Rule, [ADR 0008](0008-path-selection-and-exit-balancing.md)).
- **Re-pointing:**
  - A slot moves after its Bridge has been ineligible for 60 s.
  - It does not move back automatically when that Bridge recovers.
  - *(An Admin can rebalance the slots on demand from the panel: the fewest moves that spread them over the eligible Bridges. They still never move back automatically. Decided in [#49](https://github.com/alakiani/ways/issues/49).)*
  - The Coordinator updates the record through the ArvanCloud DNS API, with the lowest TTL ArvanCloud allows (target 60 s).
  - Self-hosting DNS on the Coordinator was rejected, because a dead Coordinator would then stop every Device from resolving.
- **Floating IPs are an optional optimisation.** Where a provider offers one, a slot may use it and have the Agent move it, giving zero-touch recovery for that slot. It is never required (inventory constraint 2).

## Shared Bridge identity

- **Every Bridge presents one WireGuard keypair**, so a config works on whichever Bridge its slot points at, and all Bridges accept every non-blocked Device (ADR 0004).
- **Every Bridge listens for Devices on one UDP port**, `61873` by default, held by the Coordinator and written into every config. It is outside the 10000–60000 range Link instances draw from (ADR 0007), so the two never collide on a Bridge, and avoids `51820`, the WireGuard default. Changing it affects only configs issued afterwards. *(Decided in [MVP 04](https://github.com/alakiani/ways/issues/20).)*
- **The private key is held by the Coordinator and shipped only in Bridge snapshots.** Exits never receive it. *(Since [ADR 0014](0014-abroad-devices.md), Abroad Bridges receive it too.)* It is included in the age-encrypted nightly backup.
- **Why the Coordinator holds it:** portability. Bridges can be added or rebuilt without the operator's laptop. The rejected alternative was to generate the key on the laptop and distribute it by Ansible only.
- **Accepted risk:** whoever seizes the domestic Coordinator gets the key that impersonates every Bridge. If ArvanCloud is compelled to re-point the slot records as well, a state actor could intercept Users' traffic before it enters a Link. A seized Bridge leaks the same key.
- **Rotation** means every User must Replace every Device. It is an emergency procedure, announced with a panel banner.

## Probe Device

The Coordinator host runs a probe Device: a real Device keypair belonging to no User and counted toward no cap. Every 15 s it handshakes with each domestic Bridge's public IP and queries the in-tunnel resolver through it. That is the User's-eye check from one domestic vantage point, and the overview shows it.

## What the User experiences

- When a Bridge fails, the tunnel still shows "connected" and nothing loads.
- **Toggling the tunnel off and on** re-resolves the hostname and reaches the re-pointed slot. That takes about 1 to 3 minutes after the failure; Android caches the resolved address for 2 minutes.
- **Switching to Backup 1, then Backup 2,** recovers within seconds if the Backup's slot is on a live Bridge.
- The help page and the Device page say exactly this.

## Consequences for earlier decisions

- **Issuance delivers three configs:** a .zip plus a QR code per slot, as in the panel prototype. They share the keypair, the tunnel address, and the shared Bridge public key, and differ only in `Endpoint`.
- **The glossary** now has **Endpoint Slot**, and **Device** is a keypair with one config per Endpoint Slot.
