---
status: accepted
---

# One Bridge Address answering with one eligible Bridge per lookup replaces the three Endpoint Slots

Every Device carries **one** config whose `Endpoint` is the **Bridge Address**, `bridge.wayfinder.ir`. Its A record lists every eligible domestic Bridge, and ArvanCloud answers each lookup with **one** of them, taking turns. The Coordinator adds and removes Bridges from that record as their eligibility changes. This replaces the Endpoint Slots and the Backup configs of [ADR 0005](0005-client-hop-failover.md); the rest of ADR 0005 (shared Bridge identity, port, probe Device) stands. Slot assignment, re-pointing and the Admin's rebalance ([#49](https://github.com/alakiani/ways/issues/49)) all go away: we trade recovery speed for one config and no slot bookkeeping.

## The record

- **Held by the Coordinator** as a setting, default `bridge.wayfinder.ir`, written into each config at issuance like the Device port. Changing it affects only configs issued afterwards.
- **One answer per lookup, in rotation**, through the record's `ip_filter_mode` (`count` single, `order` round robin) on ArvanCloud's DNS API. Lowest TTL ArvanCloud allows (target 60 s), unproxied.
- **Every eligible domestic Bridge is in the record.** There are no unpublished spares. Abroad Bridges are never published (unchanged from ADR 0005). *(Amended by [ADR 0014](0014-abroad-devices.md): Abroad Bridges are published in their own Abroad Bridge Address, never in this one.)*
- **Eligibility is ADR 0005's, unchanged:** the probe Device's check passes, the Agent is reporting, and there is a working default-Rule Path.
- **Removal:** a Bridge leaves the record after 60 s ineligible.
- **Return:** a Bridge rejoins on its own after 5 minutes eligible again. Unlike a slot, rejoining moves no one: only new lookups can land on it.
- **Never empty.** The last Bridge in the record is never removed. If every Bridge is ineligible, the record stays as it was, because a lookup that fails is certainly dead and a Bridge that may be dead is not.

## What the User experiences

- When their Bridge fails, the tunnel still shows "connected" and nothing loads. Toggling the tunnel off and on re-resolves the Bridge Address. Once the Bridge has been removed and caches have expired (about 1 to 3 minutes after the failure), the toggle lands on a live Bridge.
- There is no Backup config to switch to. The help page and the Device page say this.

## Accepted costs

- **Slower recovery than a Backup switch**, which took seconds.
- **Balancing is per resolver, not per Device.** An ISP resolver caches its one answer for the TTL and gives it to every User behind it, so whole ISPs move between Bridges in steps. Bridge load, which ADR 0008 leaves to the entry, is only roughly even.
- **One lookup reveals a Bridge, many lookups reveal them all.** Nothing about the fleet stays unpublished.
- **A Bridge blocked on one ISP but passing the probe stays in the record**, and Users on that ISP have no Backup to escape to; they toggle until they land elsewhere.

## Considered options

- **Keep the three slots** (ADR 0005): fastest manual recovery, at the cost of three configs per Device and slot assignment and rebalancing.
- **Pool name for Main, slots for Backups:** keeps the fast escape, but keeps most of the slot machinery.
- **Return every eligible Bridge in each answer:** leaves ordering to resolvers and OSes whose behaviour in Iran is unknown. Rejected for the explicit rotation ArvanCloud offers.
- **Floating IPs per slot:** dropped with the slots.

## Consequences for earlier decisions

- **ADR 0005:** its Endpoint Slots section, its floating-IP option and its Backup recovery path are superseded. Issuance delivers one config (a `.conf` and one QR code), not a `.zip` of three.
- **ADR 0006:** slot metrics and alerts become Bridge Address ones: the Bridges in the record, adds and removals, ArvanCloud API errors. "Endpoint Slot re-pointed" becomes "Bridge removed from / returned to the Bridge Address" (warning / info), and "All slots on one Bridge" becomes "Bridge Address down to one Bridge" (critical, 2 min). The Mesh dashboard shows the Bridges in the record.
- **ADR 0008:** a Bridge is eligible for the Bridge Address under the same default-Rule condition it had for a slot.
- **Migration:** existing Devices' slot configs stop working once `a`/`b`/`c` are deleted; their Users Replace their Devices. (One User today.)
- **The glossary:** **Endpoint Slot** is replaced by **Bridge Address**, and a **Device** carries one config.
