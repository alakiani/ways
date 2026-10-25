---
status: accepted
---

# Same-side Links: plain GRE first, plain WireGuard as fallback, no AmneziaWG

A Link that does not cross the filter, between two domestic Nodes or two abroad Nodes, gets two Transports: plain GRE, then plain WireGuard. Following [ADR 0007](0007-link-transport-discovery.md), both stay up and are probed all the time, and the first one that is Up carries the Link's traffic. Links that cross the filter keep their four instances from [ADR 0009](0009-gre-transport.md). This amends ADR 0007, which gave same-side Links plain WireGuard and AmneziaWG, and ADR 0009, which left them unchanged. Resolved in [Same-side Links: GRE first, plain WireGuard as fallback, no AmneziaWG](https://github.com/alakiani/ways/issues/110).

## Why

- **AmneziaWG only obfuscates against the filter**, and nothing filters a same-side Link. On these Links it only adds an `amneziawg-go` userspace daemon per Link, and in a full mesh the number of Links keeps growing.
- **GRE is the cheaper Transport.** It runs in the kernel, does no crypto, and adds 24 bytes per packet, compared with 60 to 80 for the WireGuard family.
- **Exposure doesn't change.** ADR 0009 already sends User traffic across the filter in clear inside GRE. Domestic GRE shows the same traffic to the same adversary, and GRE between abroad Nodes shows it only to foreign transit networks.

## Why keep plain WireGuard

When GRE goes down on a same-side Link, the cause is the hosting setup, not the filter, and none of these fix themselves:

- **Asymmetric NAT:** ADR 0009's accepted gap. A Node whose outbound NAT address differs from the address that reaches it never gets a working GRE instance.
- **Providers that drop IP protocol 47** unless a security-group rule allows it. The provisioning wizard checks GRE only on Links that cross the filter.
- **Address changes:** GRE does not roam. If a Node's address changes, its GRE instances stay down until the Coordinator sees the new address and sends new snapshots. WireGuard keeps working through the change.
- **Two Nodes behind one NAT address**, for example two VMs in one provider project.

A standby WireGuard instance costs one kernel interface and about 100 B/s of probes. Path selection could route around a Link that is permanently down, but only through a detour via another Node.

## Transports on a same-side Link

| Order | Transport | Instances | Runs as |
| --- | --- | --- | --- |
| 1 | Plain GRE | 1 | A kernel GRE interface, as in ADR 0009 |
| 2 | Plain WireGuard | 1 | Kernel module, as in ADR 0007 |

- **One preference order for every Link:** GRE, AmneziaWG, plain WireGuard. A same-side Link has no AmneziaWG, so the order is the same on both kinds of Link.
- **GRE works as in ADR 0009:** both ends use each other's seen address, the instance is never replaced, and every Node's nftables accept protocol 47 only from its current GRE peers. Who initiates is unchanged: on a same-side Link the Node with the lower id initiates (ADR 0007). Both ends send probes, so the NAT mapping opens from either side.
- **Disabling GRE in the candidate list** leaves same-side Links on plain WireGuard alone. Disabling both GRE and plain WireGuard leaves them with no Transport. AmneziaWG does not step in.

## Rollout

The Coordinator re-derives every same-side Link. It retires the AmneziaWG instance and creates a GRE instance. Plain WireGuard keeps carrying the Link, and the Link moves to GRE once GRE has been Up for the switch-back time. Only a Link that was already running on AmneziaWG, because its plain WireGuard was down, drops until GRE comes Up.

## Considered options

- **GRE alone on same-side Links:** less to run, but every case in "Why keep plain WireGuard" would leave the Link permanently down. The wizard would then have to treat GRE as a hard requirement on every Node pair. Rejected for the cost of one standby interface.
- **Keeping AmneziaWG as a third Transport:** it protects against nothing on these Links.
