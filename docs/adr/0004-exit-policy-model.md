---
status: accepted
---

# Exit policy: ordered Rules over Destination Sets, mesh before fallback, DNS always abroad

Bridges route each packet by the first matching Rule. A Rule names a Destination Set and the Tags its Exit must carry. When a Bridge loses every direct Exit for a Rule, it reaches one through another Bridge before any fallback applies. International traffic and all DNS fail closed rather than leave through a domestic NIC. Resolved in [Exit policy model: Tags, Rules, and per-Device routing on the Bridge](https://github.com/alakiani/ways/issues/13).

## Model

- **A Tag names the traffic an Exit may carry.** Tags are plain names such as `IR`, so a Node tagged `IR` may be the Exit for traffic to Iran.
- **A Destination Set** is a named set of IPv4 CIDRs. Its content is the source feed plus Admin additions minus Admin removals. It is identified by hash and shipped by hash (ADR 0002).
- **A Rule** combines four things:
  - a **Destination Set**;
  - **required Tags**, which are ANDed and may be negated (`!IR`);
  - a **priority**: the lowest number that matches wins, first match only, with no longest-prefix logic across Rules;
  - a **fallback**, either `next` or `drop`.
- **The default Rule** covers `0.0.0.0/0`, sits at the lowest priority, cannot be deleted, requires `!IR`, and has `drop` fallback, which cannot be changed. The panel shows it as "Default: any Exit except IR". Negated Tags were chosen over an `abroad` Tag, which carried no meaning, and over "reserved Tags", which would silently pull Exits out of the default pool whenever a new Rule named their Tag.
- **The IR Rule** uses the IR Destination Set, requires `IR`, and has fallback `next`.

## The IR Destination Set feed

- **Source:** [MrAriaNet/Get-IP-Iran `list.rsc`](https://github.com/MrAriaNet/Get-IP-Iran/blob/main/list.rsc), IPv4 lines only, fetched nightly. It is RIPEstat `country-resource-list` for IR, plus three Respina ranges registered abroad but used in Iran, plus `10.0.0.0/8`. This replaces the research recommendation (RIPE delegated-extended) with the same data and its known extras.
- **Gates before an update is accepted:**
  - Private and reserved ranges are always stripped, so `10.0.0.0/8` goes; it would collide with the Device address pool.
  - The address space must stay within ±2% of the last good set.
  - The file must parse cleanly and must not be empty.
  - A divergence from a direct RIPEstat fetch beyond the known extras raises an alert.
  - On any failure, the last good set stays in force and an alert fires. These gates exist because a third-party repository is now in the trust path: a hostile edit such as `0.0.0.0/1` must never route half the internet out of a domestic Exit.
- **Distribution:** pushed to Bridges only when the content changes. Exits never need it.

## Exit choice and the mesh

- **Exit choice is per Bridge per Rule.** In phase one, all Devices on one Bridge share an Exit for a given Rule, picked automatically by Path health. *(Amended by [ADR 0008](0008-path-selection-and-exit-balancing.md): Exit choice is per bucket of Devices per Bridge per Rule, spread over Exits by measured capacity.)*
- **The mesh comes before fallback.** For each (Bridge, Rule), the Coordinator's candidate Paths must include at least one that transits another Bridge whenever the mesh has one, and it must not share a first Link with the direct candidates. The Bridge fails over through these locally, without the Coordinator. `fallback` applies only when every candidate is down: the IR Rule falls through to the default (degraded, still working), and the default Rule drops.
- **Open, handed to [Path selection and failover](https://github.com/alakiani/ways/issues/12):** when the Coordinator is unreachable and every candidate has died, should Bridges discover transit by asking neighbouring Bridges? *(Answered in [ADR 0008](0008-path-selection-and-exit-balancing.md): yes. Bridges work out candidates themselves, every neighbouring Bridge is always a transit candidate, and a "transit OK" flag in the Link probe reply says whether it can carry the Rule.)*
- **A dual-role Node exits locally through a zero-Link Path.** A Node holding both Roles and tagged `IR` reaches itself with latency 0, so it wins on its own merits. It forwards out of its own NIC with NAT, and needs no special capability.

## Bridge data plane

- **Matching:** each Destination Set is an nftables interval set. In prerouting, packets from the WireGuard interface are marked with the first matching Rule, in priority order.
- **Routing:** `ip rule fwmark <rule>` selects that Rule's table. The table's default route goes via the first Link of the active Path, or via the local NIC for a zero-Link Path. A `drop` fallback is a blackhole route.
- **Translation and protocol:** NAT happens only at the Exit. IPv6 is dropped (ADR 0003).
- **Updates:** each change is one atomic `nft -f` transaction under commit-confirm (ADR 0002).
- **Headroom:** thousands of Devices, around 100k prefixes, and tens of Rules.
- **Per-Device policy in phase one is only the effective state** (ADR 0003): a blocked Device is removed as a peer. Matching on source address is reserved for a future User-chosen Exit and for `throttled`, and is not built. *(Amended by [ADR 0014](0014-abroad-devices.md): source matching is built for the Abroad Rule only, which sends all of an Abroad Device's traffic to an `IR` Exit before any destination Rule.)*

## DNS is always resolved abroad

- **The config's resolver is on the Bridge** at one fixed in-tunnel address, the same on every Bridge (such as `10.77.0.1`). It forwards only to public resolvers abroad and keeps no query logs. *(It is a DNS relay inside the Agent, at `10.77.0.1`, with the upstream resolvers pushed by the Coordinator; its sockets carry the default Rule's mark. DNS pauses for the second or two an Agent restart takes. Decided in [MVP 04](https://github.com/alakiani/ways/issues/20).)* *(Since [ADR 0009](0009-gre-transport.md), it reaches the upstream resolvers over DNS over TLS, because a GRE Link would carry plain DNS in clear across the filter.)*
- **The resolver's own outbound queries are policy-routed into the default Rule.** As a local process it would otherwise use the main table and leave through the domestic ISP.
- **Devices cannot bypass it with plain DNS.** All Device traffic on port 53, UDP and TCP, to any address is redirected to the Bridge resolver, and DNS over TLS on port 853 is forced into the default Rule whatever its destination. *(Amended by [ADR 0014](0014-abroad-devices.md): an Abroad Device's lookups are resolved by domestic resolvers through the Abroad Rule, and its DoT follows the Abroad Rule. Every other Device's DNS stays abroad.)*
- **No fallback to domestic.** If the default Rule has no working Path, DNS fails.
- **Accepted limit:** DNS over HTTPS cannot be told apart from HTTPS, so it follows its destination's Rule. Domestic CDNs may hand Iranian sites a foreign edge.

## Consistency across Bridges

Rules and Destination Sets are global. Every Bridge receives the same Rule list and the same set hashes, along with every non-blocked Device. Only the Exit choice is local. Bridges may differ for the few seconds a rollout takes.
