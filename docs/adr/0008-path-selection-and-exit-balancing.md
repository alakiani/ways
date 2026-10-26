---
status: accepted
---

# Path selection: Bridges choose locally, spread Devices over Exits by measured capacity, and use transit only for failover

Each Bridge Agent works out its own candidate Paths from its snapshot and ranks them on its own live measurements. No routing protocol runs, and the Coordinator pushes no Path lists. A Bridge hashes Devices into buckets and gives each Exit a share of buckets in proportion to a weight: remaining throughput, availability, and RTT. Because every Bridge measures the capacity Exits have left, load spreads across the mesh without a central optimiser. Transit through another Bridge is used only when no direct candidate is left. Resolved in [Path selection and failover](https://github.com/alakiani/ways/issues/12). It builds on the [path-selection research](https://github.com/alakiani/ways/issues/6) and on Link health from ADR 0007.

## Goal

Every Device's international traffic leaves through an Exit abroad, and the mesh's capacity is used as fully as possible. With four equally capable Exits, each carries about a quarter of the traffic. When Exits are unequal, each carries traffic in proportion to the capacity it has left. Equal shares would overload a weak Exit while a strong one sits idle.

## Candidates

For each (Bridge, Rule), the Agent works out the candidates from its snapshot (Links, each far end's Roles and Tags, Rules):

- **Direct:** every Exit that carries the Rule's required Tags and is reachable over one Link.
- **Local:** the Bridge's own NIC, when it is a dual-role Node tagged `IR` and the Rule is the IR Rule (a zero-Link Path, ADR 0004). *(Amended by [ADR 0014](0014-abroad-devices.md): whenever the Bridge is also an Exit whose Tags satisfy the Rule, so an Abroad Bridge carries ordinary Devices' default-Rule traffic itself.)*
- **Transit:** every neighbouring Bridge.

The Coordinator runs the same function only to show "why" in the panel and to judge Endpoint Slot eligibility. It pushes the scoring parameters, never Path lists. A Coordinator outage changes nothing: the topology is in the persisted snapshot.

## Transit is a hand-off, one hop deep

- Bridge A sends a Rule's traffic to Bridge B. B classifies it with the same global Rules (ADR 0004) and sends it on **its own direct and local candidates only**. Traffic that arrived from another Bridge is never sent on to a third Bridge.
- Paths are therefore at most two Links, and loops cannot happen.
- **Transit is for failover only.** A Rule's buckets go through transit only when none of its direct or local candidates is eligible. They then all go through the neighbouring Bridge with the best weight. This is how ADR 0004's "mesh before fallback" works out in practice.
- A Pinned Path model (A chooses "via B to Exit 3") was rejected, because it needs a tunnel or a marker per Exit on every Link between Bridges.

## Eligibility

A candidate is **eligible** while both of these hold:

1. Every Link on it is Up (ADR 0007). Up already requires loss under 10%, so loss is not counted again.
2. The far end's latest probe reply sets the flag the candidate relies on:
   - **egress OK**, for a direct candidate. The Exit's Agent checks its own internet every 5 s by resolving through two public resolvers and fetching a small object. *(The targets depend on the Exit's Tags: an Exit tagged `IR` checks domestic resolvers and a domestic object, every other Exit checks targets abroad. Otherwise an international shutdown would fail the check on every domestic Exit and pull them out of IR traffic exactly when they matter. The Coordinator pushes both target lists in the snapshot. Decided in [MVP 03](https://github.com/alakiani/ways/issues/19).)*
   - **transit OK for this Rule**, for a transit candidate. The neighbouring Bridge sets it while it has an eligible direct or local candidate for the Rule.

The flags travel in the 1-per-second Link probe that ADR 0007 already runs, so a Bridge notices that a neighbour has lost its direct Paths within about 3 s. **This answers the question ADR 0004 left open:** when the Coordinator is unreachable, Bridges still learn transit from their neighbours over Links they already have. A Bridge enrolled during the outage stays unknown until contact returns, which is accepted.

## Measurements

- **RTT:** from the Link probes. The RTT of a Path is the sum over its Links.
- **Availability:** the fraction of seconds the candidate was eligible over a sliding 6-hour window. Every switch from eligible to ineligible in the last hour also counts as one extra minute down, so a Path that is unstable right now is penalised quickly.
- **Throughput:** a capped active test, about 4 MB or 3 s, whichever comes first.
  - **Where and when:** on each Link's active instance, every 2 hours with jitter, in the direction that matters to Users (the Exit end towards the Bridge end).
  - **Skipped** while real traffic on the Link already exceeds the last measured figure; that traffic is the measurement. Observed peaks raise the figure.
  - **What it measures:** it runs over Links that already carry real traffic, so it measures **remaining** capacity. That is what closes the balancing loop.
  - **Why it is acceptable:** ADR 0007 ruled out throughput tests for deciding whether a Transport is Up, because sustained volume is what blocking targets. This test is short and rare (about 50 MB per Link per day), and being Up still never depends on it.

## Weight

```
weight = throughput_mbps × availability² × rtt_factor
rtt_factor = 1                 if RTT ≤ 150 ms
           = 150 / RTT          otherwise
```

- RTT counts only above a "good enough" floor, so a North American Exit with plenty of capacity can beat a nearby European Exit that is congested.
- **Cutoff:** a candidate whose weight is under 25% of the best candidate's gets no buckets. Devices are never parked on a poor Exit just to fill it.
- The local candidate, when it exists, takes every bucket of its Rule.
- Every constant (150 ms, the square, the 25% cutoff, and the timings below) is a scoring parameter pushed by the Coordinator.

Worked example, one Bridge, default Rule:

| Exit | RTT | Availability | Throughput | Weight | Share |
|---|---|---|---|---|---|
| Frankfurt | 90 ms | 0.97 | 8 Mbps | 7.5 | 0 (cut off) |
| Amsterdam | 110 ms | 1.00 | 25 Mbps | 25 | 39% |
| Virginia | 230 ms | 1.00 | 60 Mbps | 39 | 61% |

## Buckets

- Each Bridge hashes each Device's tunnel address into one of **64 buckets per Rule**. Each bucket is assigned to one candidate.
- **The target share** of each eligible candidate is proportional to its weight.
- **A Device keeps one public IP** until its bucket moves. Per-flow hashing was rejected because it makes one Device leave from several IPs at once, which breaks banking, streaming, and login sessions that tie themselves to one IP.
- Buckets are anonymous. They are not the per-Device source matching that ADR 0004 reserved for a future User-chosen Exit.

## Moving buckets

- **Failure moves are immediate.** When a candidate becomes ineligible, its buckets go at once to the remaining eligible candidates, in proportion to their weights. When no direct or local candidate is left, every bucket goes to the best transit candidate.
- **Rebalancing moves are slow.** When a candidate's actual share has been off its target by more than 10 percentage points for 15 minutes, one bucket per Rule moves every 5 minutes, from the candidate furthest over its target to the one furthest under. Each move resets the connections of about 1 to 2 Devices, because NAT happens only at the Exit.
- **New or recovered candidates** fill up only through rebalancing moves. This avoids a stampede and damps oscillation between Bridges that all see the same Exit.
- **When no candidate is eligible,** the Rule's `fallback` applies (ADR 0004): the IR Rule falls through to the default Rule, and the default Rule drops. The first candidate to become eligible again takes the buckets immediately.

## Bridge data plane

- In prerouting, after the Rule mark (ADR 0004), an nftables hash of the source address picks the bucket. A verdict map from (Rule, bucket) sets the candidate's mark.
- Each candidate has its own routing table, selected by `ip rule fwmark`. Its default route goes to the candidate's Link interface, to the local NIC, or to a blackhole for `drop`.
- Moving a bucket is one atomic update of an element in the map. Moves are the Agent's runtime state, not a snapshot apply, so commit-confirm does not apply.
- Every move is logged with its kind (failure or rebalancing) and its reason, and is exported to `/metrics`.

## Not in phase one

- Routing protocols. Babel stays the phase-two option the research named.
- Admin weights or preferences for particular Exits.
- Time-of-day logic.
- Balancing Devices across Bridges by traffic. Bridge load stays with the rotation of Endpoint Slots (ADR 0005).

## Consequences for earlier decisions

- **ADR 0001:** the persisted desired state holds scoring parameters instead of ranked candidate Paths.
- **ADR 0002:** snapshots carry scoring parameters, not candidate Paths. Health reports carry bucket shares per candidate per Rule instead of "the active Path per Exit".
- **ADR 0004:** Exit choice is per bucket per Bridge per Rule. "Mesh before fallback" is met by transit candidates that are always present and used for failover only. Its open question is answered above.
- **ADR 0005:** a Bridge is eligible for an Endpoint Slot while it has at least one eligible candidate, direct, local, or transit, for the default Rule.
- **ADR 0006:**
  - The Path metrics become share per candidate, bucket moves by kind, and the number of eligible candidates per Rule.
  - "Path flapping" fires on more than 6 **failure** moves per hour. Rebalancing moves are expected and do not count.

## Rejected alternatives

- **The Coordinator computes a ranked top 3 and pushes it** (the research's recommendation). Rejected: the rankings would rest on 30-second-old health, and the Bridge re-ranks locally anyway. At this mesh size, working out every candidate locally is trivial.
- **One Exit per Bridge per Rule.** Rejected: with two domestic Bridges, at most two Exits would ever carry default-Rule traffic.
- **Pure lowest RTT.** Rejected: the nearest Exit always wins, whatever its capacity.
- **Weighting transit candidates like any other candidate.** Rejected: the balancing loops of neighbouring Bridges would interact.
- **A central load optimiser on the Coordinator.** Rejected: it fails during outages, and the remaining-capacity feedback reaches the same balance locally.
