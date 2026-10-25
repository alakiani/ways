---
status: accepted
---

# Link transport discovery: two UDP Transports, several live instances per Link, chosen by health

Nobody records which Transport works from which datacenter, because the filter changes faster than anyone could keep that up to date. Every Link brings up all of its candidate Transport instances at once, measures each one continuously, and carries traffic on the best one that is Up. Phase one has two Transports, plain WireGuard and AmneziaWG, and both run over UDP. A UDP-wide crackdown therefore cuts every Link that crosses the filter. That is accepted for now. Resolved in [Link transport discovery and the candidate transport list](https://github.com/alakiani/ways/issues/9).

## Discovery over configuration

- The only fixed rules are ones derived from Tags. No per-datacenter or per-ISP transport fact is stored anywhere (inventory constraint 1).
- The Coordinator holds one global, ordered **candidate list** of Transports. A Transport that a new Agent version ships stays off until an Admin enables it. Per Link, an Admin may only disable a Transport, never add one.
- The candidate list and each Link's candidates are part of the snapshot (ADR 0002). Which candidate is carrying traffic is the Agent's runtime state.

## Links

- **Full mesh, derived.** The Coordinator creates a Link for every pair of Nodes. An Admin can disable a Link but never draws one.
- **One Link per Node pair.** Its candidates are alternatives, and exactly one carries traffic at any moment. Path selection sees one Link, not one per Transport.
- **Crossing the filter.** A Link crosses the filter when exactly one of its Nodes is tagged `IR`. The `IR` Tag now means both "may exit Iranian traffic" (when the Node holds the Exit Role) and "inside the filter". A separate Domestic flag on Nodes was rejected as a second fact to keep in step with the Tag.
- **Who initiates.** On a Link that crosses the filter, the `IR` end initiates: it is the only side with the peer's endpoint configured, and it sends keepalives. On a same-side Link, the Node with the lower id initiates. The other end learns the peer's address by WireGuard roaming. This follows the research finding that hosts abroad usually cannot open connections into Iran, while Iranian hosts can open connections outward.

## Phase-one Transports

| Transport | Runs as | Used on |
| --- | --- | --- |
| Plain WireGuard | Kernel module, configured over netlink | Same-side Links only *(every Link since [ADR 0009](0009-gre-transport.md))* |
| AmneziaWG (protocol 2.0 parameters) | The `amneziawg-go` userspace daemon, one per instance, under its own systemd unit, configured over its UAPI socket. No DKMS kernel module. | Every Link *(Links that cross the filter only, since [ADR 0013](0013-same-side-gre.md))* |

- **Tunnels outlive the Agent.** The Agent configures, measures, and switches, and never carries packets itself. An Agent crash or upgrade changes no tunnel.
- **No plain WireGuard across the filter.** Its handshake has a fixed fingerprint and is reported blackholed right after the handshake. Probing it every second would mark the abroad IP as a WireGuard server and risk getting that IP blocked, taking the AmneziaWG instances down with it. *(Amended by [ADR 0009](0009-gre-transport.md): plain WireGuard now runs on Links that cross the filter too, last in order, as an accepted risk for redundancy.)*
- **The Agent's Transport layer is an interface** (bring up, take down, report health), so adding a Transport later does not change the Link model.

## Candidates are Transport instances

A candidate is a Transport with its own UDP port and, for AmneziaWG, its own obfuscation parameters. Different instances present different fingerprints to the filter.

- **A Link that crosses the filter:** 2 AmneziaWG instances. *(Since [ADR 0009](0009-gre-transport.md): 1 GRE instance, then 2 AmneziaWG instances, then 1 plain WireGuard instance.)*
- **A same-side Link:** 1 plain WireGuard instance and 1 AmneziaWG instance. *(Since [ADR 0013](0013-same-side-gre.md): 1 GRE instance, then 1 plain WireGuard instance.)*
- **Preference order:** plain WireGuard before AmneziaWG; otherwise the order the instances were created. *(Since [ADR 0013](0013-same-side-gre.md): GRE, AmneziaWG, then plain WireGuard on every Link.)*

## Keys, ports, and parameters

- **Each Agent generates its own Link keypair** and keeps the private key on disk. All its WireGuard-family instances on all its Links use that one keypair, which is separate from the shared Bridge identity Devices use (ADR 0005). The Coordinator distributes only public keys, so seizing it yields no key that impersonates a Node on the mesh.
- **The listening end chooses each instance's port and parameters:**
  - Ports are random UDP ports between 10000 and 60000, never 443 (traffic there looks like QUIC, which is dropped) and never 53.
  - AmneziaWG parameters are random within the ranges the AmneziaWG documentation states are valid: junk packets, S1 to S4 padding, H1 to H4 header types, and I1 to I5 decoy packets.
  - The listening end reports them, and the Coordinator puts them in the initiating Node's snapshot.
- **Parameters change only by replacing an instance**, never in place. No instance is replaced while the Coordinator is unreachable, because the initiating end would never learn the new values.
- **Inner addressing:** each instance has its own interface and its own /31, allocated by the Coordinator from a mesh range *(The mesh range is `10.78.0.0/16`, next to the Device pool `10.77.0.0/16` of [ADR 0003](0003-identity-devices-metering.md). Decided in [MVP 03](https://github.com/alakiani/ways/issues/19).)*

## When an instance counts as Up

An instance is **Up** while all three of these are true:
1. Its tunnel has completed a handshake.
2. In-tunnel echo probes, sent once a second, show less than 10% loss over the last 30 s.
3. The last successful probe is less than 10 s old.

A handshake alone proves nothing, because the filter has cut flows after the handshake and after about six packets. The continuous probe also catches the slower failures: volume-based blocking and IPs that get blocked days later. There is **no active throughput test**: the extra volume is exactly what MCI-style blocking punishes. Bandwidth is observed passively on the active instance and is not part of Link health in phase one.

## Choosing, switching, and standby

- **The Link carries traffic on the first Up instance in preference order.**
- **Switching away:** when the active instance stops being Up, the Link switches at once. Switching is a route change between two live interfaces and takes about a second.
- **Switching back:** the Link returns to a higher-preference instance only after it has been Up for 5 minutes without interruption, so it does not flap.
- **Warm standby:** every instance stays up all the time. A standby carries only the probes, about 100 B/s.
- **Retries:** an instance that is not Up keeps its configuration and retries the handshake with exponential backoff from 30 s to 15 min, with jitter. A new Link probes all its candidates in parallel and is usable as soon as any one is Up.
- **Replacement:** an instance that has been down for 24 h is replaced by a fresh one with a new port and new parameters, so the mesh rediscovers a fingerprint that works without anyone acting.

## What Path selection sees

One health per Link: latency, loss, age of the last success, and the Transport in use, all taken from the **active** instance. A Link is **down** when no instance is Up. That matches the "Link down" alert in ADR 0006 and the per-Link fields in the health report in ADR 0002.

## Known gap: phase one is all UDP

Iran has filtered UDP at scale (measured), and UDP was "actively disrupted" during the 2026 crackdowns. When that happens, every Link that crosses the filter goes down together:
- Domestic Bridges keep serving `IR` traffic through local Exits.
- The default Rule drops foreign traffic (ADR 0004).
- Devices show "connected" while nothing foreign loads.

A TCP Transport for Links that cross the filter, such as VLESS+REALITY, is the planned answer. It was left out of phase one to keep it simple, not because it is not needed.

## Rejected alternatives

- **VLESS+REALITY over TCP/443 (Xray-core)**: the research's first choice for crossing the filter. Deferred: it brings a second process model, a JSON-config generator, SNI selection, and IP rotation every few days.
- **XHTTP or WS+TLS through a CDN**: needs a CDN account and domains that are blocked within about a day to a week. Out of scope for this phase.
- **GRE and GRE over 6to4**: no benefit over plain WireGuard at the Link speeds Iran allows, no encryption, and they fail every protocol allowlist. *(Reversed by [ADR 0009](0009-gre-transport.md): production found AmneziaWG over UDP dropped to most hosting networks, and plain GRE is now the first Transport on Links that cross the filter.)*
- **QUIC carriers (Hysteria2, MASQUE)**: QUIC has been fully blocked since June 2025 (measured).
- **One Link per (Node pair, Transport)**: multiplies Paths, and makes "must not share a first Link" in ADR 0004 ambiguous.
- **Admin-drawn Links, or recording per-datacenter transport facts**: contradicts discovery over configuration.
- **AmneziaWG inside the Agent process**: every Agent restart would drop Links.
- **The Coordinator generates Link keys**: a seized Coordinator would then hold keys that impersonate every Node on the mesh.
