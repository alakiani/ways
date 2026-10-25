---
status: accepted
---

# Plain GRE is the first Transport on Links that cross the filter, beside AmneziaWG and plain WireGuard

Links that cross the filter get three Transports: plain GRE (IP protocol 47) first, then AmneziaWG over UDP, then plain WireGuard. Following [ADR 0007](0007-link-transport-discovery.md), they all stay up and are probed all the time, and the best one that is Up carries the Link's traffic. This amends ADR 0007, which rejected GRE and kept plain WireGuard off these Links. The reason is what the first production deployment measured on 2026-10-17 and 2026-10-18:

| From a Sotoon Bridge (AS204533) to | AmneziaWG over UDP | Small or random UDP packets | GRE |
| --- | --- | --- | --- |
| AWS London (AS16509) | Up | arrive | **Up both ways through both NATs, 79 ms, 107–173 Mbit/s for 70 s, 0% loss** |
| GCore (AS199524), Hetzner (AS24940), OVH (AS16276), Vultr (AS20473) | **dropped**: the tunnel's packets leave the Bridge and never arrive | arrive, even on the tunnel's own ports | not measured |

The filter was not dropping UDP as such. It recognised tunnel flows to ordinary hosting networks and dropped them, so a Link needs Transports that don't all look alike to it. The owner's experience is that plain GRE runs well across this kind of filter, and that encryption at this layer adds little because almost all User traffic is already TLS.

## Accepted risks

- **The filter sees User traffic inside GRE as if there were no VPN.** If its DPI decapsulates GRE, its usual blocking applies inside the Link: TLS SNI blocking, plain-HTTP blocking, and resets. Blocked sites would then stay blocked while the Link carries traffic on GRE. This was not measured before the decision. When it happens, probing does not notice it, because the in-tunnel probes still pass. It shows up only as User reports, so the Admin then disables GRE in the candidate list.
- **The filter sees which Device sent what.** Inner packets carry the Device's tunnel address (ADR 0003), the destination, and the SNI, in clear on the way abroad.
- **Plain WireGuard across the filter** has the fixed handshake fingerprint ADR 0007 warned about. Probing it every second may get an Exit's IP flagged, which would take GRE and AmneziaWG to that IP down with it. The owner accepted this for redundancy.

## Transports on a Link that crosses the filter

| Order | Transport | Instances | Runs as |
| --- | --- | --- | --- |
| 1 | Plain GRE | 1 | A kernel GRE interface, configured over netlink |
| 2 | AmneziaWG over UDP | 2 | `amneziawg-go`, as in ADR 0007 |
| 3 | Plain WireGuard | 1 | Kernel module, as in ADR 0007 |

- **Same-side Links are unchanged:** plain WireGuard, then AmneziaWG. Nothing filters them. *(Amended by [ADR 0013](0013-same-side-gre.md): same-side Links now have GRE, then plain WireGuard, and no AmneziaWG.)*
- **Switching, switching back after 5 minutes Up, warm standby and retries** are as in ADR 0007. GRE's standby costs only the 1-per-second probes.
- **Like any Transport, GRE stays discovered, not configured:** an Admin can disable it in the candidate list, or on one Link.

## How GRE works on a Link

- **One GRE instance per Link.** GRE has no ports: a tunnel is identified by its pair of public addresses, and NAT gateways track at most one GRE flow per pair.
- **Never replaced.** ADR 0007's replacement after 24 h exists to change a UDP instance's port and fingerprint, and a GRE instance has neither. It just keeps retrying.
- **Inner addressing:** a /31 from the mesh range, like every instance (ADR 0007). Up is measured with the same in-tunnel echo probes.
- **Tunnels outlive the Agent:** the GRE interface lives in the kernel, like plain WireGuard.
- **Both ends need the other's public address, because GRE does not roam.**
  - **Local end:** each Node's own interface address. This works behind NAT: Sotoon's `10.10.10.215` and AWS's `172.31.7.75` both worked in the test.
  - **Remote end:** the peer's seen address, the address the Coordinator sees its Agent connect from (ADR 0002). It goes into both ends' snapshots, so nobody types an IP.
- **Accepted gap:** a Node whose outbound NAT address differs from the address that reaches it gets no working GRE instance. Sotoon NATs our Coordinator VM that way (`31.171.101.178` out, `78.109.207.63` in). Its GRE instance simply never comes Up, and the Link carries traffic on the next Transport.
- **The `IR` end sends first** (ADR 0007), which opens the GRE mapping in the NAT in front of the Bridge. The once-a-second probes keep it open.
- **MTU:** the GRE interface's MTU is the outer MTU minus 24 bytes.

## Limiting what GRE exposes

- **No open relay.** An Exit creates a GRE interface only for a current peer's address, and its nftables accept protocol 47 only from those addresses. On a GRE interface it forwards only packets whose source is in the Device range (ADR 0003) or the mesh range, and drops the rest. A spoofed packet can still claim a Bridge's address and a Device's source. That is accepted, because the reply goes back to the Bridge, not to the spoofer.
- **DNS leaves the Bridge encrypted.** The Bridge's resolver now reaches its upstream resolvers abroad over DNS over TLS, on port 853, instead of plain DNS on port 53. Otherwise every User's queries would cross the filter in clear inside GRE, and the filter rewrites DNS answers on port 53. This amends [ADR 0004](0004-exit-policy-model.md).

## Provisioning and testing

- **Providers must let IP protocol 47 through** between Bridges and Exits, for example with a security-group rule for protocol 47, or "all traffic" from the Bridges. The wizard's reachability step checks it.
- **The lab must block GRE separately from UDP**, so these can be tested: "GRE blocked: the Link moves to AmneziaWG within about a second"; "UDP blocked: GRE carries the Link"; "a spoofed GRE packet with a source outside the Device range is dropped at the Exit".

## Considered options

- **AmneziaWG inside GRE:** hides the inner traffic and the Device addresses, at the cost of a userspace daemon per GRE instance. The owner chose plain GRE: User traffic is already TLS, and an encrypted GRE payload is not obviously harder to classify than AmneziaWG over UDP already is.
- **Keeping plain WireGuard off Links that cross the filter (ADR 0007):** the owner preferred one more independent Transport, for redundancy.
- **Splitting a Link's traffic across Transports at once:** rejected. Path selection would see several Links per Node pair, the problem ADR 0007 already rejected.
- **GRE with IPsec (ESP):** a second protocol (50) to get past the filter, a second key system, and ESP is commonly blocked.
