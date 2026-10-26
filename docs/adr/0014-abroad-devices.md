---
status: accepted
---

# Abroad Devices: all traffic of Users abroad leaves through a domestic Exit

A User abroad who needs Iranian services, such as banks, payment gateways and streaming that refuse foreign IPs, holds an **Abroad Device**. It connects to an **Abroad Bridge** and **all** its traffic, DNS included, leaves through a domestic `IR` Exit over the mesh. Nothing is split: these Users connect occasionally and only need to look Iranian, so there is no Rule choice to make for them. The Bridge tells an Abroad Device apart by its source address, which is the one thing a stock WireGuard client says about itself. Resolved in [Abroad Devices: all traffic of Users abroad leaves through a domestic Exit](https://github.com/alakiani/ways/issues/112).

## Abroad Devices

- **A kind fixed at issuance.** Abroad Devices take their address from their own sub-pool, `10.77.128.0/17`; ordinary Devices keep `10.77.0.0/17`. A Bridge matches the whole kind with one prefix. Changing a Device's kind is a Replace. A User who travels holds one of each and picks one in the WireGuard app: that choice is their intent.
- **Opt-in per User.** Only a User an Admin has given the abroad permission may issue one. Abroad Devices put foreign clients onto the domestic Exits' IPs, a different risk from the rest of the service.
- **Taking the permission away cuts the User's Abroad Devices off but keeps them**, as Suspend does: they leave the Bridge snapshots with their keys kept, and granting the permission again restores them with the same configs.
- **Quota and Usage are unchanged.** An Abroad Device counts toward its User's Quota like any other.
- **The panel issues them through a separate "Add Abroad Device" action**, shown only to permitted Users. Its config differs from an ordinary one only in `Endpoint` and address. A fixed notice says that everything browsed leaves from Iran and is filtered, so the Device is for while Iranian services are needed.

## The Abroad Rule

- **Built in and locked**, like the default Rule. Source: the Abroad Device pool. Destination: everything. Requires `IR`. Fallback: `drop`. It is evaluated before every destination Rule.
- **No new Tag.** A `FREEDOM` Tag for the open internet was proposed; it would mean exactly `!IR`, which ADR 0004 already rejected an `abroad` Tag for.
- **`drop`, not the default Rule, when no `IR` Exit is reachable.** A foreign IP fails the geo-blocks the User came for, and a dead tunnel is clearer than one that seems to work while every site refuses it.
- **Transit keeps it.** NAT happens only at the Exit, so a domestic Bridge carrying an Abroad Device's traffic in transit (ADR 0008) still sees the Abroad pool and applies the same Rule.
- **Path selection is unchanged.** On an Abroad Bridge the domestic `IR` Exits are the direct candidates for the Abroad Rule, spread by weight like any other Rule's.

## DNS

- **Abroad Device lookups are resolved in Iran.** The Bridge resolver picks its upstream by the client's source address and sends Abroad Device lookups to the domestic resolvers the snapshot already carries for the `IR` egress check, with the Abroad Rule's mark, so they leave through a domestic Exit. Resolving them abroad would hand ArvanCloud-fronted sites a foreign edge and undo the point of the Device.
- **Plain DNS, not DoT.** Inside a GRE Link the lookups cross the filter readable, the same exposure as the rest of an Abroad Device's traffic, which ADR 0009 accepted. The domestic resolvers see them either way.
- **DoT on port 853 from an Abroad Device follows the Abroad Rule**, not the default Rule; port 53 is still redirected to the Bridge resolver.

## Abroad Bridges and the Abroad Bridge Address

- **Every abroad Node becomes an Abroad Bridge**, holding Bridge and Exit with no Tags. The Coordinator accepts a Role change on re-enrollment while the Tags stay the same. Abroad Nodes already have Links to every domestic Exit, which is all an Abroad Bridge needs.
- **Same shared Bridge identity and port** (ADR 0005). Abroad hosts are harder for the state to seize than domestic ones, so sending them the key adds little risk.
- **Every Bridge accepts every Device.** An ordinary Device on an Abroad Bridge follows the destination Rules: Iranian destinations through `IR` Exits, the rest out of the Abroad Bridge's own NIC as a local candidate. An Abroad Device on a domestic Bridge leaves from that Bridge's own NIC. Neither leaks or breaks a Rule, so neither is refused.
- **The Abroad Bridge Address**, default `abroad.wayfinder.ir`, is a Coordinator setting like the Bridge Address (ADR 0011) and works the same way: one answer per lookup, in rotation, in the same ArvanCloud zone, written into each Abroad Device's config at issuance.
- **Eligibility:** the Agent is reporting and has an eligible candidate for the Abroad Rule. There is no probe Device: the one on the Coordinator sits inside Iran, on the wrong side of the filter, and the Agent's own view of its `IR` candidates is the honest signal. Removal after 60 s ineligible, rejoining after 5 min eligible, and never removing the last Bridge are ADR 0011's.

## Rollout safety

An Agent that does not know a Rule can have a source would read the Abroad Rule as "`0.0.0.0/0`, requires `IR`, first", and send every User's traffic out of Iran. So:

- **The Coordinator sends the Abroad Rule only to Agents whose reported version understands it**, and leaves it out for older ones. A deploy test checks that an old Agent receives none.
- **Nodes are upgraded before the Coordinator** as well, as the normal procedure.

## Considered options

- **Split by destination, as on domestic Bridges:** Iranian destinations through `IR` Exits, the rest out of the Abroad Bridge. It needs no Device kind, since the destination Rules already do it, but leaves DNS abroad and gives these Users a choice they don't need. Rejected by the owner: all traffic to a domestic Exit is simpler for occasional use.
- **A flag on the User instead of the Device:** flipping it would move every Device to a new address, and a User could not hold both kinds.
- **A kind that can be switched later**, matched by a per-Device address set: more state on every Bridge for a rare change that Replace already covers.
- **Any Rule may name a source:** more general, a bigger Rule editor, and one use case.
- **Abroad Devices connecting to domestic Bridges directly:** no Abroad Bridges needed, but their WireGuard traffic would cross the filter, which is what the mesh exists to avoid.
- **A second shared keypair for Abroad Bridges:** two kinds of config to issue for little gained.
- **Bridges refusing the other kind of Device:** ends "every Bridge accepts every non-blocked Device" and gives each Bridge its own peer set, to prevent nothing harmful.

## Consequences for earlier decisions

- **ADR 0003:** the Device pool is split into an ordinary and an Abroad half. The policy function also blocks an Abroad Device whose User lacks the permission.
- **ADR 0004:** source matching is built, for the Abroad Rule only. Abroad Device DNS is resolved in Iran and DoT from an Abroad Device follows the Abroad Rule; "DNS always abroad" holds for every other Device.
- **ADR 0005:** Abroad Bridges face Devices and receive the shared Bridge key.
- **ADR 0006:** new alerts: "Abroad Bridge removed from / returned to the Abroad Bridge Address" (warning / info), "Abroad Bridge Address down to one Bridge" (warning, 2 min; there are only two Abroad Bridges), "No eligible Abroad Bridge" (critical, 2 min). The Mesh dashboard shows the Abroad Bridges in the record.
- **ADR 0008:** a local candidate exists for any Rule whose Tags the Node's own Tags satisfy, not only the IR Rule on a domestic Node, so an Abroad Bridge carries ordinary Devices' default-Rule traffic itself. A domestic Bridge now sees the Abroad Bridges as transit candidates for the IR Rule; transit stays failover-only.
- **ADR 0011:** Abroad Bridges are published, in their own Abroad Bridge Address, never in the Bridge Address.
