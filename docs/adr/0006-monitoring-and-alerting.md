---
status: accepted
---

# Monitoring and alerting: Prometheus on the Coordinator VM pulls from Agents; alerts leave Iran through an Exit

Prometheus, Alertmanager, and Grafana run on the domestic Coordinator VM, so monitoring adds no machine. Prometheus pulls each Agent's `/metrics`, which narrows ADR 0001's rule that the Coordinator never dials a Node. Telegram is blocked domestically, so alerts reach it through whichever Exit is healthy. No metric carries a Device or User identifier. Resolved in [Monitoring and alerting](https://github.com/alakiani/ways/issues/15).

## Placement

- **Everything on the Coordinator VM:** Prometheus, Alertmanager, Grafana. Bridges and Exits are disposable; the Coordinator VM is the one permanent host.
- **Prometheus retention is 30 days** on local disk. It is not in the nightly backup: its history may be lost.
- **No dead-man's switch.** If the Coordinator VM dies, monitoring and alerting die with it, and the operator notices because the panel is down too. **Accepted cost:** no alert for the VM's own death.

## Collecting metrics (pull, an exception to ADR 0001)

ADR 0001 says Agents always dial the Coordinator and the Coordinator never dials a Node. This ADR allows two exceptions, both read-only or one-way and neither carrying state:
1. Prometheus reads each Agent's `/metrics`.
2. The Coordinator hands an alert to an Exit's Agent for relay to Telegram (below).

Desired state, commands, and enrollment still flow only from Agent to Coordinator, so commit-confirm (ADR 0002) is unchanged.

Pulling from the domestic VM also suits the filter: connections from inside Iran outward usually succeed, while foreign hosts reaching into Iran usually do not (Link transport research, issue #3).

- **One port per Node**, with nftables accepting only the Coordinator VM's IP and silently dropping everyone else, so scanners see nothing.
- **mTLS on that port**, using the Coordinator's existing CA. Prometheus holds its own client certificate.
- **Targets come from the Coordinator** over HTTP service discovery, so enrolling or deleting a Node needs no Prometheus config edit.
- **Host metrics** come from node_exporter, installed by the playbook, bound to localhost, and served through the Agent's `/metrics`, so each Node still has one port.

## No Device or User in any metric

No metric label carries a Device or User identifier. Device figures appear only as counts per Bridge. Per-Device usage lives only in the Coordinator's metering rollups, under the retention set in ADR 0003. A per-Device time series in Prometheus would be a second copy of usage data and a record of when each Device was online, which ADR 0003 refuses to keep.

A consequence: per-Device anomalies, such as one Device using unusually much, are not alerts. They belong to quota enforcement.

## Metric set

- **Every Node:** Agent and build info, the applied snapshot version, `coordinator_last_contact_seconds`, apply failures, clock skew, expiry of its client certificate, and node_exporter host metrics.
- **Link** (labelled by its two Nodes): up, round-trip time, loss, the transport in use, transport changes, bytes.
- **Path:** share of buckets per candidate per Bridge per Rule, bucket moves by kind (failure or rebalancing), and number of eligible candidates ([ADR 0008](0008-path-selection-and-exit-balancing.md)).
- **Bridge:** count of active Devices (handshake in the last 3 minutes), total WireGuard bytes, version and age of its IR Destination Set, and metering backlog (hourly buckets not yet acknowledged).
- **Endpoint Slot:** the Bridge each slot points to, re-point count, number of eligible Bridges, ArvanCloud API errors.
- **Probe Device**, per Bridge: handshake success, DNS query success, latency.
- **Coordinator:** age of each Node's last report, CIDR refresh last success and gate rejections, last successful backup, HTTP errors, database size, and expiry of the CA, the public TLS certificate for `wayfinder.ir`, and API tokens.

## Alerts

| Alert | Fires when | Severity |
|---|---|---|
| Node unreachable | no successful scrape **and** no health report, for 3 min | critical |
| Coordinator unreachable from a Node | scrape works but `coordinator_last_contact_seconds` > 180 | warning |
| Link down | no working transport for 2 min | warning |
| Bridge has no Path for the default Rule | 1 min | critical |
| Path flapping | more than 6 failure moves per hour; rebalancing moves do not count (ADR 0008) | warning |
| Endpoint Slot re-pointed | each event | info |
| Bridge lost slot eligibility | each event | warning |
| All slots on one Bridge | 2 min | critical |
| ArvanCloud DNS API failing | 3 failures in a row | warning |
| Probe failing for a Bridge | 1 min | warning |
| Certificate or token expiring | Node certificate < 30 days (renewal is broken), public TLS < 14 days, API token < 7 days | warning |
| Clock skew | > 60 s | warning |
| CIDR refresh | a gate rejected the update, or the last good set is > 3 days old | warning |
| Backup stale | > 36 h since last success | warning |
| Metering backlog | > 3 h behind on a healthy Bridge | warning |
| Metering mismatch | metered bytes and Bridge interface bytes differ by > 20% per day | warning |
| Snapshot apply failed | each event | warning |
| Disk / conntrack | > 85% / > 80% | warning |

*(Amended by [ADR 0014](0014-abroad-devices.md): "Abroad Bridge removed from / returned to the Abroad Bridge Address" (warning / info), "Abroad Bridge Address down to one Bridge" (2 min, warning), and "No eligible Abroad Bridge" (2 min, critical).)*

*(Amended by [ADR 0015](0015-unlisted-bridges.md): "Bridge removed from the Bridge Address" does not fire for a Bridge an Admin has unlisted.)*

## Delivering alerts

Telegram is blocked domestically, so the Coordinator VM cannot reach it directly.

1. Alertmanager sends every alert as a webhook to the Coordinator on the same VM.
2. The Coordinator hands it to any healthy Exit, trying the next one if that fails.
3. That Exit's Agent forwards it to the Telegram channel, on the same allowlisted mTLS port.

No Exit is special, so throwing one away costs nothing. An alert that no Exit could deliver shows as a banner on the admin panel, so the operator still sees it from inside Iran during an international outage.

**SMS through a domestic gateway (designed, not in the MVP):**
- A domestic gateway such as Kavenegar requires identity verification with a national ID, and every message passes through the gateway and the mobile operator. So an SMS is a bare signal only, such as "WAYS: 2 critical, check Telegram/panel", with no Node names, IPs, or domains.
- Critical alerts only, at most one SMS every 15 minutes grouping everything fired in that window, plus one "all clear" when the last critical alert resolves.
- The Coordinator sends it through the gateway's HTTPS API. The operator's phone number lives only in the Coordinator's config file, never in the database: the one exception to ADR 0001's "no phone numbers".
- The MVP ships with no gateway key, so this channel stays switched off.

## Dashboards

The admin panel's status board shows the present; Grafana shows history.

Grafana listens on the Coordinator VM's loopback only. Admins open it through the panel at `/grafana/`: the Coordinator proxies it only for a signed-in Admin whose session proved TOTP, the same check as the Admin API, and names them to Grafana in its auth-proxy header, which Grafana trusts from loopback only. The browser's own copy of that header and the panel's session cookie are never passed on. *(Added 2026-10-19, [#56](https://github.com/alakiani/ways/issues/56); before, Grafana was reached through an SSH tunnel.)*
1. **Mesh:** Nodes, a grid of every Link with latency, loss, and transport, active Paths, and the Bridge behind each Endpoint Slot.
2. **User's-eye:** probe results and active Device counts per Bridge.
3. **Node detail:** host metrics and the Node's Links.
4. **Coordinator jobs:** CIDR refresh, backups, ArvanCloud API, metering backlog, certificate expiry.

## Considered options

- **The Coordinator re-publishes the health Agents push to it, so nothing dials a Node.** Rejected by the operator in favour of a direct pull, which is simpler and sees host metrics the health report does not carry.
- **Grafana on its own subdomain (`grafana.wayfinder.ir`) behind Grafana's own login.** Rejected: Grafana's login page and any Grafana flaw would face the internet from the one permanent host, and a `grafana` name in public DNS points at it.
- **Grafana only through an SSH tunnel.** The first deployment's way; dropped because it needs a laptop with the fleet's SSH key.
- **Prometheus and Grafana on a separate VM abroad.** Rejected: an extra permanent machine, and it goes blind exactly when the border link is cut.
- **A domestic messenger (Bale, Eitaa) for alerts.** Not chosen; SMS was preferred as the domestic channel.
- **An external dead-man's switch** (healthchecks.io, or a watcher on an abroad Node). Rejected for phase one.
