# WAYS

**There is always a way.** WAYS (راه, "way" in Farsi) is a censorship-circumvention VPN for
people in Iran. Users connect with the stock WireGuard app. Their traffic enters a domestic
**Bridge** and leaves the internet through an **Exit** that WAYS picks by policy and health:
abroad for the open internet, inside Iran for Iranian sites.

Everything is run from one **Coordinator**. It holds identity, topology, policy and metering,
and it never touches a packet.

## How it works

```
 Device (stock WireGuard)
    │  bridge.wayfinder.ir  ── one eligible domestic Bridge per DNS lookup
    ▼
 Bridge (inside Iran) ──Link──► Exit abroad  ──► open internet
    │                  (GRE / AmneziaWG / WireGuard, chosen by health)
    └──────────────────Link──► Exit tagged IR ──► Iranian sites

 Coordinator (domestic VM): Users, Devices, Nodes, Links, Rules, usage
    ▲ HTTPS long-poll snapshots, health and usage reports
 Agent on every Node
```

- **Nodes** are Ubuntu servers. Each one runs the **Agent**, which applies what the Coordinator
  decides, measures its **Links**, and reports health and usage. A Node holds the Bridge role,
  the Exit role, or both, and carries **Tags** such as `IR`.
- **Links** between Nodes find out which **Transport** works by trying them, never from
  configuration: plain GRE, AmneziaWG or plain WireGuard. A Link switches Transport when one
  gets blocked.
- **Rules** map **Destination Sets** (for example the Iranian address space, fed daily and
  checked against RIPEstat) to the Tags an Exit must carry. Bridges evaluate them. DNS is
  always resolved abroad, and IPv6 is dropped.
- **Path selection** runs locally on each Bridge. It spreads Devices across Exits by measured
  capacity, and when an Exit or Link fails it moves their traffic within seconds.
- **The Bridge Address** is the one hostname in every config. Each lookup answers with one
  eligible Bridge. A failed Bridge leaves the record after 60 s, and the User toggles the tunnel
  to move to a live one.
- **Users** join through single-use **Invites**, sign in with a password and TOTP, and create
  **Devices**. Keys are generated in the browser, and private keys are never stored. **Usage**
  is metered per Device and counted against a per-User **Quota**.
- **Monitoring:** Prometheus on the Coordinator VM pulls from the Agents, and alerts reach
  Telegram through an Exit.

The Coordinator is hosted inside Iran so it stays reachable during an international
shutdown. For the same reason it keeps as little as it can: a handle and credentials per User,
no email or phone number, and no destination, DNS or flow logs.

[`GLOSSARY.md`](GLOSSARY.md) defines every capitalised term above. The decisions behind them
are in [`docs/adr/`](docs/adr/).

## Repository layout

| Path | What it holds |
|---|---|
| `cmd/coordinator` | The Coordinator binary, which embeds the panel. Also `token create`, `invite create` and `backup restore` |
| `cmd/agent` | The Agent binary that runs on every Node |
| `internal/coordinator` | The HTTP APIs, background jobs, the OpenAPI spec (`openapi.json`) |
| `internal/store` | Every SQLite query, plus the embedded migrations |
| `internal/agent`, `internal/dataplane`, `internal/link` | The Agent, nftables data plane, Links and Transports |
| `internal/lab` | The lab: network-namespace Nodes with `tc netem` and filter injection |
| `internal/e2e` | End-to-end tests that run in the lab |
| `web/` | The panel (React, Vite, TypeScript, Mantine): a Farsi User panel and an English admin panel |
| `deploy/ansible` | `coordinator.yml` and `enroll.yml` playbooks |
| `deploy/monitoring` | Generated Prometheus, Alertmanager and Grafana configuration |
| `scripts/` | Build, fetch, provision and deploy helpers |
| `docs/` | ADRs, the MVP plan, research notes |

## Development

You need Go (the version in `go.mod`) and Node 24. The lab needs Linux and root.

The Coordinator embeds the panel, so build the panel before any Go step:

```sh
cd web
npm ci
npm test          # Vitest
npm run build     # generates the API client from openapi.json, type-checks, builds into internal/panel
cd ..

go build -o bin/ ./cmd/...
```

### Tests

```sh
go test ./...                                  # unit tests; lab tests skip without root
go test -exec sudo -race -count=1 ./...        # everything, including the lab (Linux)
```

The lab starts Nodes as network namespaces, each running the real Agent, together with the
real Coordinator. It joins them with veth pairs, adds latency and loss with `tc netem`, and
imitates the filter with nftables. It needs `nftables`, `iproute2` and the `wireguard`,
`ip_gre` and `sch_netem` kernel modules. Lab tests look for the Agent, `amneziawg-go`,
Prometheus and Alertmanager binaries in `WAYS_BIN`. [`.github/workflows/ci.yml`](.github/workflows/ci.yml)
is the exact recipe.

After changing the generated monitoring configuration, refresh the golden files with
`go test ./internal/monitoring -update`.

### Working on the panel

Run a Coordinator locally over plain HTTP, create an Invite, and start Vite. Vite proxies
`/v1` to port 8080.

```sh
bin/coordinator -db ./dev.db -ca-dir ./dev-ca -admin-listen 127.0.0.1:8080 -agent-listen 127.0.0.1:8443
bin/coordinator invite create -db ./dev.db -admin -panel-url http://localhost:5173
cd web && npm run dev
```

## Releases and deployment

Binaries are pushed from the operator's laptop and never pulled by a Node. This way,
installing a domestic Node never depends on reaching anything abroad.

1. **Release:** push a tag (`git tag v1.2.0 && git push origin v1.2.0`). The Release workflow
   builds the Agent, the Coordinator, the pinned `amneziawg-go`, Prometheus, Alertmanager and
   Grafana (versions in [`deploy/versions.env`](deploy/versions.env)) with a `SHA256SUMS`.
2. **Fetch:** `scripts/fetch-release.sh v1.2.0` downloads it to `~/.ways/releases/` and verifies it.
3. **Deploy:** `scripts/ways-ansible coordinator.yml`, then `scripts/ways-ansible enroll.yml`.
   Rerun either one to upgrade in place.

[`deploy/ansible/README.md`](deploy/ansible/README.md) covers the full walkthrough, including
first-time provisioning with `scripts/provision-fleet.sh`. CI tests both playbooks against
Ubuntu 26.04 containers on every pull request.

## Documentation

- [`GLOSSARY.md`](GLOSSARY.md): the domain language. Code, docs and the UI use these terms.
- [`docs/adr/`](docs/adr/): architecture decisions 0001–0011.
- [`docs/mvp-plan.md`](docs/mvp-plan.md): the MVP build plan and acceptance test.
- [`docs/research/`](docs/research/): background research on transports, CIDR feeds, path
  selection, and the limits of stock WireGuard clients.

Issues and specs live in [GitHub Issues](https://github.com/alakiani/ways/issues).
