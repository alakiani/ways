import { useEffect, useState } from "react";
import { api } from "../api/client";
import { ago, bytes, type Overview } from "./api";

// The status board (variant A in the prototype): Node tiles, a Link
// latency matrix, and the Coordinator card.
export function OverviewScreen() {
  const [o, setO] = useState<Overview | null>(null);
  const load = () => api.GET("/v1/admin/overview").then(({ data }) => setO(data ?? null));
  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);
  if (!o) return null;
  const names = o.nodes.map((n) => n.name);
  const link = (a: string, b: string) => o.links.find((l) => (l.a === a && l.b === b) || (l.a === b && l.b === a));

  return (
    <section>
      <h1>Overview</h1>
      {o.undelivered_alerts.length > 0 && (
        // Alerts no Exit could relay to Telegram (ADR 0006): seen here even
        // during an international outage.
        <div className="warning" role="alert" data-testid="undelivered-alerts">
          <strong>
            {o.undelivered_alerts.length} alert{o.undelivered_alerts.length > 1 && "s"} could not reach Telegram
          </strong>
          {o.undelivered_alerts.map((a) => (
            <div key={a.id}>
              <pre>{a.text}</pre>
              <span className="muted">
                received {ago(a.received_at)}, {a.attempts} attempt{a.attempts > 1 && "s"}: {a.last_error}
              </span>
            </div>
          ))}
        </div>
      )}
      <div className="tiles">
        {o.nodes.map((n) => (
          <a key={n.id} className="tile" href={`#/admin/nodes/${n.id}`} data-testid={`node-${n.name}`}>
            <strong>{n.name}</strong>
            <span>{n.roles.join(" + ")}</span>
            <span>{n.tags.length ? n.tags.join(", ") : "no tags"}</span>
            <span className={n.last_contact ? "" : "error"}>contact {ago(n.last_contact)}</span>
            <span>
              snapshot {n.applied_version}/{n.latest_version}
              {n.applied_version !== n.latest_version && " (behind)"}
            </span>
            {n.agent_version && <span>agent {n.agent_version}</span>}
            {n.addr && n.seen_addr && n.addr !== n.seen_addr && (
              <span className="error">
                says {n.addr}, seen as {n.seen_addr}
              </span>
            )}
          </a>
        ))}
      </div>

      <h2>Link latency</h2>
      <table className="matrix" data-testid="link-matrix">
        <thead>
          <tr>
            <th />
            {names.map((n) => (
              <th key={n}>{n}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {names.map((a) => (
            <tr key={a}>
              <th>{a}</th>
              {names.map((b) => {
                const l = a === b ? undefined : link(a, b);
                if (!l) return <td key={b} />;
                const up = l.up_a || l.up_b;
                return (
                  <td key={b} className={up ? "up" : "down"} title={l.transport}>
                    {up ? `${l.rtt_ms.toFixed(0)} ms` : "down"}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>

      <h2>
        Bridge Address <span dir="ltr">{o.bridge_address.host}</span>
      </h2>
      {!o.bridge_address.published && <p className="error">The record has not been updated since the Coordinator started.</p>}
      <table data-testid="bridge-address">
        <tbody>
          {o.bridge_address.bridges.map((b) => (
            <tr key={b.name}>
              <th>{b.name}</th>
              <td>{b.addr ?? "no address yet"}</td>
              <td className={b.in_record ? "up" : "down"}>{b.in_record ? `in the record since ${ago(b.joined)}` : "out of the record"}</td>
              <td className={b.eligible ? "up" : "down"}>{b.eligible ? "eligible" : (b.reasons ?? ["not probed yet"]).join(", ")}</td>
              <td>
                probe {b.probe ? (b.probe.ok ? "passing" : "failing") : "pending"} {b.probe && ago(b.probe.at)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p>
        Since the Coordinator started: {o.bridge_address.joins} joined, {o.bridge_address.removals} removed.
      </p>

      <h2>Coordinator</h2>
      <div className="card">
        {o.sets
          .filter((s) => s.feed)
          .map((s) => (
            <p key={s.id}>
              {s.name} feed: {s.prefixes} prefixes, updated {ago(s.updated_at)}
              {s.last_error && <span className="error"> — last update rejected: {s.last_error}</span>}
            </p>
          ))}
        <p data-testid="backup">
          Nightly backup:{" "}
          {!o.backup.configured ? (
            <span className="error">off: no age recipient configured</span>
          ) : (
            <>
              last good {ago(o.backup.last_success)}
              {o.backup.last_success && `, ${bytes(o.backup.size_bytes)}`}
              {o.backup.last_error && <span className="error"> — last attempt failed: {o.backup.last_error}</span>}
            </>
          )}
        </p>
      </div>
    </section>
  );
}
