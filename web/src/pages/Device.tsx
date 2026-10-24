import { useEffect, useState } from "react";
import { api, type DeviceInfo, type DeviceUsage, type IssuedDevice, type UsageRow } from "../api/client";
import { generateKeyPair } from "../lib/keys";
import { fa } from "../fa";
import { go } from "../router";
import { Configs } from "./Configs";
import { stateLabel } from "./Home";

export function DevicePage({ id, onChange }: { id: string; onChange: () => void }) {
  const [device, setDevice] = useState<DeviceInfo | null>(null);
  const [issued, setIssued] = useState<{ device: IssuedDevice; privateKey: string } | null>(null);
  const [usage, setUsage] = useState<DeviceUsage | null>(null);
  useEffect(() => {
    api.GET("/v1/me/devices").then(({ data }) => setDevice(data?.find((d) => d.id === id) ?? null));
    api.GET("/v1/me/devices/{id}/usage", { params: { path: { id } } }).then(({ data }) => setUsage(data ?? null));
  }, [id]);

  if (issued) {
    return (
      <Configs
        issued={issued.device}
        privateKey={issued.privateKey}
        onSaved={() => {
          setIssued(null);
          onChange();
          go("/");
        }}
      />
    );
  }
  if (!device) return null;

  const revoke = async () => {
    if (!confirm(fa.revokeConfirm)) return;
    await api.POST("/v1/me/devices/{id}/revoke", { params: { path: { id } } });
    onChange();
    go("/");
  };
  const replace = async () => {
    const keys = generateKeyPair();
    const { data } = await api.POST("/v1/me/devices/{id}/replace", {
      params: { path: { id } },
      body: { name: device.name, public_key: keys.publicKey },
    });
    if (data) setIssued({ device: data, privateKey: keys.privateKey });
  };

  return (
    <section>
      <h1>
        {fa.device}: {device.name} <span className={`state ${device.state}`}>{stateLabel(device)}</span>
      </h1>
      <dl>
        <dt>{fa.address}</dt>
        <dd dir="ltr">{device.address}</dd>
        <dt>{fa.created}</dt>
        <dd>{new Date(device.created_at).toLocaleDateString("fa-IR")}</dd>
      </dl>
      <h2>{fa.usage}</h2>
      {usage && <Usage usage={usage} />}
      <p className="hint">{fa.stuckHint}</p>
      {!device.revoked && (
        <div className="actions">
          <p>{fa.replaceHint}</p>
          <button type="button" onClick={replace}>
            {fa.replace}
          </button>
          <button type="button" className="danger" onClick={revoke}>
            {fa.revoke}
          </button>
        </div>
      )}
      <a href="#/">{fa.back}</a>
    </section>
  );
}

/** Bytes, in the units people read: KB, MB, GB. */
export function bytes(n: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1000 && i < units.length - 1) {
    n /= 1000;
    i++;
  }
  return `${n.toLocaleString("fa-IR", { maximumFractionDigits: n < 10 && i > 0 ? 1 : 0 })} ${units[i]}`;
}

function Rows({ rows, withExit, label }: { rows: UsageRow[]; withExit: boolean; label: (p: string) => string }) {
  return (
    <table className="usage">
      <thead>
        <tr>
          <th>{fa.period}</th>
          {withExit && <th>{fa.exit}</th>}
          <th>{fa.up}</th>
          <th>{fa.down}</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.period + (r.exit ?? "")}>
            <td>{label(r.period)}</td>
            {withExit && <td dir="ltr">{r.exit}</td>}
            <td>{bytes(r.up)}</td>
            <td>{bytes(r.down)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Usage({ usage }: { usage: DeviceUsage }) {
  if (usage.daily.length === 0) return <p className="muted">{fa.noUsage}</p>;
  const day = (p: string) => new Date(p + "T00:00:00Z").toLocaleDateString("fa-IR");
  const hour = (p: string) => new Date(p).toLocaleString("fa-IR", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
  return (
    <div data-testid="usage">
      <h3>{fa.thisPeriod}</h3>
      <Rows rows={[usage.period]} withExit={false} label={(p) => fa.since + " " + day(p)} />
      <h3>{fa.daily}</h3>
      <Rows rows={[...usage.daily].reverse().slice(0, 30)} withExit label={day} />
      <h3>{fa.hourly}</h3>
      <Rows rows={[...usage.hourly].reverse().slice(0, 24)} withExit label={hour} />
    </div>
  );
}
