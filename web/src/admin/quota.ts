// The Users table's and Invite form's Quota fields (ADR 0010): decimal GB
// with one decimal place, Mbit/s for Slow, Gregorian dates.
import { bytes } from "./api";

const GB = 1e9;
/** Bytes per second in one Mbit/s. */
const MBIT = 125_000;

/** period_remedies is the bytes this period's Top-ups and Resets added. */
type Usage = { period_bytes: number; quota?: number | null; period_remedies?: number };

/** "3.2 / 5 GB", "3.2 / 5 + 2 GB" with this period's Top-ups and Resets,
 * or "3.2 GB · ∞" when the Quota is unlimited. */
export function periodText(u: Usage): string {
  if (u.quota == null) return `${bytes(u.period_bytes)} · ∞`;
  const remedies = gbField(u.period_remedies ?? 0);
  return `${(u.period_bytes / GB).toFixed(1)} / ${gbField(u.quota)}${remedies === "0" ? "" : ` + ${remedies}`} GB`;
}

/** Highest share of Quota used first, against the Quota plus this period's
 * Top-ups and Resets; nothing to use counts as fully used. Unlimited Users
 * last, by bytes used; ties by handle. */
export function byQuotaShare(a: Usage & { handle: string }, b: Usage & { handle: string }): number {
  const share = (u: Usage) => {
    if (u.quota == null) return -1;
    const may = u.quota + (u.period_remedies ?? 0);
    return may > 0 ? u.period_bytes / may : Infinity;
  };
  const [x, y] = [share(a), share(b)];
  if (x !== y) return y - x;
  if (x === -1 && a.period_bytes !== b.period_bytes) return b.period_bytes - a.period_bytes;
  return a.handle.localeCompare(b.handle);
}

type Presets = {
  kind: string;
  quota?: number | null;
  running_out?: string;
  rate?: number;
  refills?: number;
  refill_days?: number;
  abroad?: boolean;
};

/** What a new-User Invite presets: "5 GB · Slow 2 Mbit/s · 2 Refills / 60 d",
 * or "Unlimited", then "Abroad" with the abroad permission (ADR 0014). A
 * recovery Invite presets nothing. */
export function presetsText(i: Presets): string {
  if (i.kind !== "new") return "";
  const parts = [];
  if (i.quota == null) parts.push("Unlimited");
  else parts.push(`${gbField(i.quota)} GB`, i.running_out === "slow" ? `Slow ${mbits(i.rate ?? 0)} Mbit/s` : "Block");
  if (i.refills) parts.push(`${i.refills} ${i.refills === 1 ? "Refill" : "Refills"} / ${i.refill_days} d`);
  if (i.abroad) parts.push("Abroad");
  return parts.join(" · ");
}

/** A Quota as a GB field's value; empty is unlimited. */
export function gbField(n?: number | null): string {
  return n == null ? "" : String(Math.round(n / (GB / 10)) / 10);
}

/** A GB field's bytes: null when empty (unlimited), undefined when invalid. */
export function parseGB(s: string): number | null | undefined {
  if (s.trim() === "") return null;
  const v = Number(s);
  if (!Number.isFinite(v) || v < 0) return undefined;
  return Math.round(v * 10) * (GB / 10);
}

/** Bytes per second for a rate in Mbit/s. */
export function rateOf(mbit: number): number {
  return Math.round(mbit * MBIT);
}

/** A rate in bytes per second as Mbit/s. */
export function mbits(rate: number): string {
  return String(Math.round((rate / MBIT) * 10) / 10);
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** A day in the Gregorian calendar, in English, whatever the browser's
 * locale: "24 Nov 2026". Quota Periods start at 00:00 UTC. */
export function renews(iso: string): string {
  const d = new Date(iso);
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}
