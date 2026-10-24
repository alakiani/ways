import type { components } from "../api/schema";

export type Overview = components["schemas"]["Overview"];
export type NodeTile = components["schemas"]["NodeTile"];
export type LinkTile = components["schemas"]["LinkTile"];
export type SetInfo = components["schemas"]["SetInfo"];
export type RuleInfo = components["schemas"]["RuleInfo"];
export type InviteRecord = components["schemas"]["InviteRecord"];
export type NodeDetail = components["schemas"]["NodeDetail"];
export type UserInfo = components["schemas"]["UserInfo"];
export type TokenInfo = components["schemas"]["TokenInfo"];
export type TransportList = components["schemas"]["TransportList"];

export function ago(iso?: string): string {
  if (!iso) return "never";
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function bytes(n: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1000 && i < units.length - 1) {
    n /= 1000;
    i++;
  }
  return `${n.toFixed(n < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

/** Asks the Admin to type a name before something destructive. */
export function typedConfirm(what: string, name: string): boolean {
  return prompt(`This cannot be undone. Type "${name}" to ${what}.`) === name;
}
