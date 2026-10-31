import { describe, expect, it } from "vitest";
import { byQuotaShare, gbField, mbits, parseGB, periodText, presetsText, rateOf, renews } from "./quota";

const user = (handle: string, period_bytes: number, quota?: number, period_remedies = 0) => ({
  handle,
  period_bytes,
  quota,
  period_remedies,
});

describe("the Users table's Quota columns", () => {
  it("shows this period against the Quota, or with ∞ when unlimited", () => {
    expect(periodText(user("a", 3.2e9, 5e9))).toBe("3.2 / 5 GB");
    expect(periodText(user("a", 12e6, 2.5e9))).toBe("0.0 / 2.5 GB");
    expect(periodText(user("a", 3.2e9))).toBe("3.2 GB · ∞");
    expect(periodText(user("a", 0))).toBe("0 B · ∞");
  });

  it("adds this period's Top-ups and Resets to the Quota", () => {
    expect(periodText(user("a", 3.2e9, 5e9, 2e9))).toBe("3.2 / 5 + 2 GB");
    expect(periodText(user("a", 3.2e9, 5e9, 1e6))).toBe("3.2 / 5 GB"); // under 0.05 GB
    expect(periodText(user("a", 3.2e9, undefined, 2e9))).toBe("3.2 GB · ∞");
  });

  it("orders Users by share of Quota used, then unlimited Users by bytes used", () => {
    const users = [
      user("nima", 3e9),
      user("omid", 1e9, 2e9),
      user("reza", 0),
      user("sara", 8e9, 10e9),
      user("maryam", 0),
      user("zero", 0, 0),
    ];
    expect(users.sort(byQuotaShare).map((u) => u.handle)).toEqual(["zero", "sara", "omid", "nima", "maryam", "reza"]);
  });

  it("counts this period's Top-ups and Resets in the share of Quota used", () => {
    const users = [
      user("sara", 8e9, 10e9, 10e9), // 40%
      user("omid", 1e9, 2e9), // 50%
      user("ali", 1e9, 0, 2e9), // 50%: a zero Quota with a Top-up
      user("zero", 1e9, 0), // nothing to use: fully used
      user("nima", 3e9, undefined, 5e9), // unlimited stays last
    ];
    expect(users.sort(byQuotaShare).map((u) => u.handle)).toEqual(["zero", "ali", "omid", "sara", "nima"]);
  });

  it("reads and writes Quotas in GB with one decimal, empty for unlimited", () => {
    expect(gbField(2.5e9)).toBe("2.5");
    expect(gbField(5e9)).toBe("5");
    expect(gbField(undefined)).toBe("");
    expect(parseGB("")).toBeNull();
    expect(parseGB(" 2.5 ")).toBe(2.5e9);
    expect(parseGB("0.25")).toBe(0.3e9);
    expect(parseGB("-1")).toBeUndefined();
    expect(parseGB("lots")).toBeUndefined();
  });

  it("converts Mbit/s to bytes per second and back", () => {
    expect(rateOf(4)).toBe(500_000);
    expect(rateOf(1.5)).toBe(187_500);
    expect(mbits(125_000)).toBe("1");
    expect(mbits(187_500)).toBe("1.5");
  });

  it("shows the renewal as a Gregorian date in UTC", () => {
    expect(renews("2026-11-24T00:00:00Z")).toBe("24 Nov 2026");
    expect(renews("2026-09-01T00:00:00Z")).toBe("1 Sep 2026");
  });
});

describe("the Invites table's Presets column", () => {
  const invite = (p: object) => ({ kind: "new", ...p });

  it("shows the Quota, what happens when it runs out, and the Refills", () => {
    expect(presetsText(invite({ quota: 5e9, running_out: "slow", rate: 250_000, refills: 2, refill_days: 60 }))).toBe(
      "5 GB · Slow 2 Mbit/s · 2 Refills / 60 d",
    );
    expect(presetsText(invite({ quota: 2.5e9, running_out: "block", refills: 1, refill_days: 30 }))).toBe("2.5 GB · Block · 1 Refill / 30 d");
    expect(presetsText(invite({ quota: 5e9, running_out: "block" }))).toBe("5 GB · Block");
  });

  it("shows the abroad permission last", () => {
    expect(presetsText(invite({ running_out: "block", abroad: true }))).toBe("Unlimited · Abroad");
    expect(presetsText(invite({ quota: 5e9, running_out: "block", refills: 1, refill_days: 30, abroad: true }))).toBe(
      "5 GB · Block · 1 Refill / 30 d · Abroad",
    );
  });

  it("shows Unlimited without a Quota, and nothing for a recovery Invite", () => {
    expect(presetsText(invite({ running_out: "block" }))).toBe("Unlimited");
    expect(presetsText(invite({ running_out: "block", refills: 3, refill_days: 10 }))).toBe("Unlimited · 3 Refills / 10 d");
    expect(presetsText({ kind: "recovery" })).toBe("");
  });
});
