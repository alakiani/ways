// Walks every admin screen against a running lab, as an Admin would. The
// Go lab test (internal/e2e/admin_test.go) sets the lab up, runs this, and
// checks the effects in the Coordinator's store.
//
// Env: PANEL_URL, ADMIN_HANDLE, ADMIN_PASSWORD, TOTP_SECRET.
import { chromium } from "@playwright/test";
import { totp } from "./totp.mjs";

const { PANEL_URL, ADMIN_HANDLE, ADMIN_PASSWORD, TOTP_SECRET } = process.env;
// LIVE=0 skips what needs running Agents: for a quick run without the lab.
const LIVE = process.env.LIVE !== "0";

const step = (name) => console.log(`- ${name}`);
const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  page.setDefaultTimeout(30_000);
  // Prompts answer from this queue first; typed confirmations answer with
  // the name asked for.
  const answers = [];
  page.on("dialog", (d) => d.accept(answers.length ? answers.shift() : d.message().match(/Type "([^"]+)"/)?.[1]));
  const screen = async (path, heading) => {
    await page.goto(`${PANEL_URL}/#${path}`);
    await page.getByRole("heading", { name: heading, exact: true }).waitFor();
  };

  step("sign in with TOTP");
  await page.goto(`${PANEL_URL}/#/admin`);
  await page.fill("input[name=handle]", ADMIN_HANDLE);
  await page.fill("input[name=password]", ADMIN_PASSWORD);
  await page.click("button[type=submit]");
  await page.fill("input[name=code]", totp(TOTP_SECRET));
  await page.click("button[type=submit]");
  if ((await page.locator("html").getAttribute("dir")) !== "ltr") throw new Error("the admin panel is not left to right");

  step("overview: Node tiles and the Link matrix are live");
  await page.getByRole("heading", { name: "Overview" }).waitFor();
  if ((await page.getByRole("link", { name: "Grafana" }).getAttribute("href")) !== "/grafana/")
    throw new Error("the admin nav has no Grafana link");
  await page.locator("[data-testid=node-ab1]").waitFor();
  if (LIVE) {
    await page.locator("[data-testid=node-ir1]").getByText(/contact \d+s ago/).waitFor();
    await page.locator("[data-testid=link-matrix] td.up").first().waitFor({ timeout: 90_000 });
  }

  step("overview: the banner shows an alert no Exit could deliver, and the backup's state");
  await page.locator("[data-testid=undelivered-alerts]", { hasText: "NodeUnreachable: Node ab9 is unreachable" }).waitFor();
  await page.locator("[data-testid=backup]", { hasText: "off: no age recipient configured" }).waitFor();

  step("users: by share of Quota used with this period's Top-ups and Resets, then unlimited Users by bytes used");
  await screen("/admin/users", "Users");
  // sara's 10 GB Top-up puts her 40% below omid's 50%; without it she'd lead at 80%.
  await page.locator("[data-testid=user-sara] td.period", { hasText: "8.0 / 10 + 10 GB" }).waitFor();
  await page.locator("[data-testid=user-omid] td.period", { hasText: "1.0 / 2 GB" }).waitFor();
  await page.locator("[data-testid=user-nima] td.period", { hasText: "3.0 GB · ∞" }).waitFor();
  const order = await page.locator("tbody tr").evaluateAll((rows) => rows.map((r) => r.dataset.testid));
  const want = ["omid", "sara", "nima", "admin", "maryam", "reza"].map((h) => `user-${h}`);
  if (order.join() !== want.join()) throw new Error(`users in the order ${order}, want ${want}`);
  // Renews is a Gregorian date, not a day number or a Solar Hijri date.
  const renews = await page.locator("[data-testid=user-sara] td.renews").textContent();
  if (!/^\d{1,2} [A-Z][a-z]{2} 20\d\d$/.test(renews)) throw new Error(`Renews shows ${renews}`);
  if (await page.locator("[data-testid=user-nima]").getByRole("button", { name: "Reset now" }).count())
    throw new Error("an unlimited User offers Reset now");

  step("users: suspend, resume, cap, recovery Invite, delete");
  const user = page.locator("[data-testid=user-maryam]");
  await user.getByRole("button", { name: "Suspend" }).click();
  await user.locator(".status", { hasText: "Suspended" }).waitFor();
  await user.getByRole("button", { name: "Resume" }).click();
  await user.locator(".status", { hasText: "Active" }).waitFor();
  await user.getByLabel("Device cap").fill("5");
  await user.getByLabel("Device cap").blur();
  await page.waitForResponse((r) => r.url().endsWith("/v1/admin/users") && r.request().method() === "GET");
  // The abroad permission (ADR 0014).
  // The box shows what the Coordinator holds, so it ticks after the reload.
  await Promise.all([
    page.waitForResponse((r) => r.url().endsWith("/abroad") && r.request().method() === "POST"),
    user.getByLabel("Abroad").click(),
  ]);
  await user.getByLabel("Abroad").and(page.locator(":checked")).waitFor();
  await user.getByRole("button", { name: "Recovery Invite" }).click();
  await page.locator("[data-testid=recovery-link]", { hasText: "/#/invite/" }).waitFor();
  await page.locator("[data-testid=user-reza]").getByRole("button", { name: "Delete" }).click();
  await page.locator("[data-testid=user-reza]").waitFor({ state: "detached" });

  step("users: set a Quota inline and slow when out");
  const quota = (r) => r.url().endsWith("/quota") && r.request().method() === "POST";
  await user.getByLabel("Quota").fill("2.5");
  let saved = page.waitForResponse(quota);
  await user.getByLabel("Quota").blur();
  await saved;
  await user.locator("td.period", { hasText: "0.0 / 2.5 GB" }).waitFor();
  saved = page.waitForResponse(quota);
  await user.getByLabel("Running out").selectOption("slow");
  await saved;
  await user.getByLabel("Mbit/s").fill("4");
  saved = page.waitForResponse(quota);
  await user.getByLabel("Mbit/s").blur();
  await saved;

  step("users: Top-up, Reset now, Give Refill");
  answers.push("1.5");
  saved = page.waitForResponse((r) => r.url().endsWith("/top-up") && r.status() === 200);
  await user.getByRole("button", { name: "Top-up" }).click();
  await saved;
  await user.locator("td.period", { hasText: "0.0 / 2.5 + 1.5 GB" }).waitFor();
  saved = page.waitForResponse((r) => r.url().endsWith("/reset") && r.status() === 200);
  await page.locator("[data-testid=user-omid]").getByRole("button", { name: "Reset now" }).click();
  await saved;
  answers.push("2", "45");
  await user.getByRole("button", { name: "Give Refill" }).click();
  await user.locator("td.refills", { hasText: /^2$/ }).waitFor();

  step("invites: create and withdraw");
  await screen("/admin/invites", "Invites");
  await page.fill("input[name=cap]", "2");
  await page.getByRole("button", { name: "Create Invite" }).click();
  await page.locator("[data-testid=invite-url]", { hasText: "/#/invite/" }).waitFor();
  const before = await page.locator("[data-testid=invite-withdrawn]").count();
  await page.locator("[data-testid=invite-open]").first().getByRole("button", { name: "Withdraw" }).click();
  await page.waitForFunction((n) => document.querySelectorAll("[data-testid=invite-withdrawn]").length > n, before);

  step("invites: create one with a Quota, slow when out, and Refills; its row shows them");
  if ((await page.inputValue("input[name=quota]")) !== "" || (await page.inputValue("select[name=running_out]")) !== "block" ||
    (await page.inputValue("input[name=refills]")) !== "0" || (await page.inputValue("input[name=refill_days]")) !== "30")
    throw new Error("the Invite form's Quota defaults are not Unlimited, Block, 0 Refills and 30 days");
  await page.fill("input[name=quota]", "5");
  await page.selectOption("select[name=running_out]", "slow");
  await page.fill("input[name=mbits]", "2");
  await page.fill("input[name=refills]", "2");
  await page.fill("input[name=refill_days]", "60");
  const created = page.waitForResponse((r) => r.url().endsWith("/v1/admin/invites") && r.request().method() === "POST");
  await page.getByRole("button", { name: "Create Invite" }).click();
  // The Go test looks the Invite up by its token.
  console.log(`preset invite: ${(await (await created).json()).url}`);
  await page.locator("[data-testid=invite-open] td.presets", { hasText: "5 GB · Slow 2 Mbit/s · 2 Refills / 60 d" }).waitFor();

  step("nodes: add with the enroll command, open a Bridge's Paths, unlist it, edit, delete");
  await screen("/admin/nodes", "Nodes");
  await page.fill("input[name=name]", "ab9");
  await page.fill("input[name=tags]", "DE");
  await page.fill("input[name=host]", "203.0.113.9");
  await page.getByRole("button", { name: "Add Node" }).click();
  const command = await page.locator("[data-testid=enroll-command]").textContent();
  if (!command.includes("enroll.yml") || !command.includes("enroll_token=")) throw new Error(`bad command: ${command}`);
  if (LIVE) {
    await page.locator("[data-testid=node-row-ir1] a").click();
    await page.locator("[data-testid=paths]", { hasText: "Default" }).waitFor();
    // ab1 is a candidate once its first egress checks have passed.
    await page.locator("[data-testid=paths]", { hasText: "ab1" }).waitFor({ timeout: 90_000 });
    // ir2 is in the Bridge Address too, so ir1 may be unlisted (ADR 0015).
    await page.getByRole("button", { name: "Unlist", exact: true }).click();
    await page.getByRole("button", { name: "List again", exact: true }).waitFor();
    await page.goto(`${PANEL_URL}/#/admin/nodes`);
    await page.locator("[data-testid=node-row-ir1]", { hasText: "unlisted" }).waitFor();
  }
  await page.locator("[data-testid=node-row-ab9] a").click();
  await page.locator("[data-testid=node-name]", { hasText: "ab9" }).waitFor();
  await page.fill("input[name=tags]", "NL");
  await page.getByRole("button", { name: "Save" }).click();
  await page.waitForResponse((r) => r.url().includes("/v1/admin/nodes/") && r.request().method() === "GET");
  await page.getByRole("button", { name: "Delete Node" }).click();
  await page.getByRole("heading", { name: "Nodes", exact: true }).waitFor();
  await page.locator("[data-testid=node-row-ab9]").waitFor({ state: "detached" });

  step("links: health and the Transport list");
  await screen("/admin/links", "Links");
  if (LIVE) await page.locator("[data-testid=links] .status", { hasText: "up" }).first().waitFor();
  await page.uncheck("input[name=transport-wireguard]");
  await page.waitForResponse((r) => r.url().endsWith("/v1/admin/transports") && r.request().method() === "POST");
  await page.check("input[name=transport-wireguard]");
  await page.waitForResponse((r) => r.url().endsWith("/v1/admin/transports") && r.request().method() === "POST");

  step("rules: change the IR Rule; the default and Abroad Rules are locked");
  await screen("/admin/rules", "Rules");
  const ir = page.locator("[data-testid=rule-IR]");
  await ir.locator("select[name=fallback]").selectOption("drop");
  await ir.getByRole("button", { name: "Save" }).click();
  await ir.locator(".status", { hasText: "drop" }).waitFor();
  await ir.locator("select[name=fallback]").selectOption("next");
  await ir.getByRole("button", { name: "Save" }).click();
  await ir.locator(".status", { hasText: "next" }).waitFor();
  await page.locator("[data-testid=rule-Default]", { hasText: "locked" }).waitFor();
  if ((await page.locator("[data-testid=rule-Default] input, [data-testid=rule-Default] select").count()) > 0) {
    throw new Error("the default Rule can be edited");
  }
  // The Abroad Rule is locked too, and shown first (ADR 0014).
  await page.locator("[data-testid=rule-Abroad]", { hasText: "Abroad Devices (10.77.128.0/17)" }).waitFor();
  if ((await page.locator("[data-testid=rule-Abroad] input, [data-testid=rule-Abroad] select").count()) > 0) {
    throw new Error("the Abroad Rule can be edited");
  }
  const rules = await page.locator("[data-testid^=rule-]").evaluateAll((els) => els.map((e) => e.dataset.testid));
  if (rules.join() !== "rule-Abroad,rule-IR,rule-Default") throw new Error(`Rules in the order ${rules}`);

  step("destination sets: fetch now, overrides, roll back");
  await screen("/admin/sets", "Destination Sets");
  const iran = page.locator("[data-testid=set-Iran]");
  // The feed now serves one prefix more than when the lab started.
  const prefixes = (n) => iran.locator("[data-testid=prefixes]", { hasText: new RegExp(`^${n}$`) }).waitFor();
  await iran.getByRole("button", { name: "Fetch now" }).click();
  await prefixes(4);
  await iran.locator("textarea[name=additions]").fill("185.0.0.0/24");
  await iran.getByRole("button", { name: "Save overrides" }).click();
  await prefixes(5);
  // Roll back restores the previous feed update; overrides stay.
  await iran.getByRole("button", { name: "Roll back" }).click();
  await prefixes(4);

  step("API tokens: create, see the secret once, revoke");
  await screen("/admin/tokens", "API tokens");
  await page.fill("input[name=name]", "ops-laptop");
  await page.getByRole("button", { name: "Make a nodes:enroll token" }).click();
  await page.locator("[data-testid=token-secret]", { hasText: "ways_" }).waitFor();
  await page.locator("[data-testid=token-ops-laptop]").getByRole("button", { name: "Revoke" }).click();
  await page.locator("[data-testid=token-ops-laptop] .status", { hasText: "revoked" }).waitFor();

  console.log("walked every admin screen");
} catch (e) {
  console.error(e);
  process.exitCode = 1;
} finally {
  await browser.close();
}
