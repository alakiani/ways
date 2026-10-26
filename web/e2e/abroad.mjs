// Walks the User panel's Abroad Devices (ADR 0014) as two Users would: one
// without the abroad permission sees no way to make one; one with it makes
// one, sees its notice, and saves a config that reaches the Abroad Bridge
// Address. The Go test (internal/e2e/abroad_panel_test.go) sets the Users
// up, runs this, and checks the Device in the Coordinator's store.
//
// Env: PANEL_URL, PASSWORD, OUT_DIR.
import { readFile } from "node:fs/promises";
import { chromium } from "@playwright/test";

const { PANEL_URL, PASSWORD, OUT_DIR } = process.env;

const step = (name) => console.log(`- ${name}`);
const fail = (msg) => {
  throw new Error(msg);
};

const browser = await chromium.launch();
try {
  const signIn = async (handle) => {
    const ctx = await browser.newContext({ locale: "fa-IR", acceptDownloads: true });
    const page = await ctx.newPage();
    page.setDefaultTimeout(20_000);
    await page.goto(`${PANEL_URL}/#/`);
    await page.fill("input[name=handle]", handle);
    await page.fill("input[name=password]", PASSWORD);
    await page.click("button[type=submit]");
    await page.locator('a[href="#/devices/new"]').waitFor();
    return page;
  };

  step("reza, without the permission: no Abroad Device to make");
  {
    const page = await signIn("reza");
    if ((await page.locator('a[href="#/devices/new-abroad"]').count()) !== 0) fail("reza is offered an Abroad Device");
    await page.context().close();
  }

  step("sara, with it: makes an Abroad Device and sees its notice");
  {
    const page = await signIn("sara");
    await page.click('a[href="#/devices/new-abroad"]');
    await page.locator("[data-testid=abroad-notice]", { hasText: "فیلتر" }).waitFor();
    await page.fill("input[name=name]", "phone abroad");
    await page.click("button[type=submit]");
    await page.waitForFunction(() => document.querySelectorAll("figure img").length === 1);
    const [download] = await Promise.all([page.waitForEvent("download"), page.click("[data-testid=download-conf]")]);
    const path = `${OUT_DIR}/abroad.conf`;
    await download.saveAs(path);
    const conf = await readFile(path, "utf8");
    if (!/^Endpoint = abroad\.wayfinder\.ir:\d+$/m.test(conf)) fail(`the config reaches elsewhere:\n${conf}`);
    if (!/^Address = 10\.77\.(1[2-9]\d|2[0-5]\d)\./m.test(conf)) fail(`the config's address is not in the Abroad pool:\n${conf}`);

    step("sara: the Device is marked abroad on her list");
    await page.click("text=ذخیره کردم");
    await page.locator(".devices li", { hasText: "خارج از کشور" }).waitFor();
    await page.context().close();
  }
} finally {
  await browser.close();
}
