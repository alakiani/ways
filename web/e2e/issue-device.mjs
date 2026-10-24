// Drives the real panel as a new User would: redeem the Invite, create a
// Device, and save its configs. internal/e2e runs this inside the lab test
// and imports the saved config on a lab phone.
//
// Env: PANEL_URL, INVITE_TOKEN, OUT_DIR.
import { chromium } from "@playwright/test";

const { PANEL_URL, INVITE_TOKEN, OUT_DIR } = process.env;
const browser = await chromium.launch();
try {
  const page = await browser.newPage({ acceptDownloads: true, locale: "fa-IR" });
  page.setDefaultTimeout(20_000);

  await page.goto(`${PANEL_URL}/#/invite/${INVITE_TOKEN}`);
  await page.fill("input[name=handle]", "maryam");
  await page.fill("input[name=password]", "a long enough password");
  await page.fill("input[name=password-again]", "a long enough password");
  await page.click("button[type=submit]");

  await page.click('a[href="#/devices/new"]');
  await page.fill("input[name=name]", "phone");
  await page.click("button[type=submit]");

  // The one config is shown once: a QR code and the file.
  await page.waitForFunction(() => document.querySelectorAll("figure img").length === 1);
  const [download] = await Promise.all([page.waitForEvent("download"), page.click("[data-testid=download-conf]")]);
  await download.saveAs(`${OUT_DIR}/ways.conf`);

  await page.click("text=ذخیره کردم");
  await page.waitForSelector(".devices li");
  const html = await page.content();
  if (!html.includes('dir="rtl"')) throw new Error("the panel is not right to left");
  console.log("issued a Device through the panel");
} finally {
  await browser.close();
}
