import { fa } from "../fa";

// The per-platform help page from the panel prototype (issue #14): install
// WireGuard, import the config, and toggle the tunnel when stuck (ADR 0011).
const platforms = [
  {
    name: "اندروید",
    steps: [
      "برنامهٔ WireGuard را از Google Play یا F-Droid نصب کنید. اگر در دسترس نبود، فایل نصبی را از کسی که به او اعتماد دارید بگیرید.",
      "در برنامه دکمهٔ + را بزنید و «اسکن از کد QR» را انتخاب کنید، یا «وارد کردن از فایل» و فایل ways.conf را بدهید.",
    ],
  },
  {
    name: "آیفون و آیپد",
    steps: [
      "برنامهٔ WireGuard را از App Store نصب کنید.",
      "«Add a tunnel» و سپس «Create from QR code» را بزنید و کد پیکربندی را اسکن کنید.",
      "اجازهٔ افزودن پیکربندی VPN را بدهید.",
    ],
  },
  {
    name: "ویندوز",
    steps: [
      "برنامهٔ WireGuard را از wireguard.com نصب کنید.",
      "«Import tunnel(s) from file» را بزنید و فایل ways.conf را انتخاب کنید.",
    ],
  },
  {
    name: "مک",
    steps: [
      "برنامهٔ WireGuard را از Mac App Store نصب کنید.",
      "«Import Tunnel(s) from File» را بزنید و فایل ways.conf را انتخاب کنید.",
    ],
  },
];

export function HelpPage() {
  return (
    <section className="help">
      <h1>{fa.help}</h1>
      {platforms.map((p) => (
        <article key={p.name}>
          <h2>{p.name}</h2>
          <ol>
            {p.steps.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ol>
        </article>
      ))}
      <article>
        <h2>اگر وصل است ولی چیزی باز نمی‌شود</h2>
        <p>{fa.stuckHint}</p>
      </article>
      <article>
        <h2>اگر پیکربندی گم شد</h2>
        <p>
          پیکربندی را نمی‌توان دوباره دریافت کرد، چون کلید خصوصی فقط روی دستگاه شماست. در صفحهٔ دستگاه، «جایگزینی» را
          بزنید تا پیکربندی تازه بسازید.
        </p>
      </article>
    </section>
  );
}
