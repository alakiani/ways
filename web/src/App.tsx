import { lazy, Suspense, useCallback, useEffect, useState } from "react";
import { Button, Group } from "@mantine/core";
import { IconChartBar, IconHelpCircle, IconRoute, IconUserCircle, type Icon } from "@tabler/icons-react";
import { api, type Me } from "./api/client";
import { fa } from "./fa";
import { go, useRoute } from "./router";
import { InvitePage } from "./pages/Invite";
import { LoginPage } from "./pages/Login";
import { HomePage } from "./pages/Home";
import { NewDevicePage } from "./pages/NewDevice";
import { DevicePage } from "./pages/Device";
import { AccountPage } from "./pages/Account";
import { HelpPage } from "./pages/Help";
import { UsagePage } from "./pages/Usage";

// Users never load the admin panel's code.
const AdminApp = lazy(() => import("./admin/AdminApp").then((m) => ({ default: m.AdminApp })));

export function App() {
  const route = useRoute();
  if (route === "/admin" || route.startsWith("/admin/"))
    return (
      <Suspense>
        <AdminApp route={route} />
      </Suspense>
    );
  return <UserApp route={route} />;
}

function UserApp({ route }: { route: string }) {
  const [me, setMe] = useState<Me | null | undefined>(undefined); // undefined: not known yet

  const refresh = useCallback(async () => {
    const { data } = await api.GET("/v1/me");
    setMe(data ?? null);
  }, []);
  useEffect(() => {
    refresh();
  }, [refresh]);

  const signedIn = (m: Me) => {
    setMe(m);
    go("/");
  };

  let page;
  if (route.startsWith("/invite/")) {
    page = <InvitePage token={route.slice("/invite/".length)} onSignedIn={signedIn} />;
  } else if (route === "/help") {
    page = <HelpPage />;
  } else if (me === undefined) {
    page = null;
  } else if (me === null) {
    page = <LoginPage onSignedIn={signedIn} />;
  } else if (route === "/devices/new") {
    page = <NewDevicePage onDone={refresh} />;
  } else if (route === "/devices/new-abroad") {
    page = <NewDevicePage onDone={refresh} abroad />;
  } else if (route.startsWith("/devices/")) {
    page = <DevicePage id={route.slice("/devices/".length)} onChange={refresh} />;
  } else if (route === "/usage") {
    page = <UsagePage />;
  } else if (route === "/account") {
    page = <AccountPage me={me} onChange={refresh} onSignedOut={() => setMe(null)} />;
  } else {
    page = <HomePage me={me} />;
  }

  return (
    <div className="app">
      <header className="app-header">
        <a href="#/" className="brand">
          <span className="brand-mark">
            <IconRoute size={22} stroke={1.8} />
          </span>
          <span>
            <strong>{fa.appName}</strong>
            <small>{fa.tagline}</small>
          </span>
        </a>
        <Group component="nav" gap={4}>
          <NavButton href="#/help" icon={IconHelpCircle} label={fa.help} current={route === "/help"} />
          {me && <NavButton href="#/usage" icon={IconChartBar} label={fa.usage} current={route === "/usage"} />}
          {me && <NavButton href="#/account" icon={IconUserCircle} label={fa.account} current={route === "/account"} />}
        </Group>
      </header>
      <main>{page}</main>
    </div>
  );
}

function NavButton({ href, icon: I, label, current }: { href: string; icon: Icon; label: string; current: boolean }) {
  return (
    <Button component="a" href={href} variant={current ? "light" : "subtle"} color={current ? undefined : "gray"} size="sm" px="xs" leftSection={<I size={18} />} aria-label={label}>
      <span className="nav-label">{label}</span>
    </Button>
  );
}
