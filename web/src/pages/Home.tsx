import { useEffect, useState } from "react";
import { Alert, Badge, Button, Group, Paper, Text, ThemeIcon, Title } from "@mantine/core";
import { IconChevronLeft, IconDeviceMobile, IconInfoCircle, IconPlus, IconWorld } from "@tabler/icons-react";
import { api, type DeviceInfo, type Me, type MyUsage } from "../api/client";
import { fa } from "../fa";
import { QuotaCard } from "./Quota";

export function stateLabel(d: DeviceInfo): string {
  if (d.revoked) return fa.revoked;
  return d.state === "active" ? fa.active : fa.blocked;
}

export function StateBadge({ device: d }: { device: DeviceInfo }) {
  const color = d.revoked ? "gray" : d.state === "active" ? "green" : "red";
  return (
    <Badge color={color} variant="light" size="sm">
      {stateLabel(d)}
    </Badge>
  );
}

export function HomePage({ me }: { me: Me }) {
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [usage, setUsage] = useState<MyUsage | null>(null);
  useEffect(() => {
    api.GET("/v1/me/devices").then(({ data }) => setDevices(data ?? []));
    api.GET("/v1/me/usage").then(({ data }) => setUsage(data ?? null));
  }, []);
  const live = devices.filter((d) => !d.revoked);
  const full = me.device_count >= me.device_cap;

  return (
    <section>
      {usage && <QuotaCard usage={usage} onChange={setUsage} />}
      <Group justify="space-between" mt="xl" mb="md">
        <Title order={1} size="h3">
          {fa.devices}{" "}
          <Text span c="dimmed" fz="sm" fw={400}>
            {fa.deviceCount(me.device_count, me.device_cap)}
          </Text>
        </Title>
        {!full && (
          <Group gap="xs">
            {me.abroad && (
              <Button component="a" href="#/devices/new-abroad" variant="light" leftSection={<IconWorld size={18} />}>
                {fa.newAbroadDevice}
              </Button>
            )}
            <Button component="a" href="#/devices/new" leftSection={<IconPlus size={18} />}>
              {fa.newDevice}
            </Button>
          </Group>
        )}
      </Group>
      {full && (
        <Alert color="yellow" variant="light" icon={<IconInfoCircle />} mb="md">
          {fa.capReached}
        </Alert>
      )}
      {live.length === 0 && (
        <Paper p="xl" ta="center" c="dimmed">
          {fa.noDevices}
        </Paper>
      )}
      <ul className="devices">
        {live.map((d) => (
          <li key={d.id}>
            <Paper component="a" href={`#/devices/${d.id}`} className="device-row">
              <ThemeIcon variant="light" size="lg" radius="md" aria-label={d.abroad ? fa.abroad : undefined}>
                {d.abroad ? <IconWorld size={20} /> : <IconDeviceMobile size={20} />}
              </ThemeIcon>
              <div className="grow">
                <Text fw={600} truncate>
                  {d.name}
                </Text>
                {(d.abroad || d.recent_bytes > 0) && (
                  <Text fz="xs" c="dimmed">
                    {[d.abroad && fa.abroad, d.recent_bytes > 0 && fa.usedRecently].filter(Boolean).join(" · ")}
                  </Text>
                )}
              </div>
              <StateBadge device={d} />
              <IconChevronLeft size={18} color="var(--mantine-color-dimmed)" />
            </Paper>
          </li>
        ))}
      </ul>
    </section>
  );
}
