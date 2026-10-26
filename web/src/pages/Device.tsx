import { useEffect, useState } from "react";
import { Alert, Anchor, Button, Group, Paper, Stack, Table, Text, Title } from "@mantine/core";
import { IconArrowRight, IconRefresh, IconTrash, IconWorld } from "@tabler/icons-react";
import { api, type DeviceInfo, type DeviceUsage, type IssuedDevice, type UsageRow } from "../api/client";
import { generateKeyPair } from "../lib/keys";
import { fa } from "../fa";
import { go } from "../router";
import { Configs } from "./Configs";
import { StateBadge } from "./Home";

export function DevicePage({ id, onChange }: { id: string; onChange: () => void }) {
  const [device, setDevice] = useState<DeviceInfo | null>(null);
  const [issued, setIssued] = useState<{ device: IssuedDevice; privateKey: string } | null>(null);
  const [usage, setUsage] = useState<DeviceUsage | null>(null);
  const [error, setError] = useState("");
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
    // A replacement is of the same kind (ADR 0014).
    const { data, response } = await api.POST("/v1/me/devices/{id}/replace", {
      params: { path: { id } },
      body: { name: device.name, public_key: keys.publicKey, abroad: device.abroad },
    });
    if (data) setIssued({ device: data, privateKey: keys.privateKey });
    else setError(response.status === 403 ? fa.abroadNotAllowed : fa.error);
  };

  return (
    <Stack gap="lg">
      <Anchor href="#/" fz="sm">
        <Group gap={4}>
          <IconArrowRight size={14} />
          {fa.back}
        </Group>
      </Anchor>
      <Group gap="sm">
        <Title order={1} size="h2">
          {fa.device}: {device.name}
        </Title>
        <StateBadge device={device} />
      </Group>
      {device.abroad && !device.revoked && (
        <Alert color={device.reason === "abroad not allowed" ? "red" : "blue"} variant="light" icon={<IconWorld />}>
          {device.reason === "abroad not allowed" ? fa.abroadBlocked : fa.abroadNotice}
        </Alert>
      )}
      <div className="pair">
        <Paper p="md">
          <Text fz="xs" c="dimmed">
            {fa.address}
          </Text>
          <Text fw={600} dir="ltr" ta="right" className="secret">
            {device.address}
          </Text>
        </Paper>
        <Paper p="md">
          <Text fz="xs" c="dimmed">
            {fa.created}
          </Text>
          <Text fw={600}>{new Date(device.created_at).toLocaleDateString("fa-IR")}</Text>
        </Paper>
      </div>
      <Title order={2} size="h3">
        {fa.usage}
      </Title>
      {usage && <Usage usage={usage} />}
      <Text c="dimmed" fz="sm">
        {fa.stuckHint}
      </Text>
      {!device.revoked && (
        <Paper p="lg">
          <Stack gap="sm">
            <Text fz="sm">{fa.replaceHint}</Text>
            {error && (
              <Alert color="red" variant="light">
                {error}
              </Alert>
            )}
            <Group>
              <Button variant="light" leftSection={<IconRefresh size={18} />} onClick={replace}>
                {fa.replace}
              </Button>
              <Button color="red" variant="light" leftSection={<IconTrash size={18} />} onClick={revoke}>
                {fa.revoke}
              </Button>
            </Group>
          </Stack>
        </Paper>
      )}
    </Stack>
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
    <Paper>
      <Table.ScrollContainer minWidth={22 * 16} type="native">
        <Table striped>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{fa.period}</Table.Th>
              {withExit && <Table.Th>{fa.exit}</Table.Th>}
              <Table.Th>{fa.up}</Table.Th>
              <Table.Th>{fa.down}</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rows.map((r) => (
              <Table.Tr key={r.period + (r.exit ?? "")}>
                <Table.Td>{label(r.period)}</Table.Td>
                {withExit && <Table.Td dir="ltr">{r.exit}</Table.Td>}
                <Table.Td>{bytes(r.up)}</Table.Td>
                <Table.Td>{bytes(r.down)}</Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
    </Paper>
  );
}

function Usage({ usage }: { usage: DeviceUsage }) {
  if (usage.daily.length === 0) return <Text c="dimmed">{fa.noUsage}</Text>;
  const day = (p: string) => new Date(p + "T00:00:00Z").toLocaleDateString("fa-IR");
  const hour = (p: string) => new Date(p).toLocaleString("fa-IR", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
  return (
    <Stack data-testid="usage">
      <Title order={3} size="h5">
        {fa.thisPeriod}
      </Title>
      <Rows rows={[usage.period]} withExit={false} label={(p) => fa.since + " " + day(p)} />
      <Title order={3} size="h5">
        {fa.daily}
      </Title>
      <Rows rows={[...usage.daily].reverse().slice(0, 30)} withExit label={day} />
      <Title order={3} size="h5">
        {fa.hourly}
      </Title>
      <Rows rows={[...usage.hourly].reverse().slice(0, 24)} withExit label={hour} />
    </Stack>
  );
}
