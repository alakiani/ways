import { useEffect, useState } from "react";
import { Alert, Badge, Code, Group, Paper, Stack, Table, Text, Title } from "@mantine/core";
import { IconAlertTriangle, IconDatabaseExport, IconRss } from "@tabler/icons-react";
import { api } from "../api/client";
import { ago, bytes, type AddressStatus, type Overview } from "./api";
import { ListTable, Screen } from "./ui";

// The status board (variant A in the prototype): Node tiles, a Link
// latency matrix, and the Coordinator card.
export function OverviewScreen() {
  const [o, setO] = useState<Overview | null>(null);
  const load = () => api.GET("/v1/admin/overview").then(({ data }) => setO(data ?? null));
  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);
  if (!o) return null;
  const names = o.nodes.map((n) => n.name);
  const link = (a: string, b: string) => o.links.find((l) => (l.a === a && l.b === b) || (l.a === b && l.b === a));

  return (
    <Screen title="Overview" about="Refreshes every 5 seconds.">
      {o.undelivered_alerts.length > 0 && (
        // Alerts no Exit could relay to Telegram (ADR 0006): seen here even
        // during an international outage.
        <Alert
          color="red"
          icon={<IconAlertTriangle />}
          data-testid="undelivered-alerts"
          title={`${o.undelivered_alerts.length} alert${o.undelivered_alerts.length > 1 ? "s" : ""} could not reach Telegram`}
        >
          <Stack gap="sm">
            {o.undelivered_alerts.map((a) => (
              <div key={a.id}>
                <Code block>{a.text}</Code>
                <Text fz="xs" c="dimmed" mt={4}>
                  received {ago(a.received_at)}, {a.attempts} attempt{a.attempts > 1 && "s"}: {a.last_error}
                </Text>
              </div>
            ))}
          </Stack>
        </Alert>
      )}

      <div className="tiles">
        {o.nodes.map((n) => {
          const behind = n.applied_version !== n.latest_version;
          return (
            <Paper key={n.id} component="a" className="tile" href={`#/admin/nodes/${n.id}`} data-testid={`node-${n.name}`}>
              <Group justify="space-between" wrap="nowrap">
                <Text fw={700}>{n.name}</Text>
                <Group gap={4} wrap="nowrap">
                  {n.roles.map((r) => (
                    <Badge key={r} size="xs" variant="light" color={r === "bridge" ? "violet" : "cyan"}>
                      {r}
                    </Badge>
                  ))}
                </Group>
              </Group>
              <Text fz="xs" c="dimmed">
                {n.tags.length ? n.tags.join(", ") : "no tags"}
              </Text>
              <Text fz="sm" c={n.last_contact ? undefined : "red"}>
                contact {ago(n.last_contact)}
              </Text>
              <Text fz="sm" c={behind ? "orange" : undefined}>
                snapshot {n.applied_version}/{n.latest_version}
                {behind && " (behind)"}
              </Text>
              {n.agent_version && (
                <Text fz="xs" c="dimmed">
                  agent {n.agent_version}
                </Text>
              )}
              {n.addr && n.seen_addr && n.addr !== n.seen_addr && (
                <Text fz="xs" c="red">
                  says {n.addr}, seen as {n.seen_addr}
                </Text>
              )}
            </Paper>
          );
        })}
      </div>

      <Title order={2} size="h4">
        Link latency
      </Title>
      <ListTable className="matrix" data-testid="link-matrix" minWidth={names.length * 96 + 96} highlightOnHover={false} withColumnBorders>
        <Table.Thead>
          <Table.Tr>
            <Table.Th />
            {names.map((n) => (
              <Table.Th key={n}>{n}</Table.Th>
            ))}
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {names.map((a) => (
            <Table.Tr key={a}>
              <Table.Th>{a}</Table.Th>
              {names.map((b) => {
                const l = a === b ? undefined : link(a, b);
                if (!l) return <Table.Td key={b} />;
                const up = l.up_a || l.up_b;
                return (
                  <Table.Td key={b} className={up ? "up" : "down"} title={l.transport}>
                    {up ? `${l.rtt_ms.toFixed(0)} ms` : "down"}
                  </Table.Td>
                );
              })}
            </Table.Tr>
          ))}
        </Table.Tbody>
      </ListTable>

      <AddressSection title="Bridge Address" status={o.bridge_address} testid="bridge-address" probed />
      {/* Abroad Devices connect here (ADR 0014); there is no probe from abroad. */}
      <AddressSection title="Abroad Bridge Address" status={o.abroad_address} testid="abroad-address" />

      <Title order={2} size="h4">
        Coordinator
      </Title>
      <Paper p="md">
        <Stack gap="xs">
          {o.sets
            .filter((s) => s.feed)
            .map((s) => (
              <Group key={s.id} gap="xs" fz="sm" wrap="nowrap" align="flex-start">
                <IconRss size={16} />
                <span>
                  {s.name} feed: {s.prefixes} prefixes, updated {ago(s.updated_at)}
                  {s.last_error && <Text span c="red"> — last update rejected: {s.last_error}</Text>}
                </span>
              </Group>
            ))}
          <Group gap="xs" fz="sm" wrap="nowrap" align="flex-start">
            <IconDatabaseExport size={16} />
            <span data-testid="backup">
              Nightly backup:{" "}
              {!o.backup.configured ? (
                <Text span c="red">
                  off: no age recipient configured
                </Text>
              ) : (
                <>
                  last good {ago(o.backup.last_success)}
                  {o.backup.last_success && `, ${bytes(o.backup.size_bytes)}`}
                  {o.backup.last_error && <Text span c="red"> — last attempt failed: {o.backup.last_error}</Text>}
                </>
              )}
            </span>
          </Group>
        </Stack>
      </Paper>
    </Screen>
  );
}

// One Bridge Address: the Bridges its record holds and how each is judged.
function AddressSection({ title, status: ba, testid, probed = false }: { title: string; status: AddressStatus; testid: string; probed?: boolean }) {
  return (
    <>
      <Group gap="xs">
        <Title order={2} size="h4">
          {title}
        </Title>
        <Code dir="ltr">{ba.host}</Code>
      </Group>
      {ba.bridges.length === 0 ? (
        <Text fz="sm" c="dimmed" data-testid={testid}>
          No Bridges for it yet.
        </Text>
      ) : (
        <>
          {!ba.published && (
            <Alert color="orange" variant="light">
              The record has not been updated since the Coordinator started.
            </Alert>
          )}
          <ListTable data-testid={testid}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Bridge</Table.Th>
                <Table.Th>Address</Table.Th>
                <Table.Th>Record</Table.Th>
                <Table.Th>Eligible</Table.Th>
                {probed && <Table.Th>Probe</Table.Th>}
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {ba.bridges.map((b) => (
                <Table.Tr key={b.name}>
                  <Table.Th>{b.name}</Table.Th>
                  <Table.Td>{b.addr ?? "no address yet"}</Table.Td>
                  <Table.Td>
                    <Badge variant="light" color={b.unlisted ? "orange" : b.in_record ? "green" : "gray"} tt="none">
                      {b.unlisted
                        ? b.in_record
                          ? "unlisted, still in the record"
                          : "unlisted by an Admin"
                        : b.in_record
                          ? `in the record since ${ago(b.joined)}`
                          : "out of the record"}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    <Badge variant="light" color={b.eligible ? "green" : "red"} tt="none">
                      {b.eligible ? "eligible" : (b.reasons ?? [probed ? "not probed yet" : "not judged yet"]).join(", ")}
                    </Badge>
                  </Table.Td>
                  {probed && (
                    <Table.Td>
                      probe {b.probe ? (b.probe.ok ? "passing" : "failing") : "pending"} {b.probe && ago(b.probe.at)}
                    </Table.Td>
                  )}
                </Table.Tr>
              ))}
            </Table.Tbody>
          </ListTable>
          <Text fz="sm" c="dimmed">
            Since the Coordinator started: {ba.joins} joined, {ba.removals} removed.
          </Text>
        </>
      )}
    </>
  );
}
