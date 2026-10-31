import { useEffect, useState } from "react";
import { Badge, Button, Checkbox, Group, NativeSelect, Paper, Stack, Table, TextInput, Title } from "@mantine/core";
import { IconPlus } from "@tabler/icons-react";
import { api } from "../api/client";
import type { InviteRecord } from "./api";
import { parseGB, presetsText, rateOf } from "./quota";
import { ListTable, Screen, Shown, Status } from "./ui";

// Invites: create with a cap, list, withdraw (issue #14). A new User's
// Invite may preset their Quota, running-out setting and Refills (ADR 0010),
// and the abroad permission (ADR 0014).
export function InvitesScreen() {
  const [list, setList] = useState<InviteRecord[]>([]);
  const [cap, setCap] = useState(3);
  const [admin, setAdmin] = useState(false);
  const [abroad, setAbroad] = useState(false);
  const [quota, setQuota] = useState(""); // GB; empty is unlimited
  const [runningOut, setRunningOut] = useState("block");
  const [mbit, setMbit] = useState(1);
  const [refills, setRefills] = useState(0);
  const [refillDays, setRefillDays] = useState(30);
  const [url, setUrl] = useState("");
  const load = () => api.GET("/v1/admin/invites").then(({ data }) => setList(data ?? []));
  useEffect(() => {
    load();
  }, []);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    const body = {
      device_cap: cap,
      admin,
      quota: parseGB(quota) ?? undefined, // absent is unlimited
      running_out: runningOut,
      rate: runningOut === "slow" ? rateOf(mbit) : undefined,
      refills,
      refill_days: refillDays,
      abroad,
    };
    const { data } = await api.POST("/v1/admin/invites", { body });
    if (data) setUrl(data.url);
    load();
  };

  return (
    <Screen title="Invites" about="A new User joins only through an Invite.">
      <Paper component="form" p="lg" onSubmit={create}>
        <Stack>
          <Title order={2} size="h5">
            New Invite
          </Title>
          <Group align="flex-end">
            <TextInput w={110} label="Device cap" name="cap" type="number" min={1} max={100} value={cap} onChange={(e) => setCap(Number(e.target.value))} />
            <TextInput
              w={130}
              label="Quota (GB)"
              name="quota"
              type="number"
              min={0}
              step={0.1}
              placeholder="Unlimited"
              value={quota}
              onChange={(e) => setQuota(e.target.value)}
            />
            <NativeSelect
              w={130}
              label="Running out"
              name="running_out"
              value={runningOut}
              onChange={(e) => setRunningOut(e.target.value)}
              data={[
                { value: "block", label: "Block" },
                { value: "slow", label: "Slow" },
              ]}
            />
            {runningOut === "slow" && (
              <TextInput w={100} label="Mbit/s" name="mbits" type="number" min={0.1} step={0.1} value={mbit} onChange={(e) => setMbit(Number(e.target.value))} />
            )}
            <TextInput w={100} label="Refills" name="refills" type="number" min={0} max={100} value={refills} onChange={(e) => setRefills(Number(e.target.value))} />
            <TextInput
              w={150}
              label="Refill expiry (days)"
              name="refill_days"
              type="number"
              min={1}
              max={3650}
              value={refillDays}
              onChange={(e) => setRefillDays(Number(e.target.value))}
            />
            <Checkbox name="admin" label="Admin" mb={8} checked={admin} onChange={(e) => setAdmin(e.target.checked)} />
            <Checkbox
              name="abroad"
              label="Abroad"
              title="May hold Abroad Devices, whose traffic all leaves through a domestic Exit"
              mb={8}
              checked={abroad}
              onChange={(e) => setAbroad(e.target.checked)}
            />
          </Group>
          <Group>
            <Button type="submit" leftSection={<IconPlus size={16} />}>
              Create Invite
            </Button>
          </Group>
        </Stack>
      </Paper>
      {url && <Shown label="Single-use, valid 7 days. Send it out of band:" value={url} testid="invite-url" />}
      <ListTable>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Created</Table.Th>
            <Table.Th>Kind</Table.Th>
            <Table.Th>For</Table.Th>
            <Table.Th>Presets</Table.Th>
            <Table.Th>Status</Table.Th>
            <Table.Th />
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {list.map((i) => (
            <Table.Tr key={i.id} data-testid={`invite-${i.status}`}>
              <Table.Td className="nowrap">{new Date(i.created_at).toLocaleString()}</Table.Td>
              <Table.Td>
                <Group gap={4} wrap="nowrap">
                  {i.kind}
                  {i.admin && (
                    <Badge size="xs" color="violet" variant="light">
                      Admin
                    </Badge>
                  )}
                  {i.device_cap ? `, cap ${i.device_cap}` : ""}
                </Group>
              </Table.Td>
              <Table.Td>{i.handle}</Table.Td>
              <Table.Td className="presets">{presetsText(i)}</Table.Td>
              <Table.Td>
                <Status>{i.status}</Status>
              </Table.Td>
              <Table.Td>
                {i.status === "open" && (
                  <Button
                    size="compact-xs"
                    variant="subtle"
                    color="red"
                    onClick={async () => {
                      await api.POST("/v1/admin/invites/{id}/withdraw", { params: { path: { id: i.id } } });
                      load();
                    }}
                  >
                    Withdraw
                  </Button>
                )}
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </ListTable>
    </Screen>
  );
}
