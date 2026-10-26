import { useEffect, useState } from "react";
import { Badge, Button, Checkbox, Group, NativeSelect, Table, Text, TextInput } from "@mantine/core";
import { api, type Me } from "../api/client";
import { typedConfirm, type UserInfo } from "./api";
import { byQuotaShare, gbField, mbits, parseGB, periodText, rateOf, renews } from "./quota";
import { ListTable, Screen, Shown, Status } from "./ui";

// Users: Suspend/Resume, Device cap, recovery Invite, Delete with typed
// confirmation. Admins see totals per User, not Devices (issue #14). Each
// User's Quota and running-out setting are edited inline, and the remedies
// are actions (ADR 0010); the most used share of Quota comes first. The
// abroad permission lets a User hold Abroad Devices (ADR 0014).
export function UsersScreen({ self }: { self: Me }) {
  const [users, setUsers] = useState<UserInfo[]>([]);
  const [link, setLink] = useState("");
  const load = () => api.GET("/v1/admin/users").then(({ data }) => setUsers((data ?? []).sort(byQuotaShare)));
  useEffect(() => {
    load();
  }, []);
  const p = (id: string) => ({ params: { path: { id } } });
  // Saves a User's Quota and running-out setting with one of them changed.
  // Slow without a rate yet starts at 1 Mbit/s.
  const setQuota = async (u: UserInfo, change: { quota?: number | null; running_out?: string; rate?: number }) => {
    const quota = "quota" in change ? change.quota : u.quota;
    const running_out = change.running_out ?? u.running_out;
    const rate = running_out === "slow" ? (change.rate ?? (u.rate || rateOf(1))) : undefined;
    // An absent quota is unlimited.
    await api.POST("/v1/admin/users/{id}/quota", { ...p(u.id), body: { quota: quota ?? undefined, running_out, rate } });
    load();
  };

  return (
    <Screen title="Users" about="Most of their Quota used first. Fields save when you leave them.">
      {link && <Shown label="Recovery Invite; send it out of band:" value={link} testid="recovery-link" />}
      <ListTable minWidth={1060}>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Handle</Table.Th>
            <Table.Th>Status</Table.Th>
            <Table.Th>Devices</Table.Th>
            <Table.Th title="May hold Abroad Devices, whose traffic all leaves through a domestic Exit">Abroad</Table.Th>
            <Table.Th>This period</Table.Th>
            <Table.Th>Quota</Table.Th>
            <Table.Th>Running out</Table.Th>
            <Table.Th>Renews</Table.Th>
            <Table.Th>Refills held</Table.Th>
            <Table.Th className="actions">Actions</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {users.map((u) => (
            <Table.Tr key={u.id} data-testid={`user-${u.handle}`}>
              <Table.Td>
                <Group gap={4}>
                  <Text fw={600} fz="sm">
                    {u.handle}
                  </Text>
                  {u.admin && (
                    <Badge size="xs" color="violet" variant="light">
                      Admin
                    </Badge>
                  )}
                  {u.totp_enabled && (
                    <Badge size="xs" color="gray" variant="light">
                      TOTP
                    </Badge>
                  )}
                </Group>
              </Table.Td>
              <Table.Td>
                <Status>{u.suspended ? "Suspended" : "Active"}</Status>
              </Table.Td>
              <Table.Td className="nowrap">
                {u.device_count} of{" "}
                <TextInput
                  className="cell-input"
                  size="xs"
                  type="number"
                  min={0}
                  max={100}
                  defaultValue={u.device_cap}
                  aria-label="Device cap"
                  onBlur={async (e) => {
                    const cap = Number(e.target.value);
                    if (cap !== u.device_cap) {
                      await api.POST("/v1/admin/users/{id}/device-cap", { ...p(u.id), body: { device_cap: cap } });
                      load();
                    }
                  }}
                />
              </Table.Td>
              <Table.Td>
                <Checkbox
                  size="xs"
                  checked={u.abroad}
                  aria-label="Abroad"
                  onChange={async (e) => {
                    const abroad = e.currentTarget.checked;
                    if (!abroad && !confirm(`${u.handle}'s Abroad Devices stop connecting until you allow it again. They are kept, not revoked.`)) return;
                    await api.POST("/v1/admin/users/{id}/abroad", { ...p(u.id), body: { abroad } });
                    load();
                  }}
                />
              </Table.Td>
              <Table.Td className="period">{periodText(u)}</Table.Td>
              <Table.Td className="nowrap">
                <TextInput
                  className="cell-input"
                  size="xs"
                  type="number"
                  min={0}
                  step={0.1}
                  placeholder="∞"
                  defaultValue={gbField(u.quota)}
                  aria-label="Quota"
                  title="GB per Quota Period; empty is unlimited"
                  onBlur={async (e) => {
                    const quota = parseGB(e.target.value);
                    if (quota === undefined) e.target.value = gbField(u.quota);
                    else if (quota !== (u.quota ?? null)) await setQuota(u, { quota });
                  }}
                />{" "}
                GB
              </Table.Td>
              <Table.Td>
                <NativeSelect
                  className="cell-select"
                  size="xs"
                  defaultValue={u.running_out}
                  aria-label="Running out"
                  data={[
                    { value: "block", label: "Block" },
                    { value: "slow", label: "Slow" },
                  ]}
                  onChange={(e) => setQuota(u, { running_out: e.target.value })}
                />
                {u.running_out === "slow" && (
                  <div className="nowrap">
                    to{" "}
                    <TextInput
                      className="cell-input"
                      size="xs"
                      type="number"
                      min={0.1}
                      step={0.1}
                      defaultValue={mbits(u.rate ?? 0)}
                      aria-label="Mbit/s"
                      onBlur={async (e) => {
                        const rate = rateOf(Number(e.target.value));
                        if (!(rate > 0)) e.target.value = mbits(u.rate ?? 0);
                        else if (rate !== u.rate) await setQuota(u, { rate });
                      }}
                    />{" "}
                    Mbit/s
                  </div>
                )}
              </Table.Td>
              <Table.Td className="renews">{renews(u.renews_at)}</Table.Td>
              <Table.Td className="refills">{u.refills}</Table.Td>
              <Table.Td>
                <Group gap={4}>
                  {u.id !== self.id && (
                    <Button
                      size="compact-xs"
                      variant="light"
                      color={u.suspended ? "green" : "orange"}
                      onClick={async () => {
                        await api.POST(u.suspended ? "/v1/admin/users/{id}/resume" : "/v1/admin/users/{id}/suspend", p(u.id));
                        load();
                      }}
                    >
                      {u.suspended ? "Resume" : "Suspend"}
                    </Button>
                  )}
                  <Button
                    size="compact-xs"
                    variant="light"
                    onClick={async () => {
                      const count = Number(prompt(`How many Refills to give ${u.handle}?`, "1"));
                      if (!Number.isInteger(count) || count < 1) return;
                      const days = Number(prompt("Each Refill expires in how many days?", "30"));
                      if (!Number.isInteger(days) || days < 1) return;
                      await api.POST("/v1/admin/users/{id}/refills", { ...p(u.id), body: { count, days } });
                      load();
                    }}
                  >
                    Give Refill
                  </Button>
                  {u.quota != null && (
                    <Button
                      size="compact-xs"
                      variant="light"
                      onClick={async () => {
                        if (!confirm(`Reset ${u.handle} to a full Quota now? Their Usage stays as it is.`)) return;
                        await api.POST("/v1/admin/users/{id}/reset", p(u.id));
                        load();
                      }}
                    >
                      Reset now
                    </Button>
                  )}
                  <Button
                    size="compact-xs"
                    variant="light"
                    onClick={async () => {
                      const n = parseGB(prompt(`GB to add to ${u.handle}'s Quota, for this Quota Period only`) ?? "");
                      if (!n) return;
                      await api.POST("/v1/admin/users/{id}/top-up", { ...p(u.id), body: { bytes: n } });
                      load();
                    }}
                  >
                    Top-up
                  </Button>
                  <Button
                    size="compact-xs"
                    variant="light"
                    color="gray"
                    onClick={async () => {
                      const { data } = await api.POST("/v1/admin/users/{id}/recovery-invite", p(u.id));
                      if (data) setLink(data.url);
                    }}
                  >
                    Recovery Invite
                  </Button>
                  {u.id !== self.id && (
                    <Button
                      size="compact-xs"
                      variant="subtle"
                      color="red"
                      onClick={async () => {
                        if (!typedConfirm("delete this User, their Devices and their usage", u.handle)) return;
                        await api.DELETE("/v1/admin/users/{id}", p(u.id));
                        load();
                      }}
                    >
                      Delete
                    </Button>
                  )}
                </Group>
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </ListTable>
    </Screen>
  );
}
