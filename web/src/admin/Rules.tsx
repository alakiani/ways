import { useEffect, useState } from "react";
import { Badge, Button, Group, NativeSelect, Paper, Stack, Text, TextInput, Title } from "@mantine/core";
import { IconLock } from "@tabler/icons-react";
import { api } from "../api/client";
import type { RuleInfo } from "./api";
import { Screen, Status } from "./ui";

// Rules: all shown; only the IR Rule's Tags and fallback change; the
// default Rule (ADR 0004) and the Abroad Rule (ADR 0014) are locked.
export function RulesScreen() {
  const [rules, setRules] = useState<RuleInfo[]>([]);
  useEffect(() => {
    api.GET("/v1/admin/rules").then(({ data }) => setRules(data ?? []));
  }, []);
  return (
    <Screen title="Rules" about="Which Exit a Destination Set's traffic leaves through.">
      {rules.map((r) => (r.builtin ? <Locked key={r.id} rule={r} /> : <Editable key={r.id} rule={r} onSaved={setRules} />))}
    </Screen>
  );
}

function Locked({ rule }: { rule: RuleInfo }) {
  return (
    <Paper p="lg" data-testid={`rule-${rule.name}`}>
      <Stack gap="xs">
        <Group gap="xs">
          <Title order={2} size="h4">
            {rule.name}
          </Title>
          <Badge variant="light" color="gray" leftSection={<IconLock size={12} />}>
            locked
          </Badge>
        </Group>
        <Text fz="sm">
          {rule.source ? `Abroad Devices (${rule.source}), whatever the destination, ahead of every Rule` : rule.set} → an Exit with{" "}
          {rule.required_tags.join(", ")}; otherwise {rule.fallback}.
        </Text>
      </Stack>
    </Paper>
  );
}

function Editable({ rule, onSaved }: { rule: RuleInfo; onSaved: (r: RuleInfo[]) => void }) {
  const [tags, setTags] = useState(rule.required_tags.join(", "));
  const [fallback, setFallback] = useState(rule.fallback);
  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    const required_tags = tags.split(/[\s,]+/).filter(Boolean);
    const { data } = await api.POST("/v1/admin/rules/{id}", { params: { path: { id: String(rule.id) } }, body: { required_tags, fallback } });
    if (data) onSaved(data);
  };
  return (
    <Paper component="form" p="lg" onSubmit={save} data-testid={`rule-${rule.name}`}>
      <Stack gap="sm">
        <Title order={2} size="h4">
          {rule.name}
        </Title>
        <Text fz="sm" component="div">
          {rule.set} → an Exit with these Tags; otherwise <Status>{rule.fallback}</Status>
        </Text>
        <Group align="flex-end">
          <TextInput label="Required Tags" description={'"!X" negates'} name="tags" value={tags} onChange={(e) => setTags(e.target.value)} />
          <NativeSelect
            label="Fallback"
            name="fallback"
            value={fallback}
            onChange={(e) => setFallback(e.target.value as RuleInfo["fallback"])}
            data={[
              { value: "next", label: "next Rule" },
              { value: "drop", label: "drop" },
            ]}
          />
          <Button type="submit">Save</Button>
        </Group>
      </Stack>
    </Paper>
  );
}
