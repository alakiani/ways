import { useState } from "react";
import { Alert, Button, Paper, Stack, TextInput, Title } from "@mantine/core";
import { IconWorld } from "@tabler/icons-react";
import { api, errorOf, type IssuedDevice } from "../api/client";
import { generateKeyPair } from "../lib/keys";
import { fa } from "../fa";
import { go } from "../router";
import { Configs } from "./Configs";

// An Abroad Device (ADR 0014) is made here too, with its notice shown
// where the choice is made.
export function NewDevicePage({ onDone, abroad = false }: { onDone: () => void; abroad?: boolean }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [issued, setIssued] = useState<{ device: IssuedDevice; privateKey: string } | null>(null);

  if (issued) {
    return (
      <Configs
        issued={issued.device}
        privateKey={issued.privateKey}
        onSaved={() => {
          setIssued(null); // drop the private key
          onDone();
          go("/");
        }}
      />
    );
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    const keys = generateKeyPair();
    const { data, error, response } = await api.POST("/v1/me/devices", { body: { name, public_key: keys.publicKey, abroad } });
    setBusy(false);
    if (data) return setIssued({ device: data, privateKey: keys.privateKey });
    if (response.status === 409) return setError(fa.capReached);
    setError(response.status === 403 ? fa.abroadNotAllowed : (errorOf(error) ?? fa.error));
  };

  return (
    <Paper component="form" p="xl" onSubmit={submit}>
      <Stack>
        <Title order={1} size="h2">
          {abroad ? fa.newAbroadDevice : fa.newDevice}
        </Title>
        {abroad && (
          <Alert color="blue" variant="light" icon={<IconWorld />} data-testid="abroad-notice">
            {fa.abroadNotice}
          </Alert>
        )}
        <TextInput label={fa.deviceName} name="name" required maxLength={64} autoFocus value={name} onChange={(e) => setName(e.target.value)} />
        {error && (
          <Alert color="red" variant="light">
            {error}
          </Alert>
        )}
        <Button type="submit" size="md" loading={busy}>
          {busy ? fa.creating : fa.create}
        </Button>
      </Stack>
    </Paper>
  );
}
