# WAYS

## Agent skills

### Issue tracker

Issues and specs are tracked in GitHub Issues via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.

## WAYMATE

`waymate/` is a separate product: messaging and calls for WAYS Users, on its own VM. Keep every change on one side. A WAYMATE change touches only `waymate/` and `.github/workflows/waymate-*.yml`, is tested by `waymate/test/deploy-test.sh`, and is released with a `waymate-v*` tag. See `waymate/README.md`.
