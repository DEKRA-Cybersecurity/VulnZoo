# Authoring Conventions (Layer 3 — factory)

> How the pipeline authors changes. Product-side navigation/conventions live in
> [`../src/AGENTS.md`](../src/AGENTS.md); this file is the factory's authoring rules.

## Language
- **All production MWP markdown is English** (Layer 0–2 files, `CONTEXT.md`, `docs/`). Translate any Spanish on touch.

## Identifiers
- **API**: `API1:2023` … `API10:2023` (OWASP API Security Top 10 2023).
- **IoT**: `IoT:I1` … `IoT:I5` (router style) or `IoT1` … `IoT4` (OWASP IoT Top 10).
- **Mobile**: `M6`, `M9` (OWASP Mobile Top 10). Custom: `IGP-01`, `BLE-07`, `AUTO-##` (automotive CAN/SOME-IP).
- Always pair with a **CWE**: `CWE-XXX (Name)`.

## Status badges
- `✅ DONE` — implemented in code and verified in the lab.
- `⏳ PENDING` — documented, not yet implemented/verified.
- `🚧 IN PROGRESS` — implementation underway; not lab-ready.

## Naming
- Device/lab folders: lowercase (`careotter/`, `routcoon/`, `owlcam/`).
- Lab package: `<device>.tar.gz`.
- Hooks: `##-descriptive-name.sh` (numeric prefix = execution order).
- Init scripts: `/etc/init.d/<name>`; UCI configs: `/etc/config/<name>`.

## Sync rule
- Keep **Layer 3 (docs) ↔ Layer 4 (code)** in sync. A code change without its doc
  update (or vice-versa) is incomplete.

## Intentional vulnerabilities
- They are intentional. **Never** harden vulnerable code unless explicitly asked
  (see [`../src/AGENTS.md`](../src/AGENTS.md)).
