# Stage 02 — Implement (Layer 2)

> **Parent:** [`../CONTEXT.md`](../CONTEXT.md) (pipeline). Second pass: write the
> vulnerable code/config as **drafts** under `output/` — do **not** touch `src/`
> here (that is `04_integrate`'s job).

## Inputs

| Layer | Source | Use |
|-------|--------|-----|
| Layer 4 | `../01_spec/output/<id>-spec.md` | What to build, where, acceptance criteria |
| Layer 3 | `../../_config/conventions.md` | Naming (`##-name.sh` hooks, `<device>.tar.gz`, lowercase) |
| Layer 0 | `../../src/AGENTS.md` | Product rules — **keep intentional vulns intentional** |
| Skills | `../../SKILL.md` | Android dev/testing skills index — consult when the change is an Android app |

## Process

1. Implement the change as draft files under `output/code/`, mirroring the eventual
   `src/` layout (e.g. `output/code/cloud_api/<device>/api_server/app.py`).
   - **Android targets:** if the implementation or development is for an Android app
     (e.g. under `vulnzoo_apps/`), first check [`../../SKILL.md`](../../SKILL.md) for a
     usable skill (Compose/UI, build/tooling, migrations, testing) and invoke it via the
     `Skill` tool instead of writing the work by hand.
2. Write `output/manifest.md`: a table mapping each draft file → its destination
   `src/` path (this feeds `04_integrate` and `../../_config/promotion-map.md`).
3. Note any repackaging needed (e.g. rebuild `<device>.tar.gz`).

## Outputs

| Artifact | Path |
|----------|------|
| Code drafts | `output/code/…` (mirrors `src/` layout) |
| Target-path manifest | `output/manifest.md` |

**Handoff:** `03_document` (for the doc) and `04_integrate` (for promotion) read this `output/`.
