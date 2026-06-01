# Stage 03 — Document (Layer 2)

> **Parent:** [`../CONTEXT.md`](../CONTEXT.md) (pipeline). Third pass: write the
> Layer 3 product documentation for the change, in **English**.

## Inputs

| Layer | Source | Use |
|-------|--------|-----|
| Layer 4 | `../01_spec/output/<id>-spec.md` | Why-it-matters, IDs, root cause |
| Layer 4 | `../02_implement/output/` | Actual code + paths for "Steps to Reproduce" and "Affected components" |
| Layer 3 | `../../_config/vuln-doc-template.md` | The required doc structure + YAML frontmatter |

## Process

1. Fill `../../_config/vuln-doc-template.md` from the spec + implementation.
2. Use English prose and the English status badges (`✅ DONE` / `⏳ PENDING` / `🚧 IN PROGRESS`).
3. Keep `affected_components` pointing at the real `src/` paths.

## Outputs

| Artifact | Path |
|----------|------|
| Vulnerability doc | `output/<VULN-ID>.md` (e.g. `output/API7_SSRF.md`) |

**Handoff:** `04_integrate` promotes this into `src/docs/<Device>/Vulns/<Category>/`.
