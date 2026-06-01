# Stage 01 — Spec (Layer 2)

> **Parent:** [`../CONTEXT.md`](../CONTEXT.md) (pipeline) → **this stage**.
> First pass: research and specify *what* to build, before any code is written.

## Inputs

| Layer | Source | Use |
|-------|--------|-----|
| setup | `../../setup/questionnaire.md` (answers) | Which device/lab, vuln-or-feature, OWASP category, scope |
| Layer 3 | `../../src/docs/<Device>/` | Existing vulns/architecture for that device (avoid duplication) |
| Layer 3 | `../../_config/conventions.md` | OWASP ID scheme, severity, status badges |
| Layer 3 | `../../shared/glossary.md` | Device → doc-folder map, ports, terms |

## Process

1. Identify the target device and the change (new vuln, fix, or feature).
2. Assign the OWASP/custom ID and CWE(s) using `../../_config/conventions.md`.
3. Write a spec: *why it matters*, the intended root cause, affected components
   (concrete `src/` paths), and the acceptance/repro criteria.

## Outputs

| Artifact | Path |
|----------|------|
| Specification | `output/<id>-spec.md` (e.g. `output/API7-ssrf-spec.md`) |

**Handoff:** `02_implement` reads `output/<id>-spec.md`.
