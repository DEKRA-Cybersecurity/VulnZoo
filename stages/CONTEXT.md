# VulnZoo Development Pipeline (MWP stages — Layer 1/2)

> **This is the "factory", not the product.** These stages are the MWP development
> pipeline used to evolve the project. The **product** lives in [`../src/`](../src/)
> and is the only thing shipped. See [`../README.md`](../README.md) → "Repository
> Layout" for how each top-level folder differs.

## Purpose

Develop something for a lab (a new vulnerability, a fix, a feature) through small,
reviewable passes, and **promote** the result into `src/`. Each stage reads the
previous stage's `output/`, transforms it, and writes its own `output/`. The
**terminal stage `04_integrate` writes into `src/`** (it does not produce a
throwaway artifact) — that handoff is where outputs "adapt into the product".

## Pipeline (execution order = folder number)

| Stage | Job | Reads | Writes |
|-------|-----|-------|--------|
| **01_spec** | Research + specify the change | `../setup/questionnaire.md` answers, `../src/docs/`, `../_config/conventions.md` | `01_spec/output/<id>-spec.md` |
| **02_implement** | Write the vulnerable code/config (drafts) | `01_spec/output/` | `02_implement/output/code/` + `manifest.md` (target paths) |
| **03_document** | Write the Layer 3 product doc | `01_spec/output/`, `02_implement/output/` | `03_document/output/<VULN-ID>.md` |
| **04_integrate** | **Promote** validated artifacts into `src/` | `02_implement/output/`, `03_document/output/`, `../_config/promotion-map.md` | edits in `../src/…` + `04_integrate/output/integration-log.md` |

```
[questionnaire] → 01_spec → 02_implement → 03_document → 04_integrate ──► src/ (product)
                     │           │             │              │
                  output/     output/       output/      (no temp output — writes src/)
                     └──── human review gate at every boundary ────┘
```

## Rules

1. **One stage, one job** (MWP §3.1). A stage that implements does not also document.
2. **`output/` holds intermediate representations** (MWP §6.1), not the deliverable. The deliverable is the committed change in `src/`.
3. **Promotion is explicit** — `04_integrate` follows the mapping table in [`../_config/promotion-map.md`](../_config/promotion-map.md). Nothing reaches `src/` except through that contract.
4. **Edit the source, not the product** (MWP §6.3). If you keep hand-fixing the same thing in `src/`, push the fix back into the relevant stage `CONTEXT.md` or `../_config/`.
5. **Product conventions** live in [`../src/AGENTS.md`](../src/AGENTS.md) (Layer 0). **Factory conventions** (how to author) live in [`../_config/`](../_config/).

## References

- Methodology: [`../MWP.md`](../MWP.md) · [`../src/MWP_README.md`](../src/MWP_README.md)
- Factory config: [`../_config/`](../_config/) · Shared refs: [`../shared/`](../shared/)
- Product map / routing: [`../src/AGENTS.md`](../src/AGENTS.md)
