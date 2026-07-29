# Stage 05 - Verify / Repro (Layer 2)

> **Parent:** [`../CONTEXT.md`](../CONTEXT.md) (pipeline). **Terminal pass.** Fifth pass: run the spec's acceptance criteria against the promoted lab and certify the result. This stage **certifies**, it does not promote (that is `04_integrate`'s job) and it does not fix (a failing criterion routes back to the owning stage).

## Inputs

| Layer | Source | Use |
|-------|--------|-----|
| Layer 4 | `../01_spec/output/<id>-spec.md` | The acceptance / repro criteria to check, closing the loop the spec opened |
| Layer 4 | the promoted change under `../../src/…` + `../04_integrate/output/integration-log.md` | What landed and where, the artifact under test |
| Layer 3 | `../../src/labs/<device>/CONTEXT.md` | How to build / flash / load the lab (its `## Build` and `## Verification` sections) |
| Layer 3 | `../../src/docs/<Device>/…/Vulnerabilities.md` (+ the `Vulns/README.md` index) | The status badge this stage advances |
| Layer 3 | `../../_config/conventions.md` | Badge semantics: `PENDING` / `IN PROGRESS` / `DONE` |

## Process

1. Bring the lab up per `../../src/labs/<device>/CONTEXT.md`. Rebuild the `<device>.tar.gz` if the overlay changed, then flash or load it.
2. Execute each acceptance criterion from the spec and each item in the lab's `## Verification` checklist. For code artifacts (`cloud_api/` Flask backends, the Android apps, `rshell.c`) run the functional / unit checks instead of an attack chain, and consult [`../../SKILL.md`](../../SKILL.md) for the testing skill when the target is an Android app.
3. Record every criterion as pass or fail in `output/<id>-verification.md`, with the command run and the observed output as evidence. A criterion that cannot be run (no hardware, no flashed device) is recorded as **blocked** with the blocker named, never silently passed.
4. Advance the Layer 3 badge from `IN PROGRESS` to `DONE` **only** for criteria backed by a passing repro. Leave anything unverified at `IN PROGRESS` or `PENDING`. This badge write is the only edit this stage makes into `src/`.
5. On failure, do not patch the product here. Route the fix back to the owning stage (`01_spec`, `02_implement`, or `03_document`) per the parent rule "edit the source, not the product" (MWP §6.3), then re-run this stage.

Keep it MWP-light. A human runs the repro and saves the evidence, no test framework or fixtures are required. The rule is one runnable check per non-trivial artifact, not a full suite.

## Outputs

| Artifact | Path |
|----------|------|
| Verification log (evidence per criterion) | `output/<id>-verification.md` |
| Badge transition (`IN PROGRESS` -> `DONE`) | evidence-backed edits in `../../src/docs/<Device>/…` |

**Done when:** every acceptance criterion has recorded pass / fail / blocked evidence, every `DONE` badge is backed by a passing repro, and any failure has been routed back to its owning stage.
