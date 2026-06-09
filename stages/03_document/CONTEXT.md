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
2. Use English prose and the plain-text status badges — `DONE`, `PENDING`, or `IN PROGRESS` — with no emoji.
3. Keep `affected_components` pointing at the real `src/` paths.
4. **One paragraph = one physical line — no hard wrapping.** Write each prose paragraph as a single unbroken line and separate paragraphs with one blank line. Never insert manual newlines mid-paragraph to hit a column width. Markdown readers (Obsidian, etc.) soft-wrap to the reader's own max-line-width setting, so hard wraps only create noisy diffs and broken re-flow. This applies to prose only — tables, list items, code fences, and blockquote lines keep their existing per-line structure.
5. **No semicolons in prose.** Do not use the semicolon `;` in informational writing — join the clauses with a comma or split them into two sentences with a period. This restriction is for prose only. Code is never altered — C, shell, JavaScript, and any language where `;` is part of the syntax, plus inline code, code fences, and command lines, keep their semicolons.

## Outputs

| Artifact | Path |
|----------|------|
| Vulnerability doc | `output/<VULN-ID>.md` (e.g. `output/API7_SSRF.md`) |

**Handoff:** `04_integrate` promotes this into `src/docs/<Device>/Vulns/<Category>/`.
