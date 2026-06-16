# VulnZoo

Intentionally-vulnerable IoT training labs, organized with the **Model Workspace
Protocol (MWP)**. The project lives in [`src/`](src/).

**Entry point:** read `@src/AGENTS.md` (Layer 0: global identity + routing table)
first, then follow its routing table to the relevant component. Methodology:
[`MWP.md`](MWP.md) (full paper), [`src/MWP_README.md`](src/MWP_README.md) (condensed).

> The vulnerabilities are intentional. Never harden them unless explicitly asked.

@src/AGENTS.md

> **Scope of this file:** this root `CLAUDE.md` is tracked in the repo (the root `.gitignore` ignores `/*.md` but whitelists it via `!/CLAUDE.md`, alongside `MWP.md`/`README.md`) and holds personal overrides layered on top of routing. The canonical, committed Layer 1 router is [`src/CLAUDE.md`](src/CLAUDE.md): for MWP structure and workspace behavior, it and the Layer 0 chain are authoritative. The rules below are personal working preferences, not part of the shipped MWP contract.

## Approach
- Start answering me with my name 'd4str3k'.
- Read existing files before writing. Don't re-read unless changed.
- Thorough in reasoning, concise in output.
- Skip files over 100KB unless required.
- No sycophantic openers or closing fluff.
- Do not guess APIs, versions, flags, commit SHAs, or package names. Verify by reading code or docs before asserting.

## Output
- For code deliverables: return the code first, explanation after and only if non-obvious.
- No prose padding around code. Use comments sparingly, only where logic is unclear.
- For docs and markdown, prose is the deliverable, so this section does not constrain it.
- No boilerplate unless explicitly requested.

## Code Rules
- Simplest working solution. No over-engineering.
- No abstractions for single-use operations.
- No speculative features or "you might also want..."
- Read the file before modifying it. Never edit blind.
- No docstrings or type annotations on code not being changed.
- No error handling for scenarios that cannot happen.
- Three similar lines is better than a premature abstraction.

## Review Rules
- State the bug. Show the fix. Stop.
- No suggestions beyond the scope of the review.
- No compliments on the code before or after the review.

## Debugging Rules
- Never speculate about a bug without reading the relevant code first.
- State what you found, where, and the fix. One pass.
- If cause is unclear: say so. Do not guess.

## Simple Formatting
- Applies to generated output and newly written content, not to pre-existing committed docs (many use em dashes as house style).
- No emojis, em dashes, smart quotes, or decorative Unicode symbols.
- Plain hyphens and straight quotes only.
- Natural language characters (accented letters, CJK, etc.) are fine when the content requires them.
- Code output must be copy-paste safe.
