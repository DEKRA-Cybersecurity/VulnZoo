# Model Workspace Protocol (MWP) — Condensed Guide

> Practical version for working in VulnZoo. Full paper: [`../MWP.md`](../MWP.md).

MWP orchestrates an agent's work **through the folder structure**, not through a
code framework. The core idea: if the prompts and context for each stage already
live as files in a well-organized hierarchy, you don't need a coordination layer —
just one agent that reads **the right files at the right moment**. It applies Unix
pipeline principles: programs that do one thing, the output of one is the input of
the next, plain text as the interface.

## The five layers

| Layer | Question | In VulnZoo |
|-------|----------|------------|
| **Layer 0** | *Where am I?* | `AGENTS.md` — global identity + routing table |
| **Layer 1** | *Where do I go?* | `CLAUDE.md` / `KIMI.md` — per-agent entry points |
| **Layer 2** | *What do I do?* | `<component>/CONTEXT.md` — stage contract |
| **Layer 3** | *What rules apply?* | `docs/` — reference material (stable) |
| **Layer 4** | *What am I working with?* | code under `*/files/`, `*/api_server/`, apps |

An agent loads **only** the layers it needs for its stage. Less irrelevant context
= better model performance. Layer 3 (reference) is *internalized as constraints*;
Layer 4 (artifacts) is *processed as input*.

## Stage contracts (Layer 2)

Each stage `CONTEXT.md` defines a three-part contract:

- **Inputs** — which files (Layer 3/4) the stage reads.
- **Process** — what it does.
- **Outputs** — what it writes, and where.

The stage reads a defined input, transforms it, and writes a defined output. A
stage that builds doesn't document; a stage that documents doesn't deploy.

## Principles when working here

1. **One stage, one job.** Stay inside the stage's contract; don't cross
   components unless the routing sends you there.
2. **Plain text as the interface.** Every artifact is readable, editable
   markdown/code; any human can inspect and correct it.
3. **Layered context loading.** Walk the chain Layer 1 → 0 → 2 → 3 before editing;
   don't load the whole workspace and don't guess paths.
4. **Edit the source, not the product.** If something goes wrong repeatedly, fix
   the source file (the `CONTEXT.md`, the Layer 3 doc), not just the one-off
   output. Fixing the source fixes every future run.
5. **Human review at every gate.** Each output is an editable surface; the human
   reviews between stages.

## MWP naming convention in VulnZoo

`AGENTS.md` (Layer 0) · `CLAUDE.md`/`KIMI.md` (Layer 1) · `*/CONTEXT.md`
(Layer 2) · `docs/` (Layer 3). The agent's entry point is its Layer 1 file, which
delegates to `AGENTS.md`.

---

*Next:* go back to [`AGENTS.md`](AGENTS.md) and use its routing table.
