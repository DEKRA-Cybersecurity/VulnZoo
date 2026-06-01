# _config — Factory Configuration (Layer 3)

> **Configure the factory, not the product** (MWP §3.1). These files define *how*
> the development pipeline authors changes. They are stable across runs and are the
> factory's counterpart to the product's reference docs in `../src/docs/`.

| File | Purpose | Used by |
|------|---------|---------|
| [`vuln-doc-template.md`](vuln-doc-template.md) | Required structure + YAML frontmatter for a product vulnerability doc | `stages/03_document` |
| [`conventions.md`](conventions.md) | Authoring conventions: OWASP/CWE IDs, status badges, naming, English-only | all stages |
| [`promotion-map.md`](promotion-map.md) | **Canonical** mapping: stage `output/` → `src/` destination paths | `stages/04_integrate` |

**Audience:** the agent (Claude). For *product* reference (audience: lab users), see [`../src/docs/`](../src/docs/).
