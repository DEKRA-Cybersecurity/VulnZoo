# VulnZoo — Claude Entry Point (Layer 1)

You are working in the **VulnZoo** workspace (intentionally-vulnerable IoT
training labs, organized with the Model Workspace Protocol).

**Start here:** read `@AGENTS.md` (Layer 0) for the global identity and the
routing table, then follow the routing table to the Layer 2 `CONTEXT.md` of the
component you are touching. Do not assume paths or behaviors — walk the chain.

## MWP navigation tree

```
CLAUDE.md (Layer 1, Claude entry — this file)
  └─→ AGENTS.md (Layer 0, global identity + routing table)
        └─→ MWP_README.md (layer methodology)
              └─→ <component>/CONTEXT.md (Layer 2, stage contract)
                    └─→ <component>/<device>/CONTEXT.md (lab-specific contract)
                          └─→ docs/<Device>/ (Layer 3, reference docs)
```

## Reminders

- The vulnerabilities are **intentional** — never harden them unless explicitly asked.
- Keep Layer 3 docs (`docs/`) in sync with Layer 4 code when you change either.

@AGENTS.md
