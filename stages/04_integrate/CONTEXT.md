# Stage 04 — Integrate / Promote (Layer 2)

> **Parent:** [`../CONTEXT.md`](../CONTEXT.md) (pipeline). **Terminal pass.** This
> stage does **not** produce a throwaway artifact — its output *is the change to
> `src/`*. This is where the pipeline's outputs **adapt into the product**.

## Inputs

| Layer | Source | Use |
|-------|--------|-----|
| Layer 4 | `../02_implement/output/code/` + `manifest.md` | Validated code drafts + their target paths |
| Layer 4 | `../03_document/output/<VULN-ID>.md` | Validated product doc |
| Layer 3 | `../../_config/promotion-map.md` | **Canonical** artifact → `src/` path mapping |

## Process (promotion contract)

For each artifact, copy it to its canonical `src/` destination per
`../../_config/promotion-map.md`. Summary of the mapping:

| Artifact (from `output/`) | Destination in `src/` (product) |
|---------------------------|---------------------------------|
| `02_implement/output/code/<path>` | same `<path>` under `src/` (per `manifest.md`) |
| Lab overlay change | repackage `src/labs/<device>/files/` → `src/labs/vulnzoo/files/usr/lib/vulnzoo-devices/<device>.tar.gz` |
| `03_document/output/<VULN-ID>.md` | `src/docs/<Device>/Vulns/<Category>/<VULN-ID>.md` |
| Index + status update | `src/docs/<Device>/Vulns/README.md` → set badge `✅ DONE` |

Then:
1. Verify the change builds/loads (see the device's `src/labs/<device>/CONTEXT.md`).
2. Confirm Layer 3 ↔ Layer 4 are in sync (doc paths match real code).

## Outputs

| Artifact | Path |
|----------|------|
| **The product change** | edits under `../../src/…` |
| Integration log | `output/integration-log.md` (what was promoted, where, when) |

**Done when:** `src/` contains the change, the doc is in place, the index badge is
updated, and the lab still loads.
