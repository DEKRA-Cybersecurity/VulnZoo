# Verification - BulbBee CRA dossier completion

Date: 2026-10-20
Spec: `stages/01_spec/output/bulbbee-cra-spec.md`
Scope: 5 new documents + 4 edits in `src/docs/BulbBee/CRA/`, no device code change.
Environment: authoring env (pandoc 3.x + xelatex present). These are documentation deliverables, so every acceptance criterion is runnable here (render, parse, grep, cross-ref), none is blocked on hardware.

## Acceptance criteria (from spec section 4), per document

Legend: P = pass.

| Criterion | BB-RMR-005 | BB-SCP-006 | BB-VVR-007 | BB-VMP-008 | BB-TD-000 |
|-----------|:----------:|:----------:|:----------:|:----------:|:---------:|
| 1 Frontmatter + control block + yaml parse | P | P | P | P | P |
| 2 CRA Annex VII item + prEN clause cited | P | P | P | P | P |
| 3 Device facts grounded in the real lab | P | P | P | P | P |
| 4 Intentional claim contradicted + gap-key row | P | P | P | P | P |
| 5 Cross-references resolve | P | P | P | P | P |
| 6 Renders through render-cra.sh | P | P | P | P | P |
| 7 Prose style (no semicolon, no em dash/emoji) | P | P | P | P | P |
| 8 Annex VII coverage complete (BB-TD-000 map) | n/a | n/a | n/a | n/a | P |

## Evidence

1. **Frontmatter / parse.** `yaml.safe_load` on each new document's frontmatter returns the expected `id`, `status: DONE` and `cra_annex`. All five carry an H1 and a document-control table in the RoutCoon style (owner + approver).
2. **Clause citation.** Each document names its Annex VII item and prEN clause in the frontmatter (`cra_annex`, `standard`) and in the section headers (clause 6.2-6.7 in BB-RMR-005, clauses 7.2-7.7c in BB-SCP-006, 7.6 in BB-VVR-007, 7.8 + prEN 40000-1-3 in BB-VMP-008, 7.5d in BB-TD-000).
3. **Device grounding.** Threats and controls trace to the real catalogue: T-01..T-09 map to BULB-01..07, BULB-CLD, BULB-APP. Architecture names the real planes (`ble_light.py`, `cloud_tunnel.py`, `local_tcp.py`, `lighting_service.py:8082`), the `secure` flag in `config.json`, and the SBOM components. No invented component or port.
4. **Intentional gap + gap key.** Each document carries an assessor note pointing at the contradicting finding. `99-Assessor-Gap-Key.md` now has a "Technical-documentation gaps" section with rows TD-1, RMR-1, SCP-1, VVR-1, VMP-1, each tied to the finding that disproves the claim.
5. **Cross-references.** Python cross-ref scan over all `BB-*.md` plus the plan and gap key: every `BB-xxx-NNN` id referenced resolves to an existing file. UNRESOLVED: none.
6. **Render.** `./render-cra.sh` produced 8 per-document PDFs plus `BulbBee-CRA-dossier.pdf` (bound, 8 documents) with no pandoc or LaTeX error. The bound `order` array puts BB-TD-000 first.
7. **Prose style.** `grep -c ';'` returns 0 for every new and edited document. No em dash, smart quote or emoji found (`grep -P` over the Unicode ranges). English throughout.
8. **Annex VII coverage.** BB-TD-000 section 2 maps every Annex VII item (1, 2a, 2b, 2-production, 3, 4, 5, 6, 7, plus Annex II user info and the Annex I mapping) to a document that exists. No item left unmapped. The same map is mirrored in the corrected `00-CRA-Documentation-Plan.md`.

## Edits verified

- `00-CRA-Documentation-Plan.md`: the false claim "Annex VII ... satisfied by this set ... no separate heavyweight technical file is required" is removed and replaced by the Annex VII coverage map and the corrected route-versus-content contrast. Document set table lists all 10 dossier documents. Frontmatter bumped to v1.1 and carries the prEN related standards.
- `99-Assessor-Gap-Key.md`: new "Technical-documentation gaps" section (5 rows).
- `BB-ERM-002`: Part II rows cross-reference BB-VMP-008 (disclosure, SBOM monitoring, secure update distribution).
- `render-cra.sh`: `order` array and header comment updated, dossier renders 8 documents.

## Status transitions

All five new documents and the four edits are verified in the authoring environment and set `status: DONE` (documentation deliverables, no hardware dependency). The intentional vulnerabilities are untouched, the `secure` baseline is described as the documented robust target and is not enabled by default.

## Not done (left to the owner)

- No commit was made. The files are written and verified, the owner commits when they choose.
- prEN 40000-1-4: not authored from memory. Its scope was not confirmed from the source PDF, so no document cites it. If its scope matters, confirm from `~/Desktop/CRA/` first.
