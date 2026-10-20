# Spec - BulbBee CRA dossier completion (Annex VII correction)

- **Target**: BulbBee CRA manufacturer dossier, `src/docs/BulbBee/CRA/`
- **Type**: documentation (Layer 3), no device code change, intentional vulnerabilities untouched
- **Backlog**: `stages/TARGET_BULBBEE_CRA.md`
- **Style reference**: `src/docs/RoutCoon/CRA/` (mirror, proportionately lighter)

## 1. Problem and why it matters

The BulbBee dossier presents a Module A self-declaration (BB-DOC-001), an Annex I essential-requirements mapping (BB-ERM-002), an SBOM (BB-SBOM-003) and user information (BB-UM-004), and the plan declares this set sufficient for Annex VII. It is not. The CRA separates the conformity-assessment route from the substantive documentation obligations.

- The route (Module A, internal control, no notified body, CE on the manufacturer's own responsibility) is correctly driven by BulbBee being a default-category product, listed in neither Annex III nor Annex IV.
- The obligations are universal. Article 13 requires the manufacturer to perform a cybersecurity risk assessment and include it in the technical documentation. Annex I Part II requires a vulnerability handling process (SBOM, coordinated disclosure, security updates, secure distribution of updates). Annex VII lists the technical-documentation contents, and Annex VIII point 2 (Module A) requires the manufacturer to establish that full Annex VII documentation. None of these is waived by the default category, only the third-party review is.

So the dossier is missing: the risk assessment (Annex VII point 3), the design/development and secure-development evidence that is the secure development lifecycle (point 2a), the test reports (point 5), the vulnerability handling process (point 2b), and the Annex VII master/index that maps them (points 4 and 6). This spec adds a proportionate set that covers these items while keeping the default-versus-important contrast with RoutCoon.

## 2. Target document set

Five new documents, four edits to existing documents. The new documents are proportionate to a single-function consumer light under Module A, so they consolidate what RoutCoon splits into 14 files.

### BB-RMR-005 Product Cybersecurity Risk Management Report (Annex VII point 3, prEN 40000-1-2 clause 6)

Mirrors RC-RMR-001, lighter. Sections: product context (intended purpose and foreseeable misuse of the light, functions, three-plane operational environment, user, distribution of security functions, no RDPS for the local planes but the cloud tunnel noted), risk acceptance criteria, asset identification, threat identification sourced from the BULB-01..07 and BULB-P01..P07 catalogue, risk analysis (likelihood/impact/scenario), risk evaluation and acceptance, risk treatment (the `secure` baseline as the target state), risk communication (to BB-UM-004), risk review (to BB-VMP-008). Intentional gap: the manufacturer accepts several high risks with optimistic justifications (LAN trusted, updates infrequent, consumer-segment norm) that the assessor challenges, mirroring RoutCoon's under-treated-risk mechanism.

### BB-SCP-006 Product Cybersecurity Plan and Secure Development Lifecycle (Annex VII points 1 and 2a and production, prEN 40000-1-2 clauses 7.2 to 7.5a and 7.7c)

Consolidates RC-SCP-002 (plan) plus RC-SRS-003 (requirements) plus RC-SAD-004 (architecture) plus RC-SDE-005 (secure development environment) plus the production part of RC-SDD-009. This is the "security lifecycle" document. Sections: the living cybersecurity plan (activities, deliverables, owners, cadence), the cybersecurity requirements derived from the risk treatment, the architecture and trust boundaries of the three planes plus the HTTP owner, the secure-by-default configuration (the `secure` toggle described as the robust baseline), the secure development and maintenance environment, secure physical production, and third-party component due diligence for the SBOM components. Intentional gap: the plan claims secure-by-default and signed updates and no debug interface and encrypted transport, each contradicted by the shipped default (BULB-02, BULB-04, BULB-06, BULB-03).

### BB-VVR-007 Cybersecurity Verification and Validation Report (Annex VII point 5, prEN 40000-1-2 clause 7.6)

Mirrors RC-VVR-008. Test methods, scope, a requirement-by-requirement results table with verdicts, recurring basis. Intentional gap: the manufacturer records every requirement as Pass against its self-declared target, which the assessor battery (device overview README) disproves on the live device. The assessor note states the contradiction explicitly.

### BB-VMP-008 Vulnerability Handling, Monitoring and Secure Update Distribution (Annex VII point 2b, Annex I Part II, prEN 40000-1-2 clause 7.8, prEN 40000-1-3)

Mirrors RC-VMP-010, plus the secure-update-distribution content that is part of Annex VII point 2b. Sections: monitoring intervals and justification for the SBOM components, the coordinated vulnerability disclosure channel and intake, incident and vulnerability treatment with an issue register seeded from BULB-01..07, secure distribution of updates (the OTA path), residual-risk communication, third-party component monitoring. Intentional gap: the claimed monitored disclosure channel (`security@bulbbee.example`) is unverified, and the "signed, integrity-protected update distribution" is contradicted by the unsigned OTA (BULB-04).

### BB-TD-000 Technical Documentation and Conformity Dossier (Annex VII points 4 and 6, master index)

Mirrors RC-TD-000. The assessor's entry point. An Annex VII content map (each item to the document that satisfies it), the standards applied (CRA, EN 303 645, prEN 40000-1-2, prEN 40000-1-3), the reference to the DoC, and a traceability table across the whole BulbBee dossier. Intentional gap: it self-declares the documentation complete and consistent, which the gap key and the live device contradict.

### Edits

- `00-CRA-Documentation-Plan.md`: remove the section-3 claim that the compact set satisfies Annex VII, replace with an Annex VII coverage map pointing at the new documents, add the 5 documents to the document-set table, keep and sharpen the default-versus-important contrast (route differs, Annex VII content does not).
- `99-Assessor-Gap-Key.md`: add gap rows for the new claims (optimistic risk acceptance in BB-RMR-005, all-pass V&V in BB-VVR-007, monitored CVD and signed update distribution in BB-VMP-008), each tied to the finding that disproves it.
- `BB-ERM-002`: in the Part II table, point the vulnerability-handling and SBOM and security-update rows at BB-VMP-008.
- `render-cra.sh`: add BB-TD-000, BB-RMR-005, BB-SCP-006, BB-VVR-007, BB-VMP-008 to the bound-dossier `order` array with BB-TD-000 first.

## 3. Standards framing

EN 303 645 remains the Annex I Part I control yardstick in BB-ERM-002 (unchanged). The new process documents additionally use the prEN 40000-1-2 clause structure (clause 6 risk management, clause 7 lifecycle) and prEN 40000-1-3 (vulnerability handling) as the method, applied proportionately for a Module A default product. This is honest: a default-category manufacturer still performs risk management and lifecycle activities under Article 13 and Annex VII, and the 40000 series is the horizontal harmonised-standard family giving the method. prEN 40000-1-4 is cited only if its scope is confirmed from the source PDF in `~/Desktop/CRA/`, otherwise omitted rather than guessed.

## 4. Acceptance criteria (verified in 05_verify, per document)

1. **Frontmatter and structure**: RoutCoon-style YAML frontmatter and H1 and document-control block present, `yaml.safe_load` parses.
2. **Clause citation**: each document names the CRA Annex VII item and the prEN clause it addresses.
3. **Device grounding**: every device fact traces to the real lab (BULB catalogue, three-plane architecture, `secure` toggle, SBOM), no invented component or port.
4. **Intentional gap**: at least one manufacturer claim contradicted by the device, and a matching row exists in 99-Assessor-Gap-Key.md.
5. **Cross-references resolve**: every referenced BB-* document and Vulns path exists.
6. **Renders**: `render-cra.sh` produces a per-document PDF for each new doc and a bound dossier with all documents, no pandoc or LaTeX error.
7. **Prose style**: English, one physical line per paragraph, no semicolon in prose (`grep` check), plain hyphens and straight quotes, no emoji.
8. **Annex VII coverage complete**: BB-TD-000's Annex VII content map has every item pointed at a real document, no item left unmapped.

## 5. Out of scope

- No device code change. The intentional vulnerabilities stay. The `secure` baseline is described as the documented robust target, not enabled by default.
- No commit. Files are written and verified, the user commits when they choose.
- prEN 40000-1-4 content is not authored from memory. If its scope matters, confirm from the PDF first.
