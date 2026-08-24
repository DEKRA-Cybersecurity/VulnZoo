---
id: ROUTCOON-CRA-PLAN
title: RoutCoon CRA Manufacturer Documentation Plan (prEN 40000-1-2)
category: Compliance
status: DONE
severity: N/A
owasp: N/A
cwe: N/A
affected_components: [routcoon]
standard: prEN 40000-1-2 (CEN/CLC/JTC 13/WG 9, JT013089)
related_standards: [prEN 40000-1-3 (Vulnerability Handling / SBOM)]
regulation: EU Cyber Resilience Act (Regulation (EU) 2024/2847)
---

# RoutCoon CRA Manufacturer Documentation Plan

## 1. Purpose and scope

This plan defines the fictional manufacturer documentation set for the RoutCoon router, prepared so an assessor can evaluate the product against the EU Cyber Resilience Act using the harmonised standard prEN 40000-1-2 (Principles, product risk management, and lifecycle activities).

The source of the assessment is the evaluator checklist `CRA_prEN40000-1-2_sample.xlsx`. That checklist lists 24 documentation deliverables mapped to the clauses of the standard. For each deliverable the manufacturer must fill the checklist column "Document name / Section" (column E, currently blank) with a pointer to the document and section where the requirement is addressed. This plan defines those documents and the target pointers so column E can be completed once the documents exist.

RoutCoon is an intentionally vulnerable training device. The documentation is fictional by design and is not intended to certify a real product. See section 4 for how the intentional vulnerabilities are handled inside a CRA dossier.

## 2. What the standard requires (checklist analysis)

prEN 40000-1-2 organises manufacturer obligations into two clauses, each expressed as numbered normative requirements ("shall" statements) with stable identifiers of the form `[FAMILY-NN-RQ-MM]`. These identifiers are the standard's own, reproduced verbatim in checklist column F.

Two requirement families:

- **RMA (Clause 6, Product cybersecurity risk management activities)**: 21 requirements across 9 deliverables (RMA-01 to RMA-09).
- **CLA (Clause 7, Product cybersecurity lifecycle activities)**: 37 requirements across the lifecycle deliverables (CLA-01 to CLA-10).

Total normative requirements: 58.

Clause 6 (risk management) sub-structure:

| Clause | Deliverable | Requirements |
|--------|-------------|--------------|
| 6.2 | Product Context (IPRFU, functions, operational environment, architecture, users, distribution of security functions, RDPS) | RMA-01-RQ-01, RMA-01-RQ-02 |
| 6.3 | Risk Acceptance Criteria | RMA-02-RQ-01 |
| 6.4.2 | Asset Identification | RMA-03-RQ-01 |
| 6.4.3 | Threat Identification | RMA-04-RQ-01 |
| 6.4.4 | Risk Analysis (likelihood, impact, scenario) | RMA-05-RQ-01..03 |
| 6.4.5 | Risk Evaluation and Acceptance | RMA-06-RQ-01..04 |
| 6.5 | Risk Treatment | RMA-07-RQ-01..03 |
| 6.6 | Risk Communication | RMA-08-RQ-01..03 |
| 6.7 | Risk Review | RMA-09-RQ-01..03 |

Clause 7 (lifecycle) sub-structure:

| Clause | Deliverable | Requirements |
|--------|-------------|--------------|
| 7.2 | Product Cybersecurity Plan (living document) | CLA-01-RQ-01..02 |
| 7.3 | Product Cybersecurity Requirements | CLA-02-RQ-01..02 |
| 7.4 | Cybersecurity Architecture and Design | CLA-03-RQ-01..02 |
| 7.5a | Secure Development Environment Evidence | CLA-04-RQ-01..07 |
| 7.5b | Component List | annex-derived, no RQ ID |
| 7.5c | Software Bill of Materials (SBOM) | annex-derived, see prEN 40000-1-3 |
| 7.5d | Technical Documentation (CRA Annex VII) | annex-derived, no RQ ID |
| 7.5e | Information and Instructions to the User (CRA Annex II) | annex-derived, no RQ ID |
| 7.5f | Third-Party Component Integration Confirmation | annex-derived, no RQ ID |
| 7.6 | Cybersecurity Verification and Validation | CLA-05-RQ-01..06 |
| 7.7a | Secure Software Distribution Evidence | CLA-06-RQ-01..04 |
| 7.7b | Accessible User Documentation Channel Evidence | annex-derived, no RQ ID |
| 7.7c | Secure Physical Production Evidence | CLA-07-RQ-01..02 |
| 7.8a | Monitoring Intervals Justification | CLA-08-RQ-01..05 |
| 7.8b | Incident / Vulnerability Treatment Evidence | annex-derived, no RQ ID |
| 7.9a | Secure Decommissioning Plan | CLA-09-RQ-01..02 |
| 7.9b | Decommissioning Instructions to the User | annex-derived, no RQ ID |
| 7.10 | Third-Party Component Due Diligence Evidence | CLA-10-RQ-01..05 |

Eight deliverables carry no RMA/CLA requirement ID because they are CRA-annex artifacts rather than prEN clause requirements. They are: Component List (7.5b), SBOM (7.5c), Annex VII technical documentation (7.5d), Annex II user information (7.5e), third-party integration confirmation (7.5f), accessible channel evidence (7.7b), incident treatment evidence (7.8b), and decommissioning instructions to the user (7.9b). These are still mandatory deliverables and each is mapped to a document below.

Checklist item numbering skips number 26 (rows run 1 to 25 then 27, 28). This is a cosmetic gap in the sample and does not correspond to a missing deliverable.

## 3. Document architecture

The 24 checklist deliverables collapse into a controlled set of 14 documents. Grouping follows the natural activity boundaries of the standard, so each document is a coherent unit an assessor recognises, while preserving one-to-one traceability from every requirement to a document section. Clause 6 becomes a single risk-management report (its requirements cross-reference each other and are one workflow). The physical/distribution, monitoring, and decommissioning sub-clauses are each grouped into one document.

Document ID scheme: `RC-<TYPE>-NNN`. All documents are versioned, dated, and carry a document control block (owner, approver, revision history) so the "living document" and "reviewed at planned intervals" requirements are demonstrable.

| Doc ID      | Title                                                                   | Covers checklist rows | Requirement IDs       |
| ----------- | ----------------------------------------------------------------------- | --------------------- | --------------------- |
| RC-TD-000   | Technical Documentation and Conformity Dossier (Annex VII master index) | 16 (7.5d)             | annex                 |
| RC-RMR-001  | Product Cybersecurity Risk Management Report                            | 1-9 (6.2-6.7)         | RMA-01..09 (21 RQ)    |
| RC-SCP-002  | Product Cybersecurity Plan                                              | 10 (7.2)              | CLA-01                |
| RC-SRS-003  | Product Cybersecurity Requirements Specification                        | 11 (7.3)              | CLA-02                |
| RC-SAD-004  | Cybersecurity Architecture and Design                                   | 12 (7.4)              | CLA-03                |
| RC-SDE-005  | Secure Development Environment Evidence                                 | 13 (7.5a)             | CLA-04 (7 RQ)         |
| RC-CBL-006  | Component List                                                          | 14 (7.5b)             | annex                 |
| RC-SBOM-007 | Software Bill of Materials (machine-readable)                           | 15 (7.5c)             | annex, prEN 40000-1-3 |
| RC-VVR-008  | Cybersecurity Verification and Validation Report                        | 19 (7.6)              | CLA-05 (6 RQ)         |
| RC-SDD-009  | Secure Distribution and Production Evidence                             | 20, 21, 22 (7.7a/b/c) | CLA-06, CLA-07        |
| RC-VMP-010  | Vulnerability Monitoring and Issue Management                           | 23, 24 (7.8a/b)       | CLA-08 (5 RQ)         |
| RC-DEC-011  | Secure Decommissioning Plan                                             | 25, 27 (7.9a/b)       | CLA-09                |
| RC-TPD-012  | Third-Party Component Due Diligence and Integration                     | 18, 28 (7.5f, 7.10)   | CLA-10 (5 RQ)         |
| RC-UM-013   | Information and Instructions to the User (Annex II user manual)         | 17 (7.5e)             | annex                 |

RC-TD-000 is the umbrella. It holds the completed traceability matrix (section 5 of this plan becomes its core content) and is the artifact the assessor opens first. Every other document is referenced from it.

RC-SBOM-007 is not a prose document. It is a machine-readable file in a commonly used format (CycloneDX JSON is the default choice, SPDX is the alternative). It is generated from the RoutCoon build configuration rather than hand-authored. See section 6.

## 4. Framing: how intentional vulnerabilities live inside a CRA dossier

RoutCoon is deliberately non-conformant. A CRA dossier that simply admitted every flaw would not resemble a real submission, and a dossier that hid every flaw would have no training value. The recommended framing is a realistic middle: a plausible, internally consistent, professionally written manufacturer dossier whose claims diverge from the product in ways the assessor discovers by verifying documentation against the live device and test evidence.

This mirrors real conformity assessment. The assessor does not trust the paperwork, they verify it. The intentional vulnerabilities become discrepancies between claimed controls and observed behaviour, which is exactly the skill a CRA evaluator practices. Two mechanisms produce the divergences:

- **Under-treated risk.** The risk management report (RC-RMR-001) genuinely identifies many real threats, sourced from the existing RoutCoon vulnerability catalogue (IoT1-10 and API2-9), but the manufacturer's risk treatment and acceptance decisions are deliberately optimistic. The assessor challenges weak residual-risk justifications against the risk acceptance criteria.
- **Claimed-but-absent controls.** The architecture, distribution, and requirements documents assert controls the product contradicts. Example: RC-SDD-009 claims signed, integrity-protected firmware distribution while the shipped device runs `opkg` with `check_signature 0` and an unsigned root cron auto-updater that executes artifacts dropped over anonymous FTP. The assessor finds the contradiction by testing the update path.

Every document therefore has two layers: the manufacturer claim (what the dossier states) and the ground truth (what the product does, already documented in the RoutCoon vulnerability catalogue). The value of the exercise is the gap between them. This plan tags, per document in section 7, where the intended gaps sit so the generation phase produces them deliberately rather than by accident.

Alternative framings, if the trainer prefers, are (a) a fully whitewashed dossier that claims complete conformity with no honest residual risk, or (b) an honest gap-documented dossier that accurately reflects the poor posture and accepts the residual risk. The recommended framing above is preferred because it is the most realistic assessment scenario and reuses the existing vulnerability catalogue as the assessor's ground truth.

## 5. Traceability matrix (fills checklist column E)

This is the target mapping. Once each document exists with real section numbers, transcribe the "Document / Section" column into column E of `CRA_prEN40000-1-2_sample.xlsx` for the matching row.

| #   | Clause | Deliverable                                         | Document / Section                      | Requirement IDs            |
| --- | ------ | --------------------------------------------------- | --------------------------------------- | -------------------------- |
| 1   | 6.2    | Product Context                                     | RC-RMR-001 s.6.2                        | RMA-01-RQ-01, RMA-01-RQ-02 |
| 2   | 6.3    | Risk Acceptance Criteria                            | RC-RMR-001 s.6.3                        | RMA-02-RQ-01               |
| 3   | 6.4.2  | Asset Identification                                | RC-RMR-001 s.6.4.2                      | RMA-03-RQ-01               |
| 4   | 6.4.3  | Threat Identification                               | RC-RMR-001 s.6.4.3                      | RMA-04-RQ-01               |
| 5   | 6.4.4  | Risk Analysis                                       | RC-RMR-001 s.6.4.4                      | RMA-05-RQ-01..03           |
| 6   | 6.4.5  | Risk Evaluation and Acceptance                      | RC-RMR-001 s.6.4.5                      | RMA-06-RQ-01..04           |
| 7   | 6.5    | Risk Treatment                                      | RC-RMR-001 s.6.5                        | RMA-07-RQ-01..03           |
| 8   | 6.6    | Risk Communication                                  | RC-RMR-001 s.6.6 and RC-UM-013 s.Safety | RMA-08-RQ-01..03           |
| 9   | 6.7    | Risk Review                                         | RC-RMR-001 s.6.7                        | RMA-09-RQ-01..03           |
| 10  | 7.2    | Product Cybersecurity Plan                          | RC-SCP-002 (whole)                      | CLA-01-RQ-01..02           |
| 11  | 7.3    | Cybersecurity Requirements                          | RC-SRS-003 (whole)                      | CLA-02-RQ-01..02           |
| 12  | 7.4    | Architecture and Design                             | RC-SAD-004 (whole)                      | CLA-03-RQ-01..02           |
| 13  | 7.5a   | Secure Development Environment                      | RC-SDE-005 (whole)                      | CLA-04-RQ-01..07           |
| 14  | 7.5b   | Component List                                      | RC-CBL-006 (whole)                      | annex                      |
| 15  | 7.5c   | SBOM                                                | RC-SBOM-007 (file)                      | annex                      |
| 16  | 7.5d   | Technical Documentation (Annex VII)                 | RC-TD-000 (whole)                       | annex                      |
| 17  | 7.5e   | Information and Instructions to the User (Annex II) | RC-UM-013 (whole)                       | annex                      |
| 18  | 7.5f   | Third-Party Integration Confirmation                | RC-TPD-012 s.Integration                | annex                      |
| 19  | 7.6    | Verification and Validation                         | RC-VVR-008 (whole)                      | CLA-05-RQ-01..06           |
| 20  | 7.7a   | Secure Software Distribution                        | RC-SDD-009 s.Distribution               | CLA-06-RQ-01..04           |
| 21  | 7.7b   | Accessible User Documentation Channel               | RC-SDD-009 s.Channel                    | annex                      |
| 22  | 7.7c   | Secure Physical Production                          | RC-SDD-009 s.Production                 | CLA-07-RQ-01..02           |
| 23  | 7.8a   | Monitoring Intervals Justification                  | RC-VMP-010 s.Monitoring                 | CLA-08-RQ-01..05           |
| 24  | 7.8b   | Incident / Vulnerability Treatment                  | RC-VMP-010 s.Treatment                  | annex                      |
| 25  | 7.9a   | Secure Decommissioning Plan                         | RC-DEC-011 s.Plan                       | CLA-09-RQ-01..02           |
| 27  | 7.9b   | Decommissioning Instructions to the User            | RC-DEC-011 s.User and RC-UM-013 s.Reset | annex                      |
| 28  | 7.10   | Third-Party Due Diligence                           | RC-TPD-012 s.DueDiligence               | CLA-10-RQ-01..05           |

## 6. RoutCoon source material per document

Each document draws on artifacts that already exist in the repository, so the dossier is grounded in the real product rather than invented. Paths are relative to `src/`.

- **RC-CBL-006 / RC-SBOM-007** (component list and SBOM). Source of truth: `labs/routcoon/.config` (312 selected packages). The SBOM is generated from this file into CycloneDX JSON. Confirm actual versions on the running image before asserting them (Samba 4.18.8, Dropbear, net-snmp are cited in docs but not pinned in `.config`). Base platform: OpenWrt 24.10.3, Linux 6.6, BusyBox 1.36.1. Base attribution: OWASP IoTGoat.
- **RC-RMR-001** (risk management). Product context from `docs/RoutCoon/README.md` and `labs/routcoon/CONTEXT.md` (services, ports, accounts, network 192.168.2.0/24 wired plus 192.168.3.0/24 WiFi). Threats sourced from the vulnerability catalogue in `docs/RoutCoon/IoT (Router)/Vulnerabilities.md` and `docs/RoutCoon/API/Vulnerabilities.md`. The SNMP section of the IoT catalogue already carries a regulatory-mapping block naming ETSI EN 303 645, IEC 62443 and the CRA, which is directly reusable.
- **RC-SAD-004** (architecture). Trust boundaries: wired LAN admin surface (eth0 192.168.2.1), WiFi AP (phy0-ap0 192.168.3.1, WPA2-PSK), single physical NIC with no distinct WAN. Services all bind 0.0.0.0. This is where secure-by-default is claimed and contradicted.
- **RC-SDD-009** (distribution and production). Update mechanism from `labs/routcoon/files/opt/oem-updates/scripts/auto-updater.sh`, `files/etc/crontabs/root`, and `files/etc/opkg.conf` (`check_signature 0`). Intended contradiction lives here.
- **RC-VMP-010** (monitoring and issue management). Bridges to prEN 40000-1-3 (vulnerability handling). The existing vulnerability catalogue frontmatter (id/severity/owasp/cwe/status) is the seed for an issue register.
- **RC-TPD-012** (third-party due diligence). FOSS components to cover: OpenWrt, LuCI/uhttpd, Dropbear, dnsmasq, Samba, miniupnpd, wpad/hostapd, mbedTLS/OpenSSL, brcmfmac. For each: intended purpose alignment, support period, maintenance/disclosure indicators.
- **RC-UM-013** (user manual). Basis: `docs/RoutCoon/README.md` getting-started plus the in-image OEM notice at `labs/routcoon/files/opt/oem-updates/pending/README.txt` (support contact `contact@routcoon-oem.local`). Add security configuration, update notifications, risk warnings, factory reset, and end-of-support guidance.

## 7. Generation phasing

Dependency-ordered. Each phase produces complete, self-contained documents. Later phases reference earlier ones.

1. **Foundation (factual base).** RC-CBL-006 Component List and RC-SBOM-007 SBOM, both generated from `.config`. RC-TD-000 skeleton with the empty traceability matrix. Everything downstream references these.
2. **Risk core.** RC-RMR-001, the single Clause 6 report. Product context, asset and threat identification (from the vulnerability catalogue), risk analysis, evaluation, treatment, communication, review. This is the largest document and the source of the deliberate under-treatment gaps.
3. **Requirements and architecture.** RC-SRS-003 and RC-SAD-004, derived from the risk treatment decisions in RC-RMR-001.
4. **Lifecycle process documents.** RC-SCP-002, RC-SDE-005, RC-VVR-008, RC-SDD-009, RC-VMP-010, RC-DEC-011, RC-TPD-012. These can be produced in parallel once the risk core and architecture exist.
5. **User-facing.** RC-UM-013 (Annex II), drawing on the risk communication content from RC-RMR-001 s.6.6 and the decommissioning user instructions from RC-DEC-011.
6. **Close-out.** Populate the RC-TD-000 traceability matrix with real section numbers, then transcribe the "Document / Section" pointers into column E of the checklist xlsx. Final consistency pass across all documents (Annex VII requires the technical documentation to be reviewed for consistency and appropriateness).

## 8. Conventions

- **Location.** `src/docs/RoutCoon/CRA/`. One file per document, named `RC-<TYPE>-NNN-<slug>.md`, except RC-SBOM-007 which is `RC-SBOM-007.cdx.json`.
- **Language.** English (MWP production-markdown rule).
- **Frontmatter.** Same YAML convention as the RoutCoon vulnerability docs (id, title, category, status, plus document-control fields: version, date, owner, approver).
- **Prose style.** MWP style: one physical line per paragraph, no semicolons in prose, plain hyphens and straight quotes.
- **Traceability.** Every requirement ID (RMA/CLA-RQ) appears verbatim in the document section that satisfies it, so an assessor can grep the dossier by requirement ID.

## 9. Resolved decisions

The following were settled before generation so the dossier is internally consistent.

- **SNMP is treated as a shipped component.** net-snmp (snmpd, v1/v2c with default communities `public`/`private`) is documented as a running RoutCoon service and included in the component list (RC-CBL-006), the SBOM (RC-SBOM-007), and the risk assessment (RC-RMR-001), consistent with `labs/routcoon/CONTEXT.md`, the vulnerability catalogue, and the `80-routcoon-services.sh` hook. This holds even though every SNMP package is currently "not set" in `.config`. Mark the SNMP entry in the SBOM as declared and confirm its version against the running image before pinning.
- **OpenWrt version is 24.10.3.** RoutCoon ships OpenWrt 24.10.3 (`r28739-d9340319c6`), Linux 6.6, BusyBox 1.36.1. This is authoritative for the dossier. The 24.10.2 value elsewhere is the wider project baseline in AGENTS.md and applies to other labs, not to RoutCoon. The `.config` device profile `rpi-2` (bcm2709) is retained as-is because the image runs correctly on Pi 3B/3B+.
- **Management IP is 192.168.2.1.** The authoritative address throughout the dossier is 192.168.2.1 (wired LAN) with the WiFi AP on 192.168.3.1. The stale `192.168.1.1` values in the IoT walkthrough and the RoutCoon README note have been corrected. The `192.168.1.x` values that remain in `dnsmasq.conf.reference` (a parked, unloaded config), `CONFIG_TARGET_PREINIT_IP` (the failsafe preinit IP), and the intentionally vulnerable LuCI controllers are functional or deliberate and were left unchanged.
