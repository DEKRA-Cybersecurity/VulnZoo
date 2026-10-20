---
id: BULBBEE-CRA-PLAN
title: BulbBee CRA Manufacturer Documentation Plan (default category, Module A)
category: Compliance
status: DONE
severity: N/A
owasp: N/A
cwe: N/A
affected_components: [bulbbee]
regulation: EU Cyber Resilience Act (Regulation (EU) 2024/2847)
standard: ETSI EN 303 645 (consumer IoT baseline)
related_standards: [prEN 40000-1-2 (risk management and lifecycle), prEN 40000-1-3 (vulnerability handling)]
version: 1.1
date: 2026-09-04
owner: BulbBee manufacturer (fictional)
---

# BulbBee CRA Manufacturer Documentation Plan

## 1. Purpose and scope

This plan defines the fictional manufacturer documentation set for the BulbBee smart light, prepared so a student-assessor can evaluate the product against the EU Cyber Resilience Act. BulbBee is the VulnZoo reference for a **default-category** product with digital elements, and this dossier deliberately demonstrates the lightest conformity route, in contrast to the RoutCoon dossier which follows the heavier important-product route under prEN 40000-1-2 (`../../RoutCoon/CRA/00-CRA-Documentation-Plan.md`).

BulbBee is an intentionally vulnerable training device. The documentation is fictional by design and is not intended to certify a real product. Section 4 explains how the intentional vulnerabilities live inside the dossier.

## 2. Product classification and conformity route

BulbBee is a consumer WiFi smart light. It is not a router, a password manager, a network-management tool, an operating system, a microprocessor, or any other product type listed in CRA Annex III (important) or Annex IV (critical). It therefore sits in the **default category**, which is roughly 90% of products with digital elements.

Consequences of the default classification:

- **Conformity assessment**: Module A, internal control (CRA Annex VIII). The manufacturer performs the assessment itself, with **no notified body**. There is no mandatory third-party audit and no EU cybersecurity certificate.
- **Declaration and marking**: the manufacturer draws up an EU Declaration of Conformity (Annex V content) and affixes the CE marking on its own responsibility.
- **Presumption of conformity**: achieved by applying harmonised standards once cited in the Official Journal. For a consumer IoT device the baseline reference is **ETSI EN 303 645**, used throughout this dossier as the technical yardstick for the Annex I essential requirements.

Contrast with RoutCoon (important, Annex III): a router must, at minimum, apply harmonised standards or undergo a third-party route, and its dossier (prEN 40000-1-2, 14 documents) is correspondingly heavier. What the default route makes lighter is the assurance route, not the content obligations. The risk assessment (Article 13, Annex VII point 3), the vulnerability handling process (Annex I Part II, Annex VII point 2b), the design and secure-development evidence (Annex VII point 2a) and the test reports (Annex VII point 5) apply to BulbBee exactly as they apply to RoutCoon, and Module A itself (Annex VIII point 2) requires the manufacturer to establish the full Annex VII technical documentation. BulbBee's dossier therefore covers the same Annex VII items as RoutCoon's, in a consolidated set proportionate to a single-function light, rather than omitting them. The lesson is the assurance contrast (no notified body, self-declaration), not a lighter set of obligations.

## 3. Document set

The default route needs a controlled, compact set. All documents live in `src/docs/BulbBee/CRA/`, English, MWP prose style, with a document-control block.

| Doc ID | Title | Role |
|--------|-------|------|
| BULBBEE-CRA-PLAN | This plan | Umbrella, route, document set, traceability, gap framing |
| BB-TD-000 | Technical Documentation and Conformity Dossier | Annex VII master index, content map, dossier-wide traceability |
| BB-DOC-001 | EU Declaration of Conformity | Annex V self-declared DoC |
| BB-ERM-002 | Annex I Essential-Requirements Mapping | Requirement -> claim -> EN 303 645 -> device ground truth -> finding |
| BB-SBOM-003 | Software Bill of Materials | Generated (CycloneDX) from the bulbbee image package list, see section 5 |
| BB-UM-004 | Information and Instructions to the User (Annex II) | Security-relevant user information, disclosure channel, end-of-support |
| BB-RMR-005 | Product Cybersecurity Risk Management Report | Annex VII point 3, Article 13 risk assessment (prEN 40000-1-2 clause 6) |
| BB-SCP-006 | Product Cybersecurity Plan and Secure Development Lifecycle | Annex VII points 1 and 2a, the security lifecycle (prEN 40000-1-2 clause 7) |
| BB-VVR-007 | Cybersecurity Verification and Validation Report | Annex VII point 5, test reports (prEN 40000-1-2 clause 7.6) |
| BB-VMP-008 | Vulnerability Handling, Monitoring and Secure Update Distribution | Annex VII point 2b, Annex I Part II (prEN 40000-1-2 clause 7.8, prEN 40000-1-3) |
| BULBBEE-CRA-GAPKEY | Assessor gap key | The trainer's answer key, per-claim divergences |

Annex VII technical documentation is not satisfied by the declaration set alone. The content items of Annex VII (general description, design and development, vulnerability handling and SBOM, production and distribution, risk assessment, standards applied, test reports, DoC) apply to a default-category product, and Module A (Annex VIII point 2) requires the manufacturer to establish them. This dossier maps those items as follows. BB-TD-000 is the Annex VII master index and holds the full map, and the risk assessment, secure development lifecycle, test reports and vulnerability handling are the BB-RMR-005, BB-SCP-006, BB-VVR-007 and BB-VMP-008 documents added for exactly this reason.

| Annex VII item | Document |
|----------------|----------|
| (1) General description | BB-RMR-005 s.6.2, BB-SCP-006 s.1, BB-UM-004 |
| (2a) Design and development (secure development lifecycle) | BB-SCP-006 sections 3-7 |
| (2b) Vulnerability handling and SBOM | BB-VMP-008, BB-SBOM-003 |
| (2) Production and distribution | BB-SCP-006 s.8, BB-VMP-008 s.5 |
| (3) Cybersecurity risk assessment | BB-RMR-005 |
| (4) Harmonised standards applied | BB-TD-000 s.3 |
| (5) Test reports | BB-VVR-007 |
| (6) EU Declaration of Conformity | BB-DOC-001 |
| (7) SBOM | BB-SBOM-003 |
| Annex II user information | BB-UM-004 |

The default route makes this set lighter in depth and removes the notified body, it does not remove the Annex VII items.

## 4. Framing: how the intentional vulnerabilities live inside the dossier

BulbBee is deliberately non-conformant. The dossier is a plausible, internally consistent, professionally written manufacturer submission whose claims diverge from the product in ways the assessor discovers by testing the live device against the paperwork. This mirrors real conformity assessment: the assessor verifies, they do not trust.

Two mechanisms produce the divergences:

- **Claimed-but-absent controls.** BB-ERM-002 asserts controls the device contradicts. Example: it claims onboarding uses per-device credentials and encrypted transport, while the device derives the pairing PIN from the enumerable serial (predictable, not a secret) over an unbonded, unencrypted BLE link (BULB-01, BULB-03).
- **Under-treated risk / optimistic self-declaration.** The EU DoC (BB-DOC-001) self-declares conformity with the Annex I essential requirements, which the finding catalogue shows is false, exactly the kind of over-confident Module A self-assessment a market-surveillance authority would challenge.

The assessor gap key (`99-Assessor-Gap-Key.md`) tags each divergence to the finding that disproves it, so the trainer has an answer key.

## 5. SBOM (BB-SBOM-003)

Generated, not hand-authored, from the bulbbee image package selection (`src/labs/vulnzoo/.config` plus the on-device Python runtime and `dbus-fast`), in CycloneDX JSON. Base platform: OpenWRT 24.10, Python 3.11+, BlueZ, dbus-fast. Confirm actual versions on the built image before pinning. This mirrors RoutCoon's SBOM approach (`../../RoutCoon/CRA/RC-SBOM-007.cdx.json`).

## 6. Conventions

- Location `src/docs/BulbBee/CRA/`, one file per document, English, MWP prose style (one physical line per paragraph, no semicolons in prose, plain hyphens and straight quotes).
- Every Annex I requirement and EN 303 645 provision appears verbatim in BB-ERM-002 so an assessor can grep by requirement.
