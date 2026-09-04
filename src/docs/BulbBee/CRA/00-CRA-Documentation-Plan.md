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
version: 1.0
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

Contrast with RoutCoon (important, Annex III): a router must, at minimum, apply harmonised standards or undergo a third-party route, and its dossier (prEN 40000-1-2, 14 documents) is correspondingly heavier. BulbBee's dossier is intentionally small, which is exactly what the default route allows. That difference is the lesson.

## 3. Document set

The default route needs a controlled, compact set. All documents live in `src/docs/BulbBee/CRA/`, English, MWP prose style, with a document-control block.

| Doc ID | Title | Role |
|--------|-------|------|
| BULBBEE-CRA-PLAN | This plan | Umbrella, route, document set, traceability, gap framing |
| BB-DOC-001 | EU Declaration of Conformity | Annex V self-declared DoC |
| BB-ERM-002 | Annex I Essential-Requirements Mapping | Requirement -> claim -> EN 303 645 -> device ground truth -> finding |
| BB-SBOM-003 | Software Bill of Materials | Generated (CycloneDX) from the bulbbee image package list, see section 5 |
| BB-UM-004 | Information and Instructions to the User (Annex II) | Security-relevant user information, disclosure channel, end-of-support |
| BULBBEE-CRA-GAPKEY | Assessor gap key | The trainer's answer key, per-claim divergences |

Annex VII technical documentation, for a default product, is satisfied by this set taken together (the plan is the index, BB-ERM-002 is the requirements evidence, BB-SBOM-003 the component inventory, BB-UM-004 the user information). No separate heavyweight technical file is required on this route.

## 4. Framing: how the intentional vulnerabilities live inside the dossier

BulbBee is deliberately non-conformant. The dossier is a plausible, internally consistent, professionally written manufacturer submission whose claims diverge from the product in ways the assessor discovers by testing the live device against the paperwork. This mirrors real conformity assessment: the assessor verifies, they do not trust.

Two mechanisms produce the divergences:

- **Claimed-but-absent controls.** BB-ERM-002 asserts controls the device contradicts. Example: it claims onboarding uses per-device credentials and encrypted transport, while the device ships a hardcoded pairing PIN over an unbonded, unencrypted BLE link (BULB-01, BULB-03).
- **Under-treated risk / optimistic self-declaration.** The EU DoC (BB-DOC-001) self-declares conformity with the Annex I essential requirements, which the finding catalogue shows is false, exactly the kind of over-confident Module A self-assessment a market-surveillance authority would challenge.

The assessor gap key (`99-Assessor-Gap-Key.md`) tags each divergence to the finding that disproves it, so the trainer has an answer key.

## 5. SBOM (BB-SBOM-003)

Generated, not hand-authored, from the bulbbee image package selection (`src/labs/vulnzoo/.config` plus the on-device Python runtime and `dbus-fast`), in CycloneDX JSON. Base platform: OpenWRT 24.10, Python 3.11+, BlueZ, dbus-fast. Confirm actual versions on the built image before pinning. This mirrors RoutCoon's SBOM approach (`../../RoutCoon/CRA/RC-SBOM-007.cdx.json`).

## 6. Conventions

- Location `src/docs/BulbBee/CRA/`, one file per document, English, MWP prose style (one physical line per paragraph, no semicolons in prose, plain hyphens and straight quotes).
- Every Annex I requirement and EN 303 645 provision appears verbatim in BB-ERM-002 so an assessor can grep by requirement.
