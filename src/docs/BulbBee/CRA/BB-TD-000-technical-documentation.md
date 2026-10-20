---
id: BB-TD-000
title: BulbBee Technical Documentation and Conformity Dossier
category: Compliance
status: DONE
standard: prEN 40000-1-2 clause 7.5d
related_standards: [prEN 40000-1-3 (Vulnerability Handling), ETSI EN 303 645]
cra_annex: Annex VII
affected_components: [bulbbee]
regulation: EU Cyber Resilience Act (Regulation (EU) 2024/2847) Annex VII, Annex VIII Module A
version: 1.0
date: 2026-10-20
owner: BulbBee Home Ltd (fictional) - Product Security
approver: BulbBee Home Ltd (fictional) - Head of Engineering
---

# BB-TD-000 Technical Documentation and Conformity Dossier

## Document control

| Field | Value |
|-------|-------|
| Document ID | BB-TD-000 |
| Title | BulbBee Technical Documentation and Conformity Dossier |
| Version | 1.0 |
| Date | 2026-10-20 |
| Product | BulbBee smart light, model BB-100, firmware 1.0 on OpenWRT 24.10 |
| Manufacturer | BulbBee Home Ltd (fictional), security@bulbbee.example |
| Conformity route | Module A, internal control (CRA Annex VIII), no notified body |
| Owner | Product Security |
| Approver | Head of Engineering |

## 1. Purpose

This document is the master technical documentation and conformity dossier for the BulbBee smart light, prepared as required by CRA Annex VII and following prEN 40000-1-2 clause 7.5d. It is the assessor's entry point. It maps the CRA Annex VII content to the supporting documents, records the standards applied, references the EU Declaration of Conformity, and holds the dossier-wide traceability table.

BulbBee is a default-category product assessed under Module A (internal control, Annex VIII), so no notified body is involved and the manufacturer draws up this technical documentation on its own responsibility. The default category sets the conformity route, not the content of this documentation: the Annex VII items below apply to the product regardless of category, and Annex VIII point 2 (Module A) requires the manufacturer to establish them.

> **Assessor note (training).** This dossier self-declares that the technical documentation is complete and consistent and that the product meets the Annex I essential requirements. The delivered device contradicts the essential-requirements claim on every theme (BB-ERM-002) and the per-document claims are contradicted finding by finding. The answer key is `99-Assessor-Gap-Key.md`. This is exactly the unverified Module A self-declaration a market-surveillance authority would disprove.

## 2. CRA Annex VII content map

| Annex VII item | Content | Document |
|----------------|---------|----------|
| (1) General description | Intended purpose, versions, operation, users | BB-RMR-005 s.6.2, BB-SCP-006 s.1, BB-UM-004 |
| (2a) Design and development | Requirements, architecture, secure development environment | BB-SCP-006 sections 3-7 |
| (2b) Vulnerability handling and SBOM | Monitoring, disclosure and issue handling, secure update distribution, SBOM | BB-VMP-008, BB-SBOM-003, prEN 40000-1-3 |
| (2) Production and distribution | Secure physical production, secure update distribution | BB-SCP-006 s.8, BB-VMP-008 s.5 |
| (3) Cybersecurity risk assessment | Assets, threats, analysis, evaluation, treatment | BB-RMR-005 |
| (4) Harmonised standards applied | See section 3 | this document s.3 |
| (5) Test reports | Verification and validation results | BB-VVR-007 |
| (6) EU Declaration of Conformity | Signed DoC | BB-DOC-001 |
| (7) SBOM | Machine-readable bill of materials | BB-SBOM-003 |
| Annex I essential-requirements mapping | Requirement to claim to EN 303 645 to device ground truth | BB-ERM-002 |
| Annex II user information | Information and instructions to the user | BB-UM-004 |

Every Annex VII item is mapped to a document that exists in this dossier. No item is left unmapped.

## 3. Standards applied

- Regulation (EU) 2024/2847 (Cyber Resilience Act), the essential cybersecurity requirements of Annex I Parts I and II, Module A conformity (Annex VIII), the technical documentation contents (Annex VII), the DoC contents (Annex V) and the user information (Annex II).
- ETSI EN 303 645 (consumer IoT baseline), the presumption-of-conformity yardstick for the Annex I Part I essential requirements, applied in BB-ERM-002.
- prEN 40000-1-2 (Principles, product risk management, and lifecycle activities), the method for the risk management (BB-RMR-005) and the lifecycle activities (BB-SCP-006, BB-VVR-007), applied proportionately for a Module A default product.
- prEN 40000-1-3 (Vulnerability Handling), the method for the vulnerability handling and SBOM activities (BB-VMP-008, BB-SBOM-003).

## 4. EU Declaration of Conformity

The EU Declaration of Conformity for the BulbBee smart light is BB-DOC-001. It is issued under the sole responsibility of the manufacturer, references this technical documentation and the standards in section 3, and supports the CE marking affixed on the manufacturer's own responsibility.

## 5. Dossier traceability

| Document | Role | CRA basis | Standard clause |
|----------|------|-----------|-----------------|
| BB-TD-000 | Technical documentation master and conformity dossier | Annex VII points 4, 6 | prEN 40000-1-2 7.5d |
| BB-DOC-001 | EU Declaration of Conformity | Annex V, Annex VIII Module A | - |
| BB-ERM-002 | Annex I essential-requirements mapping | Annex I Parts I and II | EN 303 645 |
| BB-SBOM-003 | Software Bill of Materials | Annex I Part II point 1, Annex VII point 7 | prEN 40000-1-3 |
| BB-UM-004 | Information and instructions to the user | Annex II | prEN 40000-1-2 7.5e |
| BB-RMR-005 | Risk management report | Article 13, Annex VII point 3 | prEN 40000-1-2 clause 6 |
| BB-SCP-006 | Cybersecurity plan and secure development lifecycle | Annex VII points 1, 2a, production | prEN 40000-1-2 7.2-7.5a, 7.7c |
| BB-VVR-007 | Verification and validation report | Annex VII point 5 | prEN 40000-1-2 7.6 |
| BB-VMP-008 | Vulnerability handling, monitoring and update distribution | Annex I Part II, Annex VII point 2b | prEN 40000-1-2 7.8, prEN 40000-1-3 |

## 6. Consistency statement

The technical documentation has been reviewed for consistency across the documents above. Every Annex VII item in section 2 is mapped to a document, every document in section 5 cites its CRA and standard basis, and the cross-references between documents resolve. The essential-requirements position is stated honestly in BB-ERM-002, and the divergences between the manufacturer claims and the delivered device are catalogued in `99-Assessor-Gap-Key.md`.

## 7. Default versus important (the conformity contrast)

BulbBee reaches CE marking on a self-declared Module A DoC with this proportionate dossier and no notified body. RoutCoon (important, Annex III) carries the heavier prEN 40000-1-2 dossier of 14 documents (`../../RoutCoon/CRA/`). Same regulation, same essential requirements, same Annex VII content obligations, a different assurance route and a different document depth. BulbBee's dossier covers every Annex VII item in a consolidated set proportionate to a single-function light, which is what the default route allows, and the self-declaration that does not hold up on the live device is the market-surveillance risk the default route carries.
