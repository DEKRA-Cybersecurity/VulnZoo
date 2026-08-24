---
id: RC-TD-000
title: RoutCoon Technical Documentation and Conformity Dossier (CRA Annex VII)
category: Compliance
status: DONE
standard: prEN 40000-1-2 clause 7.5d
related_standards: [prEN 40000-1-3 (Vulnerability Handling)]
cra_annex: Annex VII
covers_checklist_rows: [16]
requirement_ids: []
version: 1.0
date: 2026-08-21
owner: RoutCoon Networks - Product Security
approver: RoutCoon Networks - Head of Engineering
---

# RC-TD-000 Technical Documentation and Conformity Dossier

## Document control

| Field | Value |
|-------|-------|
| Document ID | RC-TD-000 |
| Standard clause | prEN 40000-1-2, 7.5d (CRA Annex VII) |
| Product | RoutCoon Home/Office WiFi Router, firmware 1.0 on OpenWrt 24.10.3 |
| Manufacturer | RoutCoon Networks (fictional), contact@routcoon-oem.local |
| Owner | Product Security |
| Approver | Head of Engineering |

## 1. Purpose

This document is the master technical documentation and conformity dossier for the RoutCoon router, prepared as required by CRA Annex VII and prEN 40000-1-2 clause 7.5d. It is the entry point of the dossier. It maps the CRA Annex VII content to the supporting documents, records the standards applied, and holds the traceability matrix from every prEN 40000-1-2 requirement to the document and section that satisfies it.

## 2. CRA Annex VII content map

| Annex VII item | Content | Document |
|----------------|---------|----------|
| (1) General description | Intended purpose, versions, operation, users, user information | RC-RMR-001 s.6.2, RC-UM-013 |
| (2a) Design and development | Architecture, design, secure development environment | RC-SAD-004, RC-SRS-003, RC-SDE-005 |
| (2b) Vulnerability handling and SBOM | Monitoring, disclosure and issue handling, SBOM | RC-VMP-010, RC-SBOM-007, prEN 40000-1-3 |
| (2) Production and distribution | Secure production and distribution | RC-SDD-009 |
| (3) Cybersecurity risk assessment | Assets, threats, analysis, evaluation, treatment | RC-RMR-001 |
| (4) Harmonised standards applied | See section 3 | this document s.3 |
| (5) Test reports | Verification and validation results | RC-VVR-008 |
| (6) EU Declaration of Conformity | Signed DoC | provided with the product, see section 4 |
| (7) SBOM | Machine-readable bill of materials | RC-SBOM-007 |
| Component list | Integrated components including hardware | RC-CBL-006 |
| Third-party due diligence | Selection and integration due diligence | RC-TPD-012 |
| Decommissioning | Secure decommissioning and user instructions | RC-DEC-011 |
| Cybersecurity plan | Living plan tracking all activities | RC-SCP-002 |

## 3. Standards applied

- prEN 40000-1-2 (Cybersecurity requirements for products with digital elements, Part 1-2: Principles, product risk management, and lifecycle activities). Applied in full, see the traceability matrix in section 5.
- prEN 40000-1-3 (Part 1-3: Vulnerability Handling). Applied for the vulnerability handling and SBOM activities referenced from RC-VMP-010 and RC-SBOM-007.

## 4. EU Declaration of Conformity

The EU Declaration of Conformity for the RoutCoon router is issued by the manufacturer and provided with the product. It references this technical documentation and the standards in section 3. A signed copy is held in the manufacturer's conformity records.

## 5. Traceability matrix (checklist column E)

This matrix is the completed content of column "Document name / Section" of the evaluator checklist `CRA_prEN40000-1-2_sample.xlsx`. Each row maps a checklist deliverable to the document and section that satisfies it and to the normative requirement identifiers.

| #   | Clause | Deliverable                                         | Document / Section                 | Requirement IDs            |
| --- | ------ | --------------------------------------------------- | ---------------------------------- | -------------------------- |
| 1   | 6.2    | Product Context                                     | RC-RMR-001 s.6.2                   | RMA-01-RQ-01, RMA-01-RQ-02 |
| 2   | 6.3    | Risk Acceptance Criteria                            | RC-RMR-001 s.6.3                   | RMA-02-RQ-01               |
| 3   | 6.4.2  | Asset Identification                                | RC-RMR-001 s.6.4.2                 | RMA-03-RQ-01               |
| 4   | 6.4.3  | Threat Identification                               | RC-RMR-001 s.6.4.3                 | RMA-04-RQ-01               |
| 5   | 6.4.4  | Risk Analysis                                       | RC-RMR-001 s.6.4.4                 | RMA-05-RQ-01..03           |
| 6   | 6.4.5  | Risk Evaluation and Acceptance                      | RC-RMR-001 s.6.4.5                 | RMA-06-RQ-01..04           |
| 7   | 6.5    | Risk Treatment                                      | RC-RMR-001 s.6.5                   | RMA-07-RQ-01..03           |
| 8   | 6.6    | Risk Communication                                  | RC-RMR-001 s.6.6 and RC-UM-013 s.5 | RMA-08-RQ-01..03           |
| 9   | 6.7    | Risk Review                                         | RC-RMR-001 s.6.7                   | RMA-09-RQ-01..03           |
| 10  | 7.2    | Product Cybersecurity Plan                          | RC-SCP-002                         | CLA-01-RQ-01..02           |
| 11  | 7.3    | Cybersecurity Requirements                          | RC-SRS-003                         | CLA-02-RQ-01..02           |
| 12  | 7.4    | Architecture and Design                             | RC-SAD-004                         | CLA-03-RQ-01..02           |
| 13  | 7.5a   | Secure Development Environment                      | RC-SDE-005                         | CLA-04-RQ-01..07           |
| 14  | 7.5b   | Component List                                      | RC-CBL-006                         | annex                      |
| 15  | 7.5c   | SBOM                                                | RC-SBOM-007.cdx.json               | annex                      |
| 16  | 7.5d   | Technical Documentation (Annex VII)                 | RC-TD-000                          | annex                      |
| 17  | 7.5e   | Information and Instructions to the User (Annex II) | RC-UM-013                          | annex                      |
| 18  | 7.5f   | Third-Party Integration Confirmation                | RC-TPD-012 s.4                     | annex                      |
| 19  | 7.6    | Verification and Validation                         | RC-VVR-008                         | CLA-05-RQ-01..06           |
| 20  | 7.7a   | Secure Software Distribution                        | RC-SDD-009 s.2                     | CLA-06-RQ-01..04           |
| 21  | 7.7b   | Accessible User Documentation Channel               | RC-SDD-009 s.3                     | annex                      |
| 22  | 7.7c   | Secure Physical Production                          | RC-SDD-009 s.4                     | CLA-07-RQ-01..02           |
| 23  | 7.8a   | Monitoring Intervals Justification                  | RC-VMP-010 s.2                     | CLA-08-RQ-01..05           |
| 24  | 7.8b   | Incident / Vulnerability Treatment                  | RC-VMP-010 s.4                     | annex                      |
| 25  | 7.9a   | Secure Decommissioning Plan                         | RC-DEC-011 s.2                     | CLA-09-RQ-01..02           |
| 27  | 7.9b   | Decommissioning Instructions to the User            | RC-DEC-011 s.3 and RC-UM-013 s.7   | annex                      |
| 28  | 7.10   | Third-Party Due Diligence                           | RC-TPD-012 s.3                     | CLA-10-RQ-01..05           |

## 6. Consistency statement

The technical documentation has been reviewed for consistency and appropriateness across the documents referenced above. All 58 normative requirements of prEN 40000-1-2 (21 RMA and 37 CLA) are cited in the section that satisfies them and are traceable by requirement identifier.
