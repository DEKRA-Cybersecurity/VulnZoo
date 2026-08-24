---
id: RC-SDE-005
title: RoutCoon Secure Development Environment and Implementation Evidence
category: Compliance
status: DONE
standard: prEN 40000-1-2 clause 7.5a
cra_annex: Annex VII
covers_checklist_rows: [13]
requirement_ids: [CLA-04-RQ-01, CLA-04-RQ-02, CLA-04-RQ-03, CLA-04-RQ-04, CLA-04-RQ-05, CLA-04-RQ-06, CLA-04-RQ-07]
version: 1.0
date: 2026-08-21
owner: RoutCoon Networks - Engineering
approver: RoutCoon Networks - Head of Engineering
---

# RC-SDE-005 Secure Development Environment and Implementation Evidence

## Document control

| Field | Value |
|-------|-------|
| Document ID | RC-SDE-005 |
| Title | RoutCoon Secure Development Environment and Implementation Evidence |
| Version | 1.0 |
| Date | 2026-08-21 |
| Standard clause | prEN 40000-1-2, 7.5a (CLA-04) |
| Related deliverables | RC-SRS-003, RC-SAD-004, RC-CBL-006, RC-SBOM-007, RC-TD-000, RC-UM-013, RC-VVR-008 |
| Owner | Engineering |
| Approver | Head of Engineering |

## 1. Purpose

This document provides evidence for the secure implementation activities of prEN 40000-1-2 clause 7.5. It demonstrates how the development and maintenance environment protects the product from unauthorised changes, and it records where the remaining 7.5 outputs are delivered.

## 2. Secure development and maintenance environment (CLA-04-RQ-01)

The development and maintenance environment protects the product from unauthorised change through the following measures.

- **Access control.** Source, build, and release systems require individual named accounts with multi-factor authentication and least-privilege role assignment. Access is reviewed quarterly and revoked on role change.
- **Source integrity.** The source repository enforces protected branches, mandatory peer review before merge, and signed commits for release branches.
- **Cryptographic key management.** Firmware and package signing keys are held in a hardware-backed key store. Signing is restricted to the release pipeline and to named release engineers. Keys are rotated on a defined schedule and on suspected compromise.
- **Build and tool security.** Builds run on a controlled build host from pinned tool versions. The OpenWrt build tree and feeds are fixed to the 24.10.3 baseline. Build inputs are integrity-checked against the component list.
- **Change traceability.** Every change is traceable from a tracked work item through review to the released artifact.

## 3. Implementation of requirements (CLA-04-RQ-02)

The cybersecurity requirements in RC-SRS-003, as realised by the architecture and design in RC-SAD-004, are implemented in the product. The verification that each requirement is fulfilled is reported in RC-VVR-008.

## 4. Related 7.5 outputs

The remaining outputs of clause 7.5 are delivered as follows and are cross-referenced here for completeness.

| Output | Requirement | Delivered in |
|--------|-------------|--------------|
| Component list | CLA-04-RQ-03 | RC-CBL-006 |
| SBOM | CLA-04-RQ-04 | RC-SBOM-007 |
| Technical documentation | CLA-04-RQ-05 | RC-TD-000 |
| Information and instructions to the user | CLA-04-RQ-06 | RC-UM-013 |

## 5. Deviation handling (CLA-04-RQ-07)

If the secure implementation activities result in a deviation from the architecture and design in RC-SAD-004, a review of the risk management activities (RC-RMR-001 section 6.7) and of the impacted lifecycle activities is triggered. The trigger, the review, and any resulting documentation update are recorded in RC-VMP-010 and in the affected document control blocks.
