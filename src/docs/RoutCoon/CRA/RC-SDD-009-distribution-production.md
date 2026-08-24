---
id: RC-SDD-009
title: RoutCoon Secure Distribution and Production Evidence
category: Compliance
status: DONE
standard: prEN 40000-1-2 clause 7.7 (7.7a, 7.7b, 7.7c)
cra_annex: Annex VII
covers_checklist_rows: [20, 21, 22]
requirement_ids: [CLA-06-RQ-01, CLA-06-RQ-02, CLA-06-RQ-03, CLA-06-RQ-04, CLA-07-RQ-01, CLA-07-RQ-02]
version: 1.0
date: 2026-08-21
owner: RoutCoon Networks - Operations
approver: RoutCoon Networks - Head of Engineering
---

# RC-SDD-009 Secure Distribution and Production Evidence

## Document control

| Field | Value |
|-------|-------|
| Document ID | RC-SDD-009 |
| Title | RoutCoon Secure Distribution and Production Evidence |
| Version | 1.0 |
| Date | 2026-08-21 |
| Standard clause | prEN 40000-1-2, 7.7a / 7.7b / 7.7c (CLA-06, CLA-07) |
| Related deliverables | RC-UM-013, RC-SDE-005, RC-VMP-010 |
| Owner | Operations |
| Approver | Head of Engineering |

## 1. Purpose

This document records the measures that protect the RoutCoon software during production and distribution, the protection and accessibility of the user documentation channel, and the protection of the physical product during manufacturing, as required by prEN 40000-1-2 clauses 7.7a, 7.7b, and 7.7c.

## 2. Secure software distribution (Distribution) (CLA-06-RQ-01, CLA-06-RQ-02)

Firmware images and software updates are protected from manipulation in transit and at rest (CLA-06-RQ-01). The distribution measures include (CLA-06-RQ-02):

- **Authentication to the hosting platform.** Upload and management of distribution artifacts on the OEM hosting platform require authenticated, role-restricted access.
- **Integrity in transit and at rest.** Distribution artifacts are transferred over an authenticated channel and are stored with an integrity checksum that is validated before an artifact is served.
- **Authenticity of artifacts.** Each firmware image and package is signed by the release pipeline using the signing keys managed under RC-SDE-005, and the signature is the basis for authenticity verification on the device.

## 3. Accessible user documentation channel (Channel) (CLA-06-RQ-03, CLA-06-RQ-04)

The information and instructions for the user are protected during distribution, including the communication channel that delivers them (CLA-06-RQ-03). The channel is made available in an accessible manner (CLA-06-RQ-04): the user documentation RC-UM-013 is provided with the product and is available in a printable and screen-reader-friendly format. Update notifications and security advisories are delivered through the same channel.

## 4. Secure physical production (Production) (CLA-07-RQ-01, CLA-07-RQ-02)

The risks of the hardware product being manipulated or altered by unauthorised actors during the manufacturing process are addressed (CLA-07-RQ-01). The production measures, appropriate to the risk assessment and product context, include (CLA-07-RQ-02):

- Protection of the confidentiality, authenticity, and integrity of work instructions provided to production operators.
- Verification of the expected product components and their associated firmware, software, or data at assembly.
- Protection of the confidentiality, authenticity, and integrity of software, data, and configuration installed on or transmitted to and from the manufacturing environment.

## 5. Maintenance

The distribution and production measures are reviewed under the cadence in RC-VMP-010 and updated when the hosting platform, the signing process, or the manufacturing process changes.
