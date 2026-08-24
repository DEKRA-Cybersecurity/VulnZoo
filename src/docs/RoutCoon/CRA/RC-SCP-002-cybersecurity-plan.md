---
id: RC-SCP-002
title: RoutCoon Product Cybersecurity Plan
category: Compliance
status: DONE
standard: prEN 40000-1-2 clause 7.2
cra_annex: Annex VII
covers_checklist_rows: [10]
requirement_ids: [CLA-01-RQ-01, CLA-01-RQ-02]
version: 1.0
date: 2026-08-21
owner: RoutCoon Networks - Product Security
approver: RoutCoon Networks - Head of Engineering
---

# RC-SCP-002 Product Cybersecurity Plan

## Document control

| Field | Value |
|-------|-------|
| Document ID | RC-SCP-002 |
| Title | RoutCoon Product Cybersecurity Plan |
| Version | 1.0 |
| Date | 2026-08-21 |
| Standard clause | prEN 40000-1-2, 7.2 (CLA-01) |
| Related deliverables | all RC-* documents |
| Owner | Product Security |
| Approver | Head of Engineering |

## 1. Purpose

This plan is the living document that covers the applicable product cybersecurity activities from Clauses 6 and 7 of prEN 40000-1-2 for the RoutCoon router, as required by clause 7.2. It records the activities, their deliverables, their owners, their cadence, and their execution status across the product lifecycle.

## 2. Planned activities (CLA-01-RQ-01)

The plan covers at least the applicable activities of Clauses 6 and 7. Each activity maps to a deliverable and an owner.

| Activity | Clause | Deliverable | Owner | Cadence | Status |
|----------|--------|-------------|-------|---------|--------|
| Risk management | 6.2-6.7 | RC-RMR-001 | Product Security | On change and at review interval | Complete v1.0 |
| Requirements | 7.3 | RC-SRS-003 | Product Security | On risk change | Complete v1.0 |
| Architecture and design | 7.4 | RC-SAD-004 | Engineering | On design change | Complete v1.0 |
| Secure implementation and dev environment | 7.5a | RC-SDE-005 | Engineering | Continuous | Complete v1.0 |
| Component list | 7.5b | RC-CBL-006 | Engineering | On build change | Complete v1.0 |
| SBOM | 7.5c | RC-SBOM-007 | Engineering | Per build | Complete v1.0 |
| Technical documentation | 7.5d | RC-TD-000 | Product Security | Per release | In progress |
| User information | 7.5e | RC-UM-013 | Product Security | Per release | Planned |
| Verification and validation | 7.6 | RC-VVR-008 | QA | Per release and recurring | Complete v1.0 |
| Distribution and production | 7.7 | RC-SDD-009 | Operations | Continuous | Complete v1.0 |
| Monitoring and issue management | 7.8 | RC-VMP-010 | PSIRT | Continuous, monthly review | Complete v1.0 |
| Decommissioning | 7.9 | RC-DEC-011 | Product Security | Per lifecycle stage | Complete v1.0 |
| Third-party due diligence | 7.10 | RC-TPD-012 | Engineering | On selection and continuous | Complete v1.0 |

## 3. Execution tracking (CLA-01-RQ-02)

For the complete product lifecycle, the execution of each activity is tracked. Tracking is maintained in the Status column above and in each deliverable's document control block, which records the version, date, and revision history. Changes to an activity's status are recorded when the deliverable is revised. The plan is reviewed at the interval defined in RC-VMP-010 and on the trigger events listed there.

## 4. Maintenance

This plan is a living document. It is updated when an activity, deliverable, owner, or cadence changes, and when a new activity becomes applicable. The review cadence and triggers are governed by RC-VMP-010.
