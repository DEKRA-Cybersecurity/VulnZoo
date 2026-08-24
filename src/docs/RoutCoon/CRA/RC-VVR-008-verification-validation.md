---
id: RC-VVR-008
title: RoutCoon Cybersecurity Verification and Validation Report
category: Compliance
status: DONE
standard: prEN 40000-1-2 clause 7.6
cra_annex: Annex VII
covers_checklist_rows: [19]
requirement_ids: [CLA-05-RQ-01, CLA-05-RQ-02, CLA-05-RQ-03, CLA-05-RQ-04, CLA-05-RQ-05, CLA-05-RQ-06]
version: 1.0
date: 2026-08-21
owner: RoutCoon Networks - Quality Assurance
approver: RoutCoon Networks - Head of Engineering
---

# RC-VVR-008 Cybersecurity Verification and Validation Report

## Document control

| Field | Value |
|-------|-------|
| Document ID | RC-VVR-008 |
| Title | RoutCoon Cybersecurity Verification and Validation Report |
| Version | 1.0 |
| Date | 2026-08-21 |
| Standard clause | prEN 40000-1-2, 7.6 (CLA-05) |
| Related deliverables | RC-SRS-003, RC-SAD-004, RC-TPD-012 |
| Owner | Quality Assurance |
| Approver | Head of Engineering |

## 1. Purpose

This report documents the cybersecurity verification and validation (V&V) of the RoutCoon router as required by prEN 40000-1-2 clause 7.6. It records the test methods used, the results confirming that the controls fulfil the requirements, and the validation of error handling, interface and protocol security, and integrated component risks.

## 2. Test methods (CLA-05-RQ-06)

The following test methods were selected for the V&V activities, appropriate to the product design, risk assessment, and context.

- Static configuration review of the firmware image against RC-SRS-003 and RC-SAD-004.
- Dynamic testing of the administration interfaces (web, API, SSH) from the LAN and WiFi segments.
- Network service scanning and service configuration review.
- Authentication and authorisation testing, including negative tests.
- Update-path testing for artifact authenticity and integrity handling.
- Interface and protocol fuzzing of the tool and diagnostic endpoints.

## 3. Scope of activities (CLA-05-RQ-03)

The V&V activities included, where appropriate to the design and risk: validation of error handling, verification of interface and protocol security, and verification that risks from integrated components were addressed in the implemented design (CLA-05-RQ-05).

## 4. Results (CLA-05-RQ-01, CLA-05-RQ-02)

Each requirement in RC-SRS-003 was tested. The verdicts confirm that the controls fulfil the cybersecurity requirements.

| Requirement | Method | Verdict |
|-------------|--------|---------|
| SR-01 Authentication on admin interfaces | Dynamic, negative test | Pass |
| SR-02 First-use credential change | Configuration review | Pass |
| SR-03 Rate limiting and lockout | Dynamic | Pass |
| SR-04 Strong session tokens | Configuration review | Pass |
| SR-05 Current password on change | Dynamic | Pass |
| SR-06 Administration over TLS | Configuration review | Pass |
| SR-07 Wireless protection, no shared default | Configuration review | Pass |
| SR-08 Attack-surface minimisation | Service scan | Pass |
| SR-09 SMB read-only by default | Configuration review | Pass |
| SR-10 UPnP disabled by default | Configuration review | Pass |
| SR-11 SNMP disabled by default | Configuration review | Pass |
| SR-12 Tool input allowlist | Fuzzing | Pass |
| SR-13 Safe diagnostic execution | Fuzzing | Pass |
| SR-14 Function-level authorisation | Dynamic, negative test | Pass |
| SR-15 Update authenticity | Update-path test | Pass |
| SR-16 No auto-execution of staged artifacts | Update-path test | Pass |
| SR-17 Data minimisation | Configuration review | Pass |
| SR-18 Security logging | Configuration review | Pass |
| SR-19 Secure defaults, no undocumented interfaces | Service scan | Pass |
| SR-20 Storage and debug hardening | Configuration review | Pass |

All requirements are recorded as fulfilled. No non-conformities were raised in this cycle.

## 5. Recurring basis (CLA-05-RQ-04)

V&V is performed on a recurring basis: on each release, and on a scheduled interval between releases as defined in RC-VMP-010. Regression V&V is performed after any change to the requirements, architecture, or integrated components.
