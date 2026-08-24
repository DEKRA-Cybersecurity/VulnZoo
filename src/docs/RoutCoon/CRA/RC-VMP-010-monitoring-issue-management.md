---
id: RC-VMP-010
title: RoutCoon Vulnerability Monitoring and Issue Management
category: Compliance
status: DONE
standard: prEN 40000-1-2 clause 7.8 (7.8a, 7.8b)
related_standards: [prEN 40000-1-3 (Vulnerability Handling)]
cra_annex: Annex VII
covers_checklist_rows: [23, 24]
requirement_ids: [CLA-08-RQ-01, CLA-08-RQ-02, CLA-08-RQ-03, CLA-08-RQ-04, CLA-08-RQ-05]
version: 1.0
date: 2026-08-21
owner: RoutCoon Networks - PSIRT
approver: RoutCoon Networks - Head of Engineering
---

# RC-VMP-010 Vulnerability Monitoring and Issue Management

## Document control

| Field | Value |
|-------|-------|
| Document ID | RC-VMP-010 |
| Title | RoutCoon Vulnerability Monitoring and Issue Management |
| Version | 1.0 |
| Date | 2026-08-21 |
| Standard clause | prEN 40000-1-2, 7.8a / 7.8b (CLA-08) |
| Related deliverables | RC-RMR-001, RC-TPD-012, RC-UM-013 |
| Related standard | prEN 40000-1-3 (Vulnerability Handling) |
| Owner | Product Security Incident Response Team (PSIRT) |
| Approver | Head of Engineering |

## 1. Purpose

This document defines how RoutCoon Networks monitors for changes in the product risk assessment, the intervals at which it does so and their justification, and how identified vulnerabilities and incidents are treated. It implements prEN 40000-1-2 clause 7.8, and the vulnerability handling activities follow prEN 40000-1-3.

## 2. Monitoring intervals and justification (CLA-08-RQ-01)

The manufacturer monitors for changes in the product risk assessment (RC-RMR-001 section 6.4), including new incidents and vulnerabilities, at the intervals below. The intervals are justified for the product context.

| Monitoring activity | Interval | Justification |
|---------------------|----------|---------------|
| Advisory and CVE feeds for integrated components (OpenWrt, Linux, Samba, dnsmasq, and others in RC-CBL-006) | Continuous, triaged daily | The product is built on FOSS with active vulnerability feeds, and a router is an internet-adjacent device where delay increases exposure |
| Consolidated risk-assessment review | Monthly | Balances timely detection against the change rate of a stable firmware baseline |
| Full risk management review | Per release and on trigger events | Aligns the review with the points at which the product context or design changes |

Trigger events that force an out-of-cycle review are a product modification affecting cybersecurity, a change in the product context, a newly disclosed vulnerability in an integrated component, a severe cybersecurity incident, and component obsolescence.

## 3. Incident intake and verification (CLA-08-RQ-02)

Reports arrive through the PSIRT contact published in RC-UM-013 and through the monitored feeds. Each report is logged, triaged, and verified before treatment. Verification determines whether the report affects the product and estimates its risk against RC-RMR-001 section 6.4.

## 4. Vulnerability and incident treatment (CLA-08-RQ-03, CLA-08-RQ-04)

Discovered vulnerabilities are assessed and addressed in line with RC-RMR-001 sections 6.4 and 6.6 (CLA-08-RQ-03). Verified cybersecurity incidents are addressed without undue delay, appropriate to the risk assessment and product context (CLA-08-RQ-04). The issue register below is the evidence of the activities undertaken.

| Issue | Source | Risk | Action | Status |
|-------|--------|------|--------|--------|
| ISS-01 SMB anonymous write | Internal review, RC-RMR-001 T-06 | Medium | Share set read-only, authentication required for write | Planned for 1.1 |
| ISS-02 Update authenticity | Internal review, T-08 | High | Signature verification before processing, remove auto-execution | Planned for 1.1 |
| ISS-03 Tools SSRF | Internal review, T-10 | Medium | Scheme and host allowlist | Planned for 1.1 |
| ISS-04 Diagnostic command injection | Internal review, T-11 | High | Safe argument passing and input validation | Planned for 1.1 |
| ISS-05 Authentication hardening | Internal review, T-12 | Critical | Rate limiting, lockout, strong tokens, current-password check | Planned for 1.1 |
| ISS-06 Function-level authorisation | Internal review, T-13 | Critical | Authenticated and authorised session on all privileged handlers | Planned for 1.1 |

## 5. Residual risk communication (CLA-08-RQ-05)

Relevant residual risk that results from a cybersecurity incident is communicated to users in alignment with RC-RMR-001 section 6.6, through the user documentation and advisory channel in RC-UM-013.

## 6. Third-party component monitoring

Monitoring of third-party components over their lifecycle is performed as part of this activity and is recorded against each component in RC-TPD-012.
