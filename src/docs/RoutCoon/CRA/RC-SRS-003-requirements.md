---
id: RC-SRS-003
title: RoutCoon Product Cybersecurity Requirements Specification
category: Compliance
status: DONE
standard: prEN 40000-1-2 clause 7.3
cra_annex: Annex VII
covers_checklist_rows: [11]
requirement_ids: [CLA-02-RQ-01, CLA-02-RQ-02]
version: 1.0
date: 2026-08-21
owner: RoutCoon Networks - Product Security
approver: RoutCoon Networks - Head of Engineering
---

# RC-SRS-003 Product Cybersecurity Requirements Specification

## Document control

| Field | Value |
|-------|-------|
| Document ID | RC-SRS-003 |
| Title | RoutCoon Product Cybersecurity Requirements Specification |
| Version | 1.0 |
| Date | 2026-08-21 |
| Product | RoutCoon Home/Office WiFi Router, firmware 1.0 |
| Standard clause | prEN 40000-1-2, 7.3 (CLA-02) |
| Related deliverables | RC-RMR-001, RC-SAD-004, RC-VVR-008 |
| Owner | Product Security |
| Approver | Head of Engineering |

## 1. Purpose

This document specifies the product cybersecurity requirements for RoutCoon as required by prEN 40000-1-2 clause 7.3. The requirements are the target security behaviour of the product against which the architecture (RC-SAD-004) is designed and the verification and validation (RC-VVR-008) is performed.

## 2. Derivation of requirements (CLA-02-RQ-01)

The requirements are derived from the following inputs, as required by CLA-02-RQ-01.

- **Product context (6.2).** The intended purpose, the operational environment, and the non-expert user profile from RC-RMR-001 section 6.2.
- **Risk assessment (6.4).** The identified threats T-01 to T-15 and their evaluated risk from RC-RMR-001 section 6.4.
- **Risk treatment decisions (6.5).** The treatment decisions from RC-RMR-001 section 6.5.
- **Applicable regulatory requirements.** The essential cybersecurity requirements of the Cyber Resilience Act, and data minimisation under the GDPR for the personal data the device processes (DHCP leases, DNS query records).

## 3. Cybersecurity requirements

Each requirement records the source input and the threat it addresses. The verification of each requirement is reported in RC-VVR-008 under the same identifier.

| ID | Requirement | Source | Threats |
|----|-------------|--------|---------|
| SR-01 | All administration interfaces (web, SSH, API) shall require an authenticated session before any privileged operation | Risk treatment | T-12, T-13 |
| SR-02 | The product shall require the administrator to change the default administration password before the interface becomes usable | Risk treatment, context | T-01 |
| SR-03 | Authentication shall enforce rate limiting and temporary lockout after repeated failures | Risk treatment | T-12, T-14 |
| SR-04 | Session tokens shall be generated with a cryptographically secure random source of sufficient length | Risk treatment | T-12 |
| SR-05 | Changing the administration password shall require the current password | Risk treatment | T-12 |
| SR-06 | The web administration interface shall be served over TLS | Risk assessment | T-02 |
| SR-07 | The wireless network shall use WPA2 or stronger with a user-set passphrase, and shall not ship with a shared default passphrase in use | Risk treatment, context | T-09 |
| SR-08 | The product shall minimise the exposed network services and disable services that are not required for the intended purpose | Context, state of the art | T-04, T-05, T-06 |
| SR-09 | The SMB file share shall be read-only by default and shall require authentication for write access | Risk treatment | T-06 |
| SR-10 | UPnP shall be disabled by default, and when enabled shall run in secure mode | Risk treatment | T-05 |
| SR-11 | SNMP shall be disabled by default, and when enabled shall not use default community strings | Risk treatment | T-04 |
| SR-12 | Network tool endpoints shall validate input against an allowlist of schemes and hosts and shall reject local and file URL schemes | Risk treatment | T-10 |
| SR-13 | Diagnostic functions shall not pass user input to a shell and shall use safe argument passing with input validation | Risk treatment | T-11 |
| SR-14 | All privileged API and web handlers shall enforce an authenticated and authorised session | Risk treatment | T-13 |
| SR-15 | Firmware images and packages shall have their authenticity and integrity verified before installation | Risk assessment | T-07 |
| SR-16 | The product shall not automatically execute artifacts staged over the network without authenticity verification | Risk treatment | T-08 |
| SR-17 | The product shall minimise the retention of DHCP lease and DNS query personal data and shall not expose it without authentication | Regulatory (GDPR) | T-04 |
| SR-18 | The product shall record security-relevant events in a log available to the administrator | Risk assessment | T-14 |
| SR-19 | The product shall ship with a secure default configuration with no anonymous services and no undocumented administrative interfaces | Context, state of the art | T-01, T-03, T-06 |
| SR-20 | The product design shall consider the confidentiality of secrets in storage and shall not expose enabled debug interfaces on production units | Risk assessment | T-15 |

## 4. Maintenance (CLA-02-RQ-02)

These requirements are reviewed and, when necessary, updated when any of the derivation inputs in section 2 change. Such changes include an update to the risk assessment in RC-RMR-001, a change in the product context, a new regulatory obligation, or a change in the integrated components. The review cadence and triggers are governed by RC-VMP-010, and the outcome is recorded in the document control block.
