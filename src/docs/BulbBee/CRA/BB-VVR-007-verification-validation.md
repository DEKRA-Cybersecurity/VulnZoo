---
id: BB-VVR-007
title: BulbBee Cybersecurity Verification and Validation Report
category: Compliance
status: DONE
standard: prEN 40000-1-2 clause 7.6
related_standards: [ETSI EN 303 645]
cra_annex: Annex VII point 5
affected_components: [bulbbee]
regulation: EU Cyber Resilience Act (Regulation (EU) 2024/2847) Annex VII point 5
version: 1.0
date: 2026-10-20
owner: BulbBee Home Ltd (fictional) - Quality
approver: BulbBee Home Ltd (fictional) - Head of Engineering
---

# BB-VVR-007 Cybersecurity Verification and Validation Report

## Document control

| Field | Value |
|-------|-------|
| Document ID | BB-VVR-007 |
| Title | BulbBee Cybersecurity Verification and Validation Report |
| Version | 1.0 |
| Date | 2026-10-20 |
| Product | BulbBee smart light, model BB-100, firmware 1.0 |
| Standard clause | prEN 40000-1-2, 7.6 |
| CRA basis | Annex VII point 5 (test reports) |
| Related deliverables | BB-SCP-006, BB-RMR-005, BB-VMP-008 |
| Owner | Quality |
| Approver | Head of Engineering |

## 1. Purpose

This report documents the cybersecurity verification and validation of the BulbBee smart light, as required by CRA Annex VII point 5 and following prEN 40000-1-2 clause 7.6. It records the test methods, the scope, and the verdicts confirming that the controls fulfil the cybersecurity requirements in BB-SCP-006 section 3.

> **Assessor note (training).** This report records the manufacturer's self-declared verdicts against the robust security baseline (BB-SCP-006 section 6). Every requirement is recorded as Pass. The shipped device default does not run that baseline, so the same tests fail on the live device in its default configuration. The assessor reproduces the tests against the delivered device, following the assessor battery in `../README.md`, and finds the contradiction. Each failing requirement maps to a finding in `../Vulns/` and a gap-key row in `99-Assessor-Gap-Key.md`. This all-pass report against a posture the device does not ship is the central V&V gap of the exercise.

## 2. Test methods

The following methods were selected, appropriate to the product design, the risk assessment (BB-RMR-005) and the product context.

- Static configuration review of the firmware image against BB-SCP-006 sections 3 and 4.
- Dynamic testing of the control planes (BLE GATT, the AES-CCM LAN port, the HTTP surface) and of the cloud API.
- BLE pairing and provisioning testing, including an unpaired-central negative test.
- Authentication and authorisation testing of the control surface, including negative tests.
- Update-path testing for payload signature verification.
- Input testing of the scene parser for the LED-count bound.
- Secret-handling review of the provisioning and config reads and the on-disk state file.

## 3. Scope of activities

The activities included, where appropriate to the design and risk: validation of error handling on the control surface, verification of interface and protocol security on each plane, and verification that risks from integrated components (BB-SBOM-003) were addressed in the implemented design.

## 4. Results

Each requirement in BB-SCP-006 section 3 was tested. The verdicts below are recorded against the robust baseline.

| Requirement | Method | Verdict (vs robust baseline) | Device finding if default |
|-------------|--------|------------------------------|---------------------------|
| SR-01 Bonded BLE pairing, non-derivable PIN | BLE pairing test | Pass | BULB-01 |
| SR-02 Per-device session, auth token on control | Dynamic, negative test | Pass | BULB-02 |
| SR-03 Encrypted transport on every plane, nonce | Protocol capture | Pass | BULB-03 |
| SR-04 Signed, verified updates | Update-path test | Pass | BULB-04 |
| SR-05 Protected secret storage, omitted from reads | Configuration review | Pass | BULB-05 |
| SR-06 No production debug interface | Service scan | Pass | BULB-06 |
| SR-07 Bounded scene LED count | Input test | Pass | BULB-07 |
| SR-08 Cloud owner-equals-caller, strong token | Dynamic, negative test | Pass | BULB-CLD |
| SR-09 App without embedded routine or cleartext secrets | APK review | Pass | BULB-APP |
| SR-10 Attack-surface minimisation | Service scan | Pass | 6.3 attack surface |
| SR-11 Owner binding enforced device and cloud | Dynamic, non-owner test | Pass | BULB-P05 |
| SR-12 Security logging without secrets | Log review | Pass | 6.3 state of the art |

All requirements are recorded as fulfilled against the robust baseline. No non-conformities were raised in this cycle.

> **Assessor note (training).** Reproduced against the delivered device in its default configuration, SR-01 through SR-08 and SR-11 fail, as the assessor battery in `../README.md` demonstrates test by test. The verdicts above hold only when `secure=true`, which is not the shipped default. The V&V was therefore run against a configuration the product does not deliver.

## 5. Recurring basis

Verification and validation is performed on each release and on a scheduled interval between releases as defined in BB-VMP-008. Regression verification is performed after any change to the requirements (BB-SCP-006 section 3), the architecture, or an integrated component in BB-SBOM-003.
