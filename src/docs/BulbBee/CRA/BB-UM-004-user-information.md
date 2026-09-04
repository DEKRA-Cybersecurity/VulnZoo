---
id: BB-UM-004
title: BulbBee Information and Instructions to the User (CRA Annex II)
category: Compliance
status: DONE
severity: N/A
affected_components: [bulbbee]
regulation: EU Cyber Resilience Act (Regulation (EU) 2024/2847) Annex II
version: 1.0
date: 2026-09-04
owner: BulbBee manufacturer (fictional)
---

# Information and Instructions to the User

The CRA Annex II items a manufacturer must provide with the product. Fictional, and, like the rest of the dossier, some statements are contradicted by the device (flagged for the assessor).

- **Manufacturer contact / single point of contact**: `security@bulbbee.example`.
- **Coordinated vulnerability disclosure**: report issues to `security@bulbbee.example`, acknowledged within 72 hours (claim, the assessor verifies the channel resolves and is monitored, EN 303 645 5.2).
- **Intended use and secure setup**: onboard the light with the BulbBee app over Bluetooth, then it joins the home WiFi. *(Assessor note: onboarding is unauthenticated with a hardcoded PIN, BULB-01.)*
- **Security update policy**: automatic updates for a declared support period ending 2031-09. *(Assessor note: updates are unsigned, BULB-04.)*
- **Handling of personal data**: the light processes no personal data.
- **Decommissioning / factory reset**: a factory reset clears the stored WiFi and cloud credentials. *(Assessor note: those credentials are stored in cleartext while in use, BULB-05.)*
- **End of support**: after the support period, no security updates are provided, replace the device.

This user document is the Annex II deliverable referenced by the EU Declaration of Conformity (BB-DOC-001). Its claims are cross-checked against the device in the assessor gap key (`99-Assessor-Gap-Key.md`).
