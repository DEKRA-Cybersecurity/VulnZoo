---
id: RC-DEC-011
title: RoutCoon Secure Decommissioning Plan and User Instructions
category: Compliance
status: DONE
standard: prEN 40000-1-2 clause 7.9 (7.9a, 7.9b)
cra_annex: Annex VII
covers_checklist_rows: [25, 27]
requirement_ids: [CLA-09-RQ-01, CLA-09-RQ-02]
version: 1.0
date: 2026-08-21
owner: RoutCoon Networks - Product Security
approver: RoutCoon Networks - Head of Engineering
---

# RC-DEC-011 Secure Decommissioning Plan and User Instructions

## Document control

| Field | Value |
|-------|-------|
| Document ID | RC-DEC-011 |
| Title | RoutCoon Secure Decommissioning Plan and User Instructions |
| Version | 1.0 |
| Date | 2026-08-21 |
| Standard clause | prEN 40000-1-2, 7.9a / 7.9b (CLA-09) |
| Related deliverables | RC-RMR-001, RC-UM-013 |
| Owner | Product Security |
| Approver | Head of Engineering |

## 1. Purpose

This document sets out the secure decommissioning plan for the RoutCoon router and the decommissioning instructions provided to the user, as required by prEN 40000-1-2 clause 7.9.

## 2. Secure decommissioning plan (CLA-09-RQ-01)

The plan accounts for the following.

- **Cybersecurity considerations for decommissioning.** At end of use, the device holds secrets and personal data that must not persist on a disposed or transferred unit. Decommissioning removes this material before disposal or resale.
- **Confidential assets to be securely deleted and their logical location.** The administrator credentials and session state (UCI configuration and the credential store), the wireless passphrase (wireless configuration), the SSH host and authorized keys (the dropbear key store), the DHCP lease and DNS records (the runtime state on the overlay), the SMB share contents (the share directory), and the system logs. These reside on the microSD overlay filesystem.
- **Third-party operated parts.** No part of the product is operated by a third party and there is no RDPS, so no third-party decommissioning action is required.
- **Manufacturer activities at and beyond end-of-support.** At end of support the manufacturer publishes the end-of-support date, stops issuing feature changes, and communicates that security updates will no longer be provided. The end-of-support policy is stated in RC-UM-013.

## 3. Decommissioning instructions to the user (CLA-09-RQ-02)

The user instructions in RC-UM-013 cover, where applicable, at least the following.

- **Remove user data.** Perform a factory reset to erase the configuration, credentials, wireless passphrase, leases, and logs.
- **Export user data.** Export any configuration the user wishes to keep before the reset.
- **Remove cybersecurity assets.** Confirm that credentials, keys, and the wireless passphrase are cleared by the reset.
- **Remove the product from the operational environment.** Disconnect the device from the network and remove its entries from other systems.
- **Securely dispose of the product.** Remove or securely erase the microSD card before disposal or resale, because the root filesystem is not encrypted.
