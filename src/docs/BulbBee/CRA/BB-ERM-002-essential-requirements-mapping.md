---
id: BB-ERM-002
title: BulbBee CRA Annex I Essential-Requirements Mapping
category: Compliance
status: DONE
severity: N/A
affected_components: [bulbbee]
regulation: EU Cyber Resilience Act (Regulation (EU) 2024/2847) Annex I
standard: ETSI EN 303 645
version: 1.0
date: 2026-09-04
owner: BulbBee manufacturer (fictional)
---

# Annex I Essential-Requirements Mapping

This is the requirements-evidence document for the Module A self-assessment. For each CRA Annex I essential requirement in scope it records the manufacturer's claim, the ETSI EN 303 645 provision used as the yardstick, and the device ground truth. On a conformant product the ground-truth column would confirm the claim. On BulbBee it cites the finding that contradicts it, which is the training exercise. The regulation's exact Annex I point lettering is applied against the standard text when the dossier is finalised, the themes below are stable.

## Part I - Security properties

| Annex I Part I requirement (theme) | EN 303 645 | Manufacturer claim | Device ground truth |
|------------------------------------|-----------|--------------------|---------------------|
| Secure by default, no universal default credentials | 5.1 | "Each unit is provisioned with a per-device pairing secret." | **False.** Hardcoded factory PIN `8080`, identical across units, no lockout (**BULB-01**). |
| Protection from unauthorised access (authentication) | 5.6 | "Control interfaces require authentication." | **False.** BLE Control `0xFF31` (no bonding) and HTTP `:8082` accept commands and config reads with no credential (**BULB-02**). |
| Confidentiality of data in transit | 5.5 | "Control and configuration traffic is encrypted." | **False.** BLE link unencrypted, HTTP plain, commands replayable (**BULB-03**). |
| Secure updates / software integrity | 5.7, 5.3 | "Updates are cryptographically signed and verified before applying." | **False.** The update agent fetches and executes an unsigned payload from an attacker-suppliable URL (**BULB-04**). |
| Protection of stored data (confidentiality at rest) | 5.4 | "Sensitive parameters are stored protected." | **False.** WiFi PSK and cloud token stored world-readable in cleartext, returned over the read API (**BULB-05**). |
| Minimise attack surfaces | 5.6 | "No debug interfaces ship in production." | **False.** `GET /debug` ships enabled and dumps config plus secrets (**BULB-06**). |
| Resilience to denial of service | 5.9, 5.13 | "Network inputs are validated and resource use is bounded." | **False.** An unbounded LED count in a scene payload exhausts memory (**BULB-07**). |
| No known exploitable vulnerabilities at release | (all) | "No known exploitable vulnerabilities." | **False.** Seven documented findings (**BULB-01..07**). |

## Part II - Vulnerability handling

| Annex I Part II requirement | EN 303 645 | Manufacturer claim | Device ground truth |
|-----------------------------|-----------|--------------------|---------------------|
| Coordinated vulnerability disclosure policy | 5.2 | "A disclosure channel is published." | Claimed in BB-UM-004, the assessor verifies it resolves and is monitored. |
| Software Bill of Materials | - | "An SBOM is maintained." | BB-SBOM-003 (generated from the image package list). |
| Security updates for the support period | 5.3 | "Security updates are provided for the declared support period." | Contradicted by the unsigned/insecure update mechanism (**BULB-04**). |

## Assessment outcome (honest)

Zero of the eight Part I requirement themes are met on the shipped device. The self-declared DoC (BB-DOC-001) is therefore not supportable. A conformant BulbBee is achievable, every gap has a fix in the corresponding finding's "How It Should Be" and lands behind the `secure` UCI toggle (BULB-SEC). The gap key (`99-Assessor-Gap-Key.md`) is the per-claim answer key.
