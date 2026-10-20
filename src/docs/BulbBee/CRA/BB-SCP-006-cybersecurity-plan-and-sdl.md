---
id: BB-SCP-006
title: BulbBee Product Cybersecurity Plan and Secure Development Lifecycle
category: Compliance
status: DONE
standard: prEN 40000-1-2 clauses 7.2, 7.3, 7.4, 7.5a, 7.7c
related_standards: [ETSI EN 303 645]
cra_annex: Annex VII points 1 and 2a (and production)
affected_components: [bulbbee]
regulation: EU Cyber Resilience Act (Regulation (EU) 2024/2847) Annex I Part I, Annex VII
version: 1.0
date: 2026-10-20
owner: BulbBee Home Ltd (fictional) - Engineering
approver: BulbBee Home Ltd (fictional) - Head of Engineering
---

# BB-SCP-006 Product Cybersecurity Plan and Secure Development Lifecycle

## Document control

| Field | Value |
|-------|-------|
| Document ID | BB-SCP-006 |
| Title | BulbBee Product Cybersecurity Plan and Secure Development Lifecycle |
| Version | 1.0 |
| Date | 2026-10-20 |
| Product | BulbBee smart light, model BB-100, firmware 1.0 on OpenWRT 24.10 |
| Standard clause | prEN 40000-1-2, 7.2 (plan), 7.3 (requirements), 7.4 (architecture), 7.5a (secure development), 7.7c (production) |
| CRA basis | Annex VII points 1 (general description), 2a (design and development), 2 (production) |
| Related deliverables | BB-RMR-005, BB-VVR-007, BB-VMP-008, BB-SBOM-003, BB-UM-004, BB-TD-000 |
| Owner | Engineering |
| Approver | Head of Engineering |

## 1. Purpose

This document is the living product cybersecurity plan and the secure development lifecycle evidence for the BulbBee smart light. It consolidates, proportionately for a default-category product, what the prEN 40000-1-2 lifecycle clauses treat separately: the cybersecurity plan (7.2), the cybersecurity requirements (7.3), the architecture and design (7.4), the secure development environment (7.5a), and secure physical production (7.7c). It covers CRA Annex VII point 1 (general description) and point 2a (design and development), and the production part of point 2. The requirements here derive from the risk treatment in BB-RMR-005 and are verified in BB-VVR-007.

> **Assessor note (training).** This plan describes the robust security baseline as the manufacturer's intended design. The shipped device default degrades that baseline on every plane, which is the training exercise. Where this document claims secure-by-default, signed updates, encrypted transport or no debug interface, the shipped default contradicts it (BULB-02, BULB-04, BULB-03, BULB-06), and the divergence is tagged in `99-Assessor-Gap-Key.md`. The robust baseline described here is real and present in the product behind the `secure` flag, it is simply not the default.

## 2. Cybersecurity plan (clause 7.2)

The plan records the product cybersecurity activities, their deliverable, owner and cadence, across the product lifecycle. It is a living document, revised when an activity, deliverable, owner or cadence changes.

| Activity | Clause | Deliverable | Owner | Cadence | Status |
|----------|--------|-------------|-------|---------|--------|
| Risk management | 6.2-6.7 | BB-RMR-005 | Product Security | On change and at review interval | Complete v1.0 |
| Requirements | 7.3 | BB-SCP-006 section 3 | Product Security | On risk change | Complete v1.0 |
| Architecture and design | 7.4 | BB-SCP-006 sections 4-6 | Engineering | On design change | Complete v1.0 |
| Secure development environment | 7.5a | BB-SCP-006 section 7 | Engineering | Continuous | Complete v1.0 |
| Component list and SBOM | 7.5b, 7.5c | BB-SBOM-003 | Engineering | Per build | Complete v1.0 |
| Technical documentation | 7.5d | BB-TD-000 | Product Security | Per release | Complete v1.0 |
| User information | 7.5e | BB-UM-004 | Product Security | Per release | Complete v1.0 |
| Verification and validation | 7.6 | BB-VVR-007 | Quality | Per release and recurring | Complete v1.0 |
| Secure production | 7.7c | BB-SCP-006 section 8 | Operations | Continuous | Complete v1.0 |
| Vulnerability monitoring and handling | 7.8 | BB-VMP-008 | Product Security | Continuous, monthly review | Complete v1.0 |
| Secure update distribution | 7.7a (via 2b) | BB-VMP-008 section 5 | Operations | Per update | Complete v1.0 |
| Third-party due diligence | 7.10 | BB-SCP-006 section 9 | Engineering | On selection and continuous | Complete v1.0 |
| Decommissioning | 7.9 | BB-UM-004 | Product Security | Per lifecycle stage | Complete v1.0 |

Execution is tracked in the Status column and in each deliverable's document control block. The plan is reviewed at the interval and on the triggers defined in BB-VMP-008.

## 3. Cybersecurity requirements (clause 7.3)

The requirements below derive from the risk treatment in BB-RMR-005 section 6.5. Each is realised by a control in the architecture (section 4) and verified in BB-VVR-007.

| ID | Requirement | From threat |
|----|-------------|-------------|
| SR-01 | BLE pairing uses LE Secure Connections with a passkey, the shared default is rejected, and the onboarding PIN is not derived from the device serial | T-01 |
| SR-02 | The device-bound session key is a random per-device secret, and every control write requires a valid authentication token | T-02 |
| SR-03 | Every control plane is encrypted (LE Secure Connections on BLE, TLS on HTTP and MQTT) and each command carries a nonce to prevent replay | T-03 |
| SR-04 | Update payloads are verified against a signature before they are applied | T-04 |
| SR-05 | The WiFi passphrase and cloud token are stored with restrictive permissions and are not returned by the provisioning or config read | T-05 |
| SR-06 | No debug or diagnostic interface is present in the production configuration | T-06 |
| SR-07 | The scene LED count is bounded to the physical ring size | T-07 |
| SR-08 | The cloud enforces owner-equals-caller authorisation and rejects unsigned or none-algorithm tokens with a strong signing secret | T-08 |
| SR-09 | The companion app does not embed the PIN derivation routine and does not store credentials in cleartext | T-09 |
| SR-10 | Only the control planes and services required for the intended purpose are enabled by default | 6.3 attack surface |
| SR-11 | Owner binding is enforced on the device and in the cloud, so only the owner controls the bulb | T-02, T-08 |
| SR-12 | Security-relevant events are recorded without logging secrets | 6.3 state of the art |

## 4. Architecture and trust boundaries (clause 7.4)

BulbBee runs OpenWRT 24.10 on a Raspberry Pi driving a WS2812 ring over SPI. A single on-device owner (`lighting_service.py` on `:8082`) holds the lighting state and the ring, and each control plane is a thin adapter that translates its wire format into a lighting command applied through that owner, so there is never a second writer to the ring. Component versions and origins are in BB-SBOM-003.

| Boundary | Description | Controls at the boundary (target) |
|----------|-------------|-----------------------------------|
| BLE link | `ble_light.py`, GATT service `0xFF30` (control) and `0xFF40` (provisioning) | LE Secure Connections with a passkey, bonded link, provisioning behind the bond |
| Home WiFi and LAN | AES-CCM port `:6668` (`local_tcp.py`), HTTP `:8082` (`lighting_service.py`) | Per-device key, authenticated control, no debug interface |
| Cloud tunnel | outbound MQTT (`cloud_tunnel.py`) to the manufacturer broker | Per-device HMAC token over TLS, owner-equals-caller in the cloud |
| Physical device | board, storage, SPI ring | Protected secret storage, production configuration with no debug surface |

Control over every plane converges on the device-bound session before it reaches the owner, so the session is the single authorisation point.

### Selected cybersecurity controls

| Control | Design | Fulfils |
|---------|--------|---------|
| Bonded BLE pairing | LE Secure Connections with a passkey agent, the shared default rejected, onboarding PIN not derived from the serial | SR-01 |
| Per-device session | A random per-device session secret in `session_token.py`, an authentication token required on every control write | SR-02, SR-11 |
| Encrypted transport | LE Secure Connections on BLE, TLS on HTTP and MQTT, a per-command nonce | SR-03 |
| Update authenticity | A signature verified by the update agent before a payload is applied | SR-04 |
| Protected storage | WiFi passphrase and cloud token stored with restrictive permissions, omitted from the provisioning and config read | SR-05 |
| No debug surface | The `/debug` route refused in the production configuration | SR-06 |
| Bounded scene input | The scene LED count clamped to the ring size | SR-07 |
| Cloud authorisation | Owner-equals-caller enforced, none-algorithm rejected, a strong signing secret | SR-08, SR-11 |
| Attack-surface minimisation | Only the required planes enabled, no anonymous or undocumented interface | SR-10 |
| Security logging | Security-relevant events recorded without secrets | SR-12 |

### Secure interface design

Authentication is enforced at the control interface before any state change. Input received over any plane is validated at the adapter boundary, including the scene count bound. The attack surface is minimised to the planes required for the intended purpose, and there is no diagnostic or debug interface in the production configuration.

## 5. Component integration security

Each third-party component in BB-SBOM-003 is integrated in line with its intended purpose. The BLE stack (BlueZ) provides the pairing and link-layer encryption, the Python runtime hosts the lighting and adapter services, and the base OpenWRT platform provides the network services. Integrated components do not weaken the trust boundaries in section 4, and where a component provides a security function its configuration derives from the requirements in section 3.

## 6. Secure-by-default configuration

The product ships a robust security baseline selectable by the `secure` flag in `/opt/bulbbee/config.json`. In the robust baseline, BLE pairing is bonded and encrypted, the session secret is per-device and non-derivable, every plane is encrypted, updates are signature-verified, secrets are stored protected and omitted from reads, the debug route is refused, the scene count is clamped, and owner binding is enforced on the device and in the cloud.

> **Assessor note (training).** The shipped default sets this flag off, which degrades every control above to the finding behaviour (BULB-01, BULB-02, BULB-03, BULB-04, BULB-05, BULB-06, BULB-07, and the cloud BULB-CLD). So the secure-by-default claim is contradicted by the default configuration. The assessor demonstrates this by comparing the device in the default posture against the same device with `secure=true`, as set out in the assessor battery in `../README.md`. The manufacturer target is to make the robust baseline the default.

## 7. Secure development and maintenance environment (clause 7.5a)

The development and maintenance environment protects the product from unauthorised change.

- **Access control.** Source, build and release systems require individual named accounts with multi-factor authentication and least-privilege roles, reviewed on role change.
- **Source integrity.** The source repository enforces protected branches and peer review before merge.
- **Key management.** The update signing key is held in a protected key store and used only by the release pipeline, rotated on a schedule and on suspected compromise.
- **Build security.** Builds run on a controlled host from the pinned OpenWRT 24.10 baseline, and build inputs are checked against the component list in BB-SBOM-003.
- **Change traceability.** Every change is traceable from a tracked work item through review to the released firmware.

## 8. Secure physical production (clause 7.7c)

Production flashes the released firmware image, provisions a per-device identity, and ships the device with the production configuration. The production step does not enable any debug or diagnostic interface and does not place a shared secret on the device beyond the per-device provisioning. The robust baseline is the intended production default.

> **Assessor note (training).** In the shipped build the production configuration ships with `secure` off and the debug route enabled, which contradicts this section. This is the BULB-06 insecure-default finding viewed from the production process.

## 9. Third-party component due diligence (clause 7.10)

For each third-party component in BB-SBOM-003 (OpenWRT, BusyBox, the Python runtime, BlueZ, python3-dbus-fast) the manufacturer records its intended purpose in the product, its supported version line, and its maintenance and disclosure status. Components are monitored over the product lifecycle as part of BB-VMP-008. Versions are confirmed against the built image before they are pinned in the SBOM.

## 10. Deviation handling

If a secure development or production activity deviates from the architecture in sections 4 to 6, a review of the risk management activities (BB-RMR-005 section 6.7) and of the impacted lifecycle activities is triggered. The trigger, the review and any resulting documentation update are recorded in BB-VMP-008 and in the affected document control blocks.
