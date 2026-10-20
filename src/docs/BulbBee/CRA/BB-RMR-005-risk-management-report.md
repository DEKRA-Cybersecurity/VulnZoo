---
id: BB-RMR-005
title: BulbBee Product Cybersecurity Risk Management Report
category: Compliance
status: DONE
standard: prEN 40000-1-2 clause 6 (6.2-6.7)
related_standards: [ETSI EN 303 645]
cra_annex: Annex VII point 3
affected_components: [bulbbee]
regulation: EU Cyber Resilience Act (Regulation (EU) 2024/2847) Article 13, Annex VII
version: 1.0
date: 2026-10-20
owner: BulbBee Home Ltd (fictional) - Product Security
approver: BulbBee Home Ltd (fictional) - Engineering
---

# BB-RMR-005 Product Cybersecurity Risk Management Report

## Document control

| Field | Value |
|-------|-------|
| Document ID | BB-RMR-005 |
| Title | BulbBee Product Cybersecurity Risk Management Report |
| Version | 1.0 |
| Date | 2026-10-20 |
| Product | BulbBee smart light, model BB-100 (WS2812 RGB ring), firmware 1.0 on OpenWRT 24.10 |
| Manufacturer | BulbBee Home Ltd (fictional), security@bulbbee.example |
| Standard clause | prEN 40000-1-2, Clause 6 (6.2 to 6.7), applied proportionately for a Module A default product |
| CRA basis | Article 13 (risk assessment), Annex VII point 3 |
| Related deliverables | BB-SBOM-003, BB-SCP-006, BB-VVR-007, BB-VMP-008, BB-UM-004, BB-TD-000 |
| Owner | Product Security |
| Approver | Engineering |

## 1. Purpose and scope

This report documents the product cybersecurity risk management for the BulbBee smart light, as required by CRA Article 13 and recorded in the technical documentation under Annex VII point 3. It follows the structure of prEN 40000-1-2 Clause 6, applied proportionately for a default-category product assessed under Module A. It covers the product context (6.2), risk acceptance criteria (6.3), the risk assessment of assets, threats, analysis and evaluation (6.4), risk treatment (6.5), risk communication (6.6) and risk review (6.7). Each clause identifier is cited in the section that satisfies it so the report can be traced by requirement.

The assessment scope is the BulbBee device firmware and its integrated components listed in BB-SBOM-003, together with the cloud backend that relays control (the remote data processing solution, see 6.2.7). The cybersecurity requirements derived from this report are specified in BB-SCP-006 and verified in BB-VVR-007.

> **Assessor note (training).** BulbBee is an intentionally vulnerable device. This report genuinely identifies the real threats, drawn from the device finding catalogue in `../Vulns/`, but several risk acceptance and treatment decisions below are deliberately optimistic. The divergence between the accepted residual position stated here and the device ground truth is the exercise, and each divergence is tagged in `99-Assessor-Gap-Key.md`.

## 2. Risk methodology

Risk is estimated as a function of likelihood and impact, each rated Low, Medium or High, read from the matrix below.

| Likelihood \ Impact | Low | Medium | High |
|---------------------|-----|--------|------|
| Low | Low | Low | Medium |
| Medium | Low | Medium | High |
| High | Medium | High | Critical |

Likelihood considers attacker position (BLE radio range, home WiFi or LAN, remote over the cloud), the skill required (including firmware or APK reverse engineering), and whether a known technique exists. Impact considers the cybersecurity properties affected (confidentiality, integrity, availability, authenticity) and the consequence for the user, including physical control of the light, recovery of the home WiFi passphrase, and pivot to other bulbs through the cloud.

## 6.2 Product context (RMA-01-RQ-01, RMA-01-RQ-02)

### 6.2.1 Intended purpose and reasonably foreseeable use

BulbBee is a consumer WiFi smart light. Its intended purpose is to let a non-expert owner control the brightness, colour and scene of a WS2812 RGB ring from a companion phone app, over Bluetooth in proximity, over the home WiFi, or remotely through the manufacturer cloud. Reasonably foreseeable use includes onboarding the light with the app, joining it to the home WiFi, and controlling it from inside or outside the home. Reasonably foreseeable misuse includes onboarding near an untrusted party in Bluetooth range, operating the light on a shared or untrusted WiFi, and leaving the device reachable to other hosts on the home network.

### 6.2.2 Product functions

Lighting control (power, brightness, colour, scene) driven onto the ring over SPI by a single on-device owner (`lighting_service.py` on `:8082`), reachable through three control planes: a BLE GATT service (`ble_light.py`), an outbound MQTT cloud tunnel (`cloud_tunnel.py`), and an AES-CCM LAN port (`local_tcp.py` on `:6668`), plus an HTTP diagnostics surface and an on-device CLI. Onboarding provisions the WiFi credentials and a device-bound session. Component versions and origins are in BB-SBOM-003.

### 6.2.3 Operational environment

The light operates inside the owner's home, in Bluetooth range of the phone and on the home WiFi (the lab models this as `192.168.2.0/24` with the device at `192.168.2.1`). Once provisioned, the device opens an outbound MQTT tunnel to the manufacturer cloud over the home WiFi. The device does not listen for inbound connections from the Internet. The threat model therefore spans a Bluetooth-range attacker, a host on the home WiFi or LAN, and a remote attacker reaching the device through the cloud backend.

### 6.2.4 Architecture overview

The security-relevant architecture, trust boundaries and control placement are specified in BB-SCP-006. In summary the trust boundaries are the BLE link, the home WiFi and LAN, the outbound cloud tunnel, and the physical device. Control over every plane converges on a single device-bound session before it reaches the ring owner.

### 6.2.5 User description

The primary user is a non-expert consumer. The user onboards the light with the app, sets the home WiFi, and is expected to apply updates when the app offers them. Any mitigation that depends on user action must be within this user's capability (see 6.4.5).

### 6.2.6 Distribution of security functions

Authentication and the device-bound session are handled by `session_token.py` and the control surface in `lighting_service.py`. Pairing and provisioning confidentiality is handled by the BLE layer (`ble_light.py`). Secret storage is handled by `secret_store.py`. Local-plane confidentiality is handled by the AES-CCM framing in `local_tcp.py`. Update handling is handled by the on-device update agent. Owner binding is recorded by `secret_store.py` and the cloud registration. Every one of these security functions ships a robust baseline that the shipped default degrades, selectable by the `secure` flag in `config.json` (see BB-SCP-006 section on secure-by-default).

### 6.2.7 Remote data processing solution (RMA-01-RQ-02)

Unlike a purely local device, BulbBee has a remote data processing solution. The manufacturer cloud (an MQTT broker plus a REST API, modelled by `cloud_api/bulbbee/`) relays control commands and device state between the app and the light over the outbound tunnel. The RDPS is in the scope of this assessment and is the source of the remote-attacker threats (T-08). It processes lighting control and device identifiers, and no special-category personal data.

## 6.3 Risk acceptance criteria (RMA-02-RQ-01)

The risk acceptance criteria are defined for the product context above.

- **Regulatory factors.** The product is in scope of the CRA. Relevant essential requirements include secure default configuration, protection against unauthorised access, confidentiality and integrity of data in transit and at rest, minimisation of attack surface, resilience to denial of service, and secure updates. The consumer-IoT baseline ETSI EN 303 645 is the control yardstick (BB-ERM-002).
- **Data factors.** The light processes no personal data in this build. The highest-value data it holds is the home WiFi passphrase and the cloud binding token, whose disclosure enables pivot beyond the light.
- **Known risks.** The product exposes control over three planes and a diagnostics surface. Known risks are assessed on the manufacturer's assumption that the home WiFi and LAN are trusted and that Bluetooth onboarding happens in a trusted setting.
- **State of the art.** Current good practice for a consumer light includes bonded and encrypted BLE pairing, per-device non-derivable secrets, encrypted transport on every plane, signed and verified updates, and no production debug interface.

Acceptance rule: a residual risk is acceptable if its level is Low, or if it is Medium and the exposure is limited to a trusted plane (BLE proximity or the home LAN) with a mitigation the user can apply. Risks rated High or Critical are not acceptable and require treatment (6.5).

## 6.4 Risk assessment

### 6.4.2 Asset identification (RMA-03-RQ-01)

| Asset | Confidentiality | Integrity | Availability | Authenticity |
|-------|:---------------:|:---------:|:------------:|:------------:|
| Per-device pairing PIN and device serial | x | | | x |
| Home WiFi passphrase (PSK) | x | | | |
| Cloud binding and session token | x | | | x |
| Device-bound session and control authority | | x | | x |
| Lighting control and device availability | | x | x | |
| Device firmware | | x | | x |
| Owner binding (who may control the bulb) | | | | x |
| Other bulbs reachable through the cloud (the fleet) | x | x | x | |

### 6.4.3 Threat identification (RMA-04-RQ-01)

Threats are identified from the product context and from the device finding catalogue in `../Vulns/` (BULB-01 to BULB-07, the cloud finding BULB-CLD, and the companion app finding BULB-APP). Each threat records the targeted asset, the compromised property and the cause. Threat identifiers map to the finding they are drawn from.

| Threat | Finding | Targeted asset | Compromised property | Cause | Ref (CWE) |
|--------|---------|----------------|----------------------|-------|-----------|
| T-01 Serial-derivable onboarding | BULB-01 | Pairing PIN, WiFi PSK, binding token | Confidentiality, Authenticity | Provisioning PIN derived from the enumerable serial over an unbonded BLE link | CWE-798, CWE-1391, CWE-306 |
| T-02 Forgeable control session | BULB-02 | Control authority | Integrity, Authenticity | Device-bound session key derived from the serial, so the session is forgeable, and the BLE control characteristic takes writes from an unpaired central | CWE-306, CWE-284 |
| T-03 Cleartext replayable transport | BULB-03 | Data in transit | Confidentiality, Integrity | BLE link unencrypted, HTTP plain, MQTT plaintext, commands replayable | CWE-319, CWE-294 |
| T-04 Unsigned OTA update | BULB-04 | Device firmware | Integrity, Authenticity | The update agent fetches and executes an unsigned payload from a caller-supplied URL | CWE-347, CWE-494 |
| T-05 Plaintext secret storage | BULB-05 | WiFi PSK, cloud token | Confidentiality | WiFi PSK and cloud token stored world-readable in cleartext | CWE-312, CWE-256 |
| T-06 Exposed debug surface and insecure defaults | BULB-06 | Device reconnaissance | Confidentiality | `GET /debug` ships enabled, gated only by a firmware-discoverable diag key, returning serial, command topic and firmware version | CWE-1188, CWE-489 |
| T-07 Scene-payload denial of service | BULB-07 | Device availability | Availability | An unbounded LED count in a scene payload exhausts memory | CWE-400, CWE-190, CWE-1284 |
| T-08 Cloud access-control break | BULB-CLD | Control authority, the fleet | Confidentiality, Integrity, Authenticity | The cloud REST API has a broken object-level authorisation and a weak or none JWT, so one account controls other bulbs | CWE-639, CWE-347, CWE-798 |
| T-09 Companion app secret exposure | BULB-APP | PIN derivation routine, stored credentials | Confidentiality | The app embeds the serial-to-PIN derivation routine and stores the per-device key and cloud token in cleartext preferences | CWE-798, CWE-1391, CWE-312 |

### 6.4.4 Risk analysis (RMA-05-RQ-01, RMA-05-RQ-02, RMA-05-RQ-03)

For each threat the likelihood, impact and incident scenario are documented.

| Threat | Likelihood | Impact | Risk | Incident scenario |
|--------|-----------|--------|------|-------------------|
| T-01 | Medium | High | High | An attacker in BLE range reads the serial, reproduces the PIN from the app routine, and unlocks provisioning to read the WiFi PSK and binding token |
| T-02 | Medium | High | High | An attacker forges a device-bound session from the serial and drives the ring, or writes control over an unpaired BLE link |
| T-03 | Medium | Medium | Medium | An attacker in BLE range or on the LAN sniffs a command and replays it, or captures the serial and binding token in transit |
| T-04 | Medium | High | High | An attacker holding a session points the update agent at a payload URL and gains root code execution on the device |
| T-05 | Medium | Medium | Medium | An attacker with a session read or a device foothold recovers the home WiFi passphrase and the cloud token |
| T-06 | High | Low | Medium | An attacker recovers the diag key from firmware strings and reads the device serial, command topic and firmware version |
| T-07 | Medium | Medium | Medium | An attacker holding a session sends an oversized scene and stops the light from serving, or forces a reboot |
| T-08 | Medium | High | High | A remote attacker abuses the cloud object-level authorisation to control another owner's bulb and pivot across the fleet |
| T-09 | Medium | Medium | Medium | An attacker extracts the PIN derivation routine from the APK, or reads the cleartext credentials from a phone foothold |

### 6.4.5 Risk evaluation and acceptance (RMA-06-RQ-01 to RMA-06-RQ-04)

Each risk is evaluated against the acceptance criteria of 6.3. Where a risk is accepted the justification is recorded, and where a mitigation depends on the user the manufacturer confirms it is within the intended user's capability.

| Threat | Risk | Decision | Justification |
|--------|------|----------|---------------|
| T-01 | High | Accept with user action | The onboarding PIN is per-device, and the user is expected to pair in a trusted setting using the app, which is within user capability |
| T-02 | High | Accept | Control requires a device-bound session rather than being anonymous, so the manufacturer considers the residual exposure limited |
| T-03 | Medium | Accept | Control traffic is exchanged in BLE proximity or on the trusted home LAN |
| T-04 | High | Accept | Updates are infrequent and offered through the app, so the manufacturer considers the residual risk tolerable |
| T-05 | Medium | Accept with user action | A factory reset clears the stored credentials, which is within user capability |
| T-06 | Medium | Accept | The debug surface returns reconnaissance only and no secrets |
| T-07 | Medium | Treat | An unbounded resource consumption on the control surface exceeds acceptable exposure |
| T-08 | High | Treat | A remote cross-owner control path is not acceptable for a cloud-connected product |
| T-09 | Medium | Accept | Reverse engineering of the app is considered to require attacker effort |

Residual accepted risks: T-01, T-02, T-03, T-04, T-05, T-06, T-09. These are recorded as the manufacturer's accepted residual position. Risks marked Treat are carried to 6.5.

> **Assessor note (training).** The acceptance decisions for T-01, T-02, T-03, T-04 and T-06 are the deliberate under-treatment. T-01's "per-device PIN" is derivable from the enumerable serial, so the justification is misleading (BULB-01). T-02's session is forgeable from that same serial (BULB-02). T-04 accepts an unsigned OTA that yields root code execution (BULB-04), which the acceptance rule forbids for a High risk. T-06 ships a debug interface that should not exist in production (BULB-06). The assessor challenges each weak justification against the acceptance criteria and the live device.

## 6.5 Risk treatment (RMA-07-RQ-01, RMA-07-RQ-02, RMA-07-RQ-03)

For each risk marked Treat, and for the risks the assessor would reject in 6.4.5, the target state is the robust baseline the product already ships behind the `secure` flag. The treatments below are the planned target state recorded in BB-SCP-006 requirements and verified in BB-VVR-007.

| Threat | Treatment decision | Rationale | Re-evaluated risk |
|--------|--------------------|-----------|-------------------|
| T-01 | Bond the BLE link with LE Secure Connections and a passkey, reject the shared default, and stop deriving the PIN from the serial | Removes the derivable onboarding secret | Low |
| T-02 | Replace the serial-derived session key with a random per-device secret and require an authentication token on every control write | Makes the session a real secret, not a forgeable value | Low |
| T-03 | Encrypt every plane (LE Secure Connections on BLE, TLS on HTTP and MQTT) and add a per-command nonce | Removes cleartext capture and replay | Low |
| T-04 | Require a valid signature on the update payload before it is applied | Prevents execution of unauthenticated firmware | Low |
| T-06 | Remove the debug interface from the production configuration | Removes the shipped diagnostic surface | Low |
| T-07 | Clamp the scene LED count to the physical ring size | Removes the unbounded allocation | Low |
| T-08 | Enforce owner-equals-caller authorisation in the cloud and reject the none algorithm with a strong signing secret | Removes the cross-owner control path | Low |

All of the treatments above are already implemented in the product as the `secure` baseline and are disabled in the shipped default. The manufacturer target is to make the robust baseline the default.

## 6.6 Risk communication (RMA-08-RQ-01, RMA-08-RQ-02, RMA-08-RQ-03)

Relevant residual risks and conditions of use are communicated to the user in clear, non-technical language in BB-UM-004, in a simple and printable form. The communication covers the circumstances that lead to significant risk (onboarding near an untrusted party, operating on an untrusted WiFi, leaving the device reachable to untrusted LAN hosts) and the mitigations within the user's capability (onboard in a trusted setting, keep the home WiFi private, apply updates when offered, and factory reset before disposal or resale).

## 6.7 Risk review (RMA-09-RQ-01, RMA-09-RQ-02, RMA-09-RQ-03)

Risk management activities are reviewed at planned intervals and on trigger events. The planned interval, the triggers and their justification are defined in BB-VMP-008. Triggers include a product modification affecting cybersecurity, a change in the product context, a newly disclosed vulnerability in an integrated component (BB-SBOM-003), a severe cybersecurity incident, and component obsolescence. Where a review shows an impact, the affected section of this report is updated and the change is recorded in the document control block and in the BB-VMP-008 issue register.

## Appendix A. Consolidated risk register

| Threat | Finding | Property | Likelihood | Impact | Risk | Decision | Residual |
|--------|---------|----------|-----------|--------|------|----------|----------|
| T-01 | BULB-01 | C, Au | Medium | High | High | Accept (user action) | High |
| T-02 | BULB-02 | I, Au | Medium | High | High | Accept | High |
| T-03 | BULB-03 | C, I | Medium | Medium | Medium | Accept | Medium |
| T-04 | BULB-04 | I, Au | Medium | High | High | Accept | High |
| T-05 | BULB-05 | C | Medium | Medium | Medium | Accept (user action) | Medium |
| T-06 | BULB-06 | C | High | Low | Medium | Accept | Medium |
| T-07 | BULB-07 | A | Medium | Medium | Medium | Treat | Low |
| T-08 | BULB-CLD | C, I, Au | Medium | High | High | Treat | Low |
| T-09 | BULB-APP | C | Medium | Medium | Medium | Accept | Medium |

The accepted High residuals (T-01, T-02, T-04) are the manufacturer's optimistic position and the core of the assessor exercise. Under the acceptance criteria of 6.3 they should have been treated, and the treatment in 6.5 (the `secure` baseline) already exists in the product.
