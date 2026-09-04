# BulbBee - Vulnerability Roadmap

> **Layer:** 3 (Reference Material) - MWP Methodology
> **Scope:** `labs/bulbbee/` (and, later, `cloud_api/bulbbee/` and a companion app).
> **Purpose:** Machine-parseable roadmap of the consumer-IoT vulnerabilities planned for bulbbee, with their CRA / ETSI EN 303 645 mapping.
> **Status:** Phase 0 (functional bring-up, BULB-A0) is implemented and self-checked in simulation, pending verification on the Pi. Every finding below is `PENDING`. See [`../README.md`](../README.md).

---

## Certification mapping

BulbBee is the VulnZoo reference for a **CRA default-category** product: a consumer smart light that falls in no vertical of Annex III (important) or Annex IV (critical) of the EU Cyber Resilience Act (Regulation (EU) 2024/2847), and therefore follows the lightest conformity route. Findings carry a triple mapping.

- **CRA Annex I** essential requirements. Part I (secure by default, no known exploitable vulnerabilities, protect confidentiality/integrity/availability of data, minimise attack surface, resilience to denial of service, secure updates, protect stored and transmitted data) and Part II (vulnerability handling, SBOM, coordinated disclosure). Exact Annex I point numbers are pinned per finding when each is specified, not guessed here.
- **ETSI EN 303 645** as the consumer-IoT baseline and the presumption-of-conformity anchor for the default route. Smart lighting is a canonical EN 303 645 device, so each finding names the EN 303 645 provision it breaks.
- **OWASP IoT Top 10** (2018) as the familiar cross-map used across the other VulnZoo labs.

The default-category conformity path itself, **Module A (internal control)** with a self-declared EU Declaration of Conformity and CE marking and no notified body, is the subject of the manufacturer dossier (BULB-CRA), which reuses the RoutCoon CRA dossier framing (claim versus device ground truth) on the lighter route and contrasts it against RoutCoon's important-product route.

The custom identifier scheme for the device findings is `BULB-##`, consistent with the project's other custom IDs (`IGP-01`, `BLE-07`, `AUTO-##`). Cloud and app findings, when built, reuse the OWASP `API#:2023` and `M#` schemes.

---

## Planned vulnerabilities (roadmap)

| ID | Title | Surface | OWASP IoT | EN 303 645 | CRA Annex I | Status | Severity (est.) | CWE (candidate) |
|----|-------|---------|-----------|------------|-------------|--------|-----------------|-----------------|
| [BULB-01](IoT/BULB-01-unauthenticated-ble-onboarding.md) | Unauthenticated onboarding: BLE provisioning + open `BulbBee-setup` AP + hardcoded pairing | onboarding (BLE / WiFi) | I1 | 5.1 | Part I secure-by-default | IN PROGRESS | High | CWE-798 / CWE-1392 / CWE-307 / CWE-306 |
| [BULB-02](IoT/BULB-02-unauthenticated-control-surface.md) | Unauthenticated control surface (BLE GATT no-bonding + local HTTP) | BLE + LAN control | I2 | 5.6 | Part I access control | IN PROGRESS | High | CWE-306 / CWE-284 |
| [BULB-03](IoT/BULB-03-cleartext-replayable-channel.md) | Cleartext, replayable control channel (BLE no encryption, plus HTTP + MQTT) | BLE / LAN / cloud | I7 | 5.5 | Part I protect data in transit | IN PROGRESS | Medium | CWE-319 / CWE-294 |
| [BULB-04](IoT/BULB-04-unsigned-ota-update.md) | Unsigned OTA update of the lighting service | update | I4 | 5.7 | Part I secure updates | IN PROGRESS | Critical | CWE-347 / CWE-494 |
| [BULB-05](IoT/BULB-05-plaintext-secret-storage.md) | WiFi PSK + cloud token readable over BLE/HTTP config, world-readable on disk | storage | I7 | 5.4 | Part I protect stored data | IN PROGRESS | Medium | CWE-312 / CWE-256 |
| [BULB-06](IoT/BULB-06-insecure-default-debug.md) | Insecure default settings / exposed debug surface | defaults | I9 | 5.6 | Part I minimise attack surface | IN PROGRESS | Medium | CWE-1188 / CWE-489 |
| [BULB-07](IoT/BULB-07-scene-payload-dos.md) | Scene-payload DoS (unbounded LED count / integer overflow) | BLE / LAN control | I2 | 5.9, 5.13 | Part I resilience to DoS | IN PROGRESS | Medium | CWE-400 / CWE-190 / CWE-1284 |
| [BULB-CRA](../CRA/00-CRA-Documentation-Plan.md) | CRA default-category manufacturer dossier (Module A, self-declared DoC, gap key) | compliance | - | (baseline) | Annex I + Annex VIII Module A | DONE | N/A | N/A |
| [BULB-CLD](API/BULB-CLD-cloud-api-bola-weak-jwt.md) | Cloud API: BOLA on bulb control + broken auth (alg:none / weak JWT) | cloud API `:5004` | (API) | 5.5 | Part I access control | DONE | High | CWE-639 / CWE-347 / CWE-798 |
| [BULB-APP](Mobile/BULB-APP-hardcoded-pin-and-plaintext-storage.md) | Android app: hardcoded pairing PIN (extractable) + plaintext credential storage | mobile app | (M1/M9) | 5.4 | Part I protect stored data | IN PROGRESS | Medium | CWE-798 / CWE-312 |

Notes:

- BULB-A0 (functional bring-up) carries no intentional weakness. It ships the honest lighting service, the WS2812 driver, the `:8082` control API and the packaging, and is the groundwork the findings above attack.
- BULB-A1 (BLE GATT control service) is the other functional groundwork: it is the Android app's channel to the Pi (modeled on CareOtter's `ble_server.py`), also carrying no intentional weakness of its own. The weaknesses on that channel are BULB-01 (onboarding), BULB-02 (no bonding/auth) and BULB-03 (no encryption).
- BULB-02, BULB-04 and BULB-05 chain: the unauthenticated control surface (BULB-02, over BLE or HTTP) reads the plaintext secrets (BULB-05) and triggers the unsigned update (BULB-04) from an unauthenticated BLE-range or LAN position.
- BULB-03's primary channel is BLE with no encryption or bonding (sniffable and replayable). The plain-HTTP half and a local MQTT mock are reproducible without a cloud, the real cloud MQTT half depends on the deferred cloud (BULB-CLD).
- A `secure` UCI toggle (`bulbbee.@bulbbee[0].secure=1`, target BULB-SEC) provides a hardened comparison mode, so each finding can be shown firing in vulnerable mode and neutralised in secure mode.
- Deferred to a later wave: BULB-CLD (thin cloud API on `:5004`, API1 BOLA + API2 weak/none JWT) and BULB-APP (the companion control app, the device's controller over BLE, an M-family finding).

---

## ETSI EN 303 645 coverage

BulbBee is assessed natively against the CRA baseline, and cross-maps to the ETSI EN 303 645 consumer-IoT provisions as the presumption-of-conformity lens. `PENDING` is on the roadmap, `N/A` is out of scope for this single-function light with a one-line reason.

| EN 303 645 provision | BulbBee finding(s) | Status | Note |
|----------------------|--------------------|--------|------|
| 5.1 No universal default passwords | BULB-01 | IN PROGRESS | unauthenticated BLE provisioning (no bonding) and a hardcoded pairing PIN, open setup AP as fallback |
| 5.2 Implement a means to manage reports of vulnerabilities | BULB-CRA | DONE | the dossier's coordinated-disclosure policy is claimed, then tested (BB-UM-004) |
| 5.3 Keep software updated | BULB-04 | IN PROGRESS | an update path exists but applies unsigned payloads |
| 5.4 Securely store sensitive security parameters | BULB-05 | IN PROGRESS | WiFi PSK and cloud token in world-readable cleartext |
| 5.5 Communicate securely | BULB-03 | IN PROGRESS | BLE control with no encryption or bonding, plus plain HTTP and TLS-less MQTT, all sniffable and replayable |
| 5.6 Minimise exposed attack surfaces | BULB-02, BULB-06 | IN PROGRESS | unauthenticated control surface (BLE GATT + HTTP, BULB-02) and a `/debug` surface shipped enabled (BULB-06) |
| 5.7 Ensure software integrity | BULB-04 | IN PROGRESS | no signature or origin check on the update |
| 5.8 Ensure that personal data is secure | - | N/A | a light holds no personal data in this build |
| 5.9 Make systems resilient to outages | BULB-07 | IN PROGRESS | a crafted scene payload stops the service from serving |
| 5.13 Validate input data | BULB-07 | IN PROGRESS | unbounded LED count / integer overflow in the scene parser |

---

## Secure mode (BULB-SEC)

A `secure` toggle (`bulbbee.@bulbbee[0].secure=1` in UCI, `"secure": true` in `config.json`) flips the device from the vulnerable default to a hardened branch, so the lab runs in both modes for a direct comparison (objective 6) and gives the CRA dossier a "what conformity looks like" reference. The vulnerabilities remain the default, the toggle only adds the hardened path.

| Finding | Secure-mode neutralization |
|---------|----------------------------|
| BULB-01 | provisioning refuses the shared default PIN and locks out after 5 attempts |
| BULB-02 | HTTP `/set`, `/scene`, `/config`, `/update` require an `X-Auth-Token` |
| BULB-04 | `apply_update` requires a valid HMAC signature line, unsigned payloads rejected |
| BULB-05 | the WiFi PSK is omitted from the provisioning read, the state file is `chmod 600` |
| BULB-06 | `/debug` is forced off (404) |
| BULB-07 | the scene `count` is clamped to `led_count` |

BULB-03 (transport confidentiality) is documented, not code-gated, its secure state is TLS on HTTP plus LE Secure Connections on BLE plus a per-command nonce. All the neutralizations above are verified offline in `stages/05_verify/output/bulbbee-sec-verification.md`.

## Legend

| Badge | Meaning |
|-------|---------|
| DONE | Implemented in code and verified in the lab. |
| IN PROGRESS | Implemented and documented, not yet verified on the live lab. |
| PENDING | Documented or scoped, not yet implemented or verified. |

Phase 0 (BULB-A0, BULB-A1) is the functional bring-up and carries no intentional weakness. BULB-01 through BULB-07 (the device findings) are `IN PROGRESS` (logic/offline-verified, over-the-air / on-Pi verification pending). BULB-CRA (dossier), BULB-CLD (cloud API) and BULB-SEC (secure-mode toggle) are `DONE` (verified offline, no device dependency). BULB-APP (mobile) is `IN PROGRESS`: the source and M1/M9 findings are present and inspection-verified, the Android build and on-device BLE control are the remaining steps.

---

## Cross-reference to other layers

- **Layer 4 (working artifacts):** `labs/bulbbee/`
- **Layer 3 (landing page):** [`../README.md`](../README.md), setup [`../LAB_SETUP.md`](../LAB_SETUP.md)
- **Layer 2 (lab contract):** [`../../../labs/bulbbee/CONTEXT.md`](../../../labs/bulbbee/CONTEXT.md)
- **Development backlog / stages:** `stages/TARGET_BULBBEE.md`, spec `stages/01_spec/output/bulbbee-a0-spec.md`
- **CRA framing to reuse / contrast:** [`../../RoutCoon/CRA/00-CRA-Documentation-Plan.md`](../../RoutCoon/CRA/00-CRA-Documentation-Plan.md)
- **Layer 0 (global identity):** [`../../../AGENTS.md`](../../../AGENTS.md)
