# CareOtter — Vulnerability Index

> **Layer:** 3 (Reference Material) — MWP Methodology  
> **Scope:** `labs/careotter/`, `cloud_api/careotter/`, `vulnzoo_apps/careotter_app/`  
> **Purpose:** Machine-parseable index of all documented vulnerabilities, organized by attack surface.  
> **Version:** 1.0  
> **Date:** 2026-05-02

---

## How to Use This Index

This directory follows the **Model Workspace Protocol (MWP)** Layer 3 conventions. Each vulnerability lives in its own file, categorized by the primary attack surface it exposes:

| Category | Path | Description |
|----------|------|-------------|
| `API/` | Cloud API vulnerabilities (Flask, REST, JWT) |
| `IoT/` | Device firmware vulnerabilities (IGP v4, OpenWRT, C binaries) |
| `Mobile/` | Mobile app and BLE vulnerabilities (Android, GATT, CSCP) |

Each file contains a YAML frontmatter block for automated parsing, followed by human-readable reproduction steps, root cause analysis, and remediation guidance.

> **Agent instruction:** When a task mentions a vulnerability ID (e.g., "fix API-06"), read the corresponding file directly. Do not scan the full test suite.

---

## Active Vulnerabilities

| ID | Title | Category | Status | Severity | CWE |
|----|-------|----------|--------|----------|-----|
| [IGP-01](IoT1_Weak_Guessable_Hardcoded_Passwords.md) | Hardcoded Credential (`OtterMobile2026`) | IoT | DONE | Critical | CWE-798 |
| [IoT:I2](IoT/IoT2_Insecure_Network_Services.md) | Insecure Network Services — cleartext IGP (§2.1), no-auth HTTP threshold overwrite (§2.2), forgotten legacy FTP daemon (`vsftpd 2.3.4` backdoor) → unauthenticated root RCE (§2.3), hidden BLE factory-provisioning backdoor → root RCE (§2.4) | IoT | DONE | Critical | CWE-1104 / CWE-912 / CWE-78 / CWE-306 / CWE-319 / CWE-798 / CWE-918 / CWE-613 |
| [IoT:I3](IoT/IoT3_Insecure_Ecosystem_Interfaces.md) | Insecure Ecosystem Interfaces — Cloud API device-ingest accepts forged telemetry under a spoofable static factory-signature header over plaintext HTTP, repointing the dashboard and hijacking placeholder device rows (§3.1). Lens over the cloud/web/mobile ecosystem cases — BFLA device control, factory-signature replay, device-secret disclosure, edge ACL bypass, weak JWT, beta-host OTP, mobile rogue-device MITM (no peer auth) | IoT | DONE | High | CWE-345 / CWE-290 / CWE-294 / CWE-319 |
| [IoT:I6](IoT/IoT6_Insufficient_Privacy_Protection.md) | Insufficient Privacy Protection — BLE ManufacturerData leaks the Cloud API address (§6.1) and Device Information GATT leaks the software stack (§6.2), both passively without pairing | IoT | DONE | Medium | CWE-200 / CWE-497 |
| [IoT:I7](IoT/IoT7_Insecure_Data_Transfer_and_Storage.md) | Insecure Data Transfer and Storage — CSCP v1 clinical thresholds under a hard-coded fleet-wide AES-ECB key → forgeable packet → deferred ZeroDivisionError DoS of BLE notifications (§7.1) | IoT | DONE | High | CWE-321 / CWE-306 / CWE-20 / CWE-369 / CWE-703 |
| [API-01](API1_Broken_Object_Level_Authorization.md) | Broken Object Level Authorization (BOLA) — Cross-User Vitals Access | API | DONE | High | CWE-639 / CWE-863 |
| [API-02](API2_Broken_Authentication.md) | Broken Authentication — weak storage/JWT + misplaced rate limit on `/api/auth/login/patient` (role gate before limiter → unlimited admin brute force + 401/403 oracle) | API | DONE | High | CWE-287 / CWE-308 / CWE-759 / CWE-307 / CWE-204 |
| [API-03](API3_Broken_Objetc_Property_Level_Authorization.md) | Broken Object Property Level Authorization (BOPLA) — A: Caregiver PII Exposure (read) · B: Store Quantity Property Tampering (write) | API | DONE | High | CWE-213 / CWE-359 / CWE-200 · CWE-1287 / CWE-20 / CWE-840 |
| [API-04](API4_Unrestricted_Resource_Consumption.md) | Unrestricted Resource Consumption — careservice command-channel flood | API | DONE | High | CWE-770 / CWE-400 / CWE-799 |
| [API-05](API5_Broken_Function_Level_Authorization.md) | Broken Function Level Authorization (BFLA) | API | DONE | High | CWE-863 |
| [API-06](API6_Unrestricted_Access_to_Business_Flows.md) | Unrestricted Access to Sensitive Business Flows — Teleconsultation Appointment Booking (cancel counter-desync → slot hoarding / denial of care) | API | DONE | High | CWE-840 / CWE-696 / CWE-799 |
| [API-07](API7_Server_Side_Request_Forgery.md) | Server-Side Request Forgery — Device-Diagnostics whitelist bypass (embedded-credentials parser confusion) → loopback internal admin → delete user | API | DONE | High | CWE-918 / CWE-20 / CWE-346 |
| [API-08](API8_Security_Misconfiguration.md) | Security Misconfiguration — reverse-proxy (nginx) ACL bypass via nginx↔gunicorn path-processing discrepancy (exact-match deny + slash-insensitive app → trailing-slash bypass to admin/debug/init) | API | DONE | High | CWE-16 / CWE-436 / CWE-863 |
| [API-09](API9_Improper_Inventory_Management.md) | Improper Inventory Management — forgotten beta subdomain (`beta.api.careotter.lab`) serves the password-reset OTP without the production vhost's rate-limit (app has no attempt cap) → 6-digit code brute-force → patient account takeover | API | DONE | High | CWE-307 / CWE-640 / CWE-799 |
| [M1](Mobile/M1_Improper_Credential_Usage.md) | Improper Credential Usage — fleet-wide AES-128 CSCP key (`careotter-key-16`) and default clinical thresholds hard-coded in the patient APK (recoverable with strings/jadx), so a forged CSCP packet sets lethal thresholds (`bpm_max=255`, `spo2_min=0`) the device accepts with no clinical range check (§1.1-§1.4) | Mobile | DONE | High | CWE-798 / CWE-321 / CWE-306 |
| [M3](Mobile/M3_Insecure_Authentication_Authorization.md) | Insecure Authentication/Authorization — the patient app authenticates a safety-critical threshold write to `0xFF01` only by possession of a static CSCP packet, with no authenticated session (CWE-306), no anti-replay so a sniffed packet replays with no key (CWE-294), and no per-operation authorization (CWE-285). Operation-auth lens on the BLE-07 chain (key=M1, channel=M5, device-side data/DoS=IoT7) | Mobile | DONE | High | CWE-294 / CWE-306 / CWE-285 |
| [M4](Mobile/M4_Insufficient_Input_Output_Validation.md) | Insufficient Input/Output Validation — the app's Historical Readings screen sends `patient_id` to `GET /api/vitals/readings`, which concatenates it into raw SQL (no parameterization) → UNION-based SQL injection (CWE-89) with a verbose `sqlite3.OperationalError` oracle (CWE-209); dumps `users` password hashes and a hidden `devices.ble_psk` CTF flag (`FLAG{SQLi_M4_CareOtter_2026}`) reachable only via the injection | Mobile | DONE | Critical | CWE-89 / CWE-209 |
| [M5](Mobile/M5_Insecure_Communication.md) | Insecure Communication — BLE client connects to any peripheral advertising the name `CareOtter_HR` with no pairing, bonding, MAC pinning, or LE Secure Connections, over an unencrypted link → rogue-device impersonation and MITM of patient vitals (§5.1/§5.2). Mobile-interface facet of IoT:I3 §A.7 | Mobile | DONE | High | CWE-300 / CWE-940 / CWE-319 / CWE-306 |
| [M6](Mobile/M6_Inadequate_Privacy_Control.md) | Inadequate Privacy Controls - the patient app over-collects the phone's precise GPS and justifies `ACCESS_FINE_LOCATION` with a false "needed for BLE scanning" rationale (`BLUETOOTH_SCAN` is `neverForLocation`). It POSTs the coordinates to `POST /api/vitals/readings` bundled with vitals (PHI), and the backend persists `latitude`/`longitude` verbatim with no masking or consent check, so the M4 SQLi on the GET form now also leaks a patient location trail | Mobile | DONE | Medium | CWE-359 / CWE-313 / CWE-200 |
| [M7](Mobile/M7_Insufficient_Binary_Protection.md) | Insufficient Binary Protection - the app ships present-but-bypassable RASP (`SecurityGuard`: naive root/debugger/Frida checks plus a non-enforced signing-certificate check, all behind one hookable `isCompromised` verdict) and a non-obfuscated release build (`isMinifyEnabled=false`). A single Frida hook on `isCompromised` defeats the attestation, then a hook on the client-side `LoginActivity.routeByRole` forces `role=admin`, dropping a normal patient into `AdminActivity`, which performs no entry authorization and auto-authenticates to the careservice IGP surface on `:9999` with the hardcoded `OtterMobile2026` token (IGP-01) for full device admin (DEFIBRILLATE, command injection, lethal thresholds). The same `:9999` surface is also reachable directly | Mobile | DONE | High | CWE-693 / CWE-602 / CWE-285 |
| [M8](Mobile/M8_Security_Misconfiguration.md) | Security Misconfiguration - a hidden diagnostic threshold panel (`android:visibility="gone"`, unlocked by 5 title taps within 3s) ships in the production APK with no debug guard, exposing technician-only threshold read/write controls to a normal user (CWE-912 hidden functionality). Trivially recovered via `strings`/`jadx`. The panel's plain-JSON write is rejected by the current CSCP-v1 firmware, so it is a stale relic - the live alert-suppression attack is the M1/M3 chain over direct BLE | Mobile | DONE | Medium | CWE-912 / CWE-489 / CWE-656 |
| [BLE-07](Mobile/BLE-07_CSCP_Threshold_Forging.md) | _MIGRATED_ — re-classified out of Mobile/M3 into IoT: provisioning backdoor → IoT2 §2.4, CSCP threshold forging → IoT7, BLE leaks → IoT6 | Mobile | MIGRATED | Critical | — |

---

## Legend

| Badge | Meaning |
|-------|---------|
| DONE | Vulnerability is implemented in code and verified in the lab environment. |
| PENDING | Vulnerability is documented but not yet implemented or not yet verified. |
| IN PROGRESS | Implementation is in progress; do not use for lab verification yet. |

---

## Cross-Reference to Other Layers

- **Layer 4 (Working Artifacts):** `labs/careotter/`, `cloud_api/careotter/`, `vulnzoo_apps/careotter_app/`
- **Layer 3 (Other Reference):** `../CareOtter_Test_Suite.md` (full 28-vulnerability test suite)
- **Layer 2 (Stage Contract):** `../../../labs/careotter/CONTEXT.md`
- **Layer 0 (Global Identity):** `../../../AGENTS.md`
