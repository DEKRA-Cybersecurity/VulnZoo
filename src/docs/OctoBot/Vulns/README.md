# OctoBot - Vulnerability Index

> **Layer:** 3 (Reference Material) - MWP Methodology
> **Scope:** `labs/octobot/`, `cloud_api/octobot/`
> **Purpose:** Machine-parseable index of OctoBot vulnerabilities, organized by attack surface.
> **Status:** Implementation promoted (Stage 04). Items are `IN PROGRESS` pending an on-Pi lab-load verification, which flips them to `DONE`.

---

## How to Use This Index

This directory follows MWP Layer 3 conventions. Vulnerabilities are organized by category under `IoT/`, `API/`, and `Mobile/`. Implementation details and how-to-test steps are also summarized in [`../OPENWRT_INTEGRATION.md`](../OPENWRT_INTEGRATION.md) Section 7.

> **Agent instruction:** When a task mentions a vulnerability ID (e.g., "verify IoT:I4"), read the corresponding file directly.

---

## Active Vulnerabilities

| ID | Title | Category | Status | Severity | CWE |
|----|-------|----------|--------|----------|-----|
| [IoT:I1](IoT/IoT1_Weak_Guessable_Hardcoded_Passwords.md) | Weak / guessable / hardcoded passwords | IoT | IN PROGRESS | High | CWE-798 / CWE-1392 |
| [IoT:I2](IoT/IoT2_Insecure_Network_Services.md) | Insecure network services (serial bus needs PASS:, MQTT auto-injects PASS: and leaks commands on `cell01/cmd/telemetry`, revealing `cell01/cmd`; Modbus/TCP leaks password on auth failure) | IoT | IN PROGRESS | Critical | CWE-306 / CWE-319 |
| [IoT:I3](IoT/IoT3_Insecure_Ecosystem_Interfaces.md) | Insecure ecosystem interfaces (no-auth REST, IDOR, SSTI -> unauth root RCE) | IoT | DONE | Critical | CWE-1336 / CWE-94 / CWE-306 / CWE-639 / CWE-79 |
| [IoT:I4](IoT/IoT4_Lack_of_Secure_Update_Mechanism.md) | Lack of secure update mechanism (unsigned OTA `.hex` via avrdude) | IoT | IN PROGRESS | Critical | CWE-494 / CWE-345 |
| [IoT:I5](IoT/IoT5_Use_of_Insecure_or_Outdated_Components.md) | Use of insecure / outdated components (Werkzeug 2.3.6 / Flask 2.0.2 on the Pi gateway, CVE-2023-46136 / CVE-2023-30861) | IoT | DONE | Medium | CWE-1104 / CWE-1035 |
| [IoT:I6](IoT/IoT6_Insufficient_Privacy_Protection.md) | Insufficient privacy protection (cleartext operator log) | IoT | IN PROGRESS | Medium | CWE-359 / CWE-200 |
| [IoT:I7](IoT/IoT7_Insecure_Data_Transfer_and_Storage.md) | Insecure data transfer and storage (no TLS, cleartext creds) | IoT | IN PROGRESS | High | CWE-319 / CWE-312 |
| [IoT:I8](IoT/IoT8_Lack_of_Device_Management.md) | Lack of device management (no rate-limit, audit, monitoring) | IoT | IN PROGRESS | Medium | CWE-778 / CWE-770 |
| [IoT:I9](IoT/IoT9_Insecure_Default_Settings.md) | Insecure default settings (default creds, permissive firewall) | IoT | IN PROGRESS | High | CWE-1188 / CWE-16 |
| [IoT:I10](IoT/IoT10_Lack_of_Physical_Hardening.md) | Lack of physical hardening (USB reflash, exposed UART, SD secrets) | IoT | IN PROGRESS | Medium | CWE-1263 / CWE-1191 |
| [IoT:I10-FW](IoT/IoT_Firmware_Static_Analysis.md) | Firmware static analysis: SD-card binwalk extraction | IoT | IN PROGRESS | Medium | CWE-1263 / CWE-798 |

## API Vulnerabilities

| ID | Title | Category | Status | Severity | CWE |
|----|-------|----------|--------|----------|-----|
| [API5:2023](API/API5_Broken_Function_Level_Authorization.md) | Broken Function Level Authorization (downgrade to unauthenticated v0 firmware endpoint) | API | IN PROGRESS | High | CWE-285 |
| [API10:2023](API/API10_Unsafe_Consumption_of_APIs.md) | Login input SQL injection (id kept; accurate class is SQLi / CWE-89, not Unsafe Consumption) | API | DONE | High | CWE-89 |

## Mobile Vulnerabilities

| ID | Title | Category | Status | Severity | CWE |
|----|-------|----------|--------|----------|-----|
| [M5](Mobile/M5_Insecure_Communication.md) | Insecure Communication (cleartext HTTP: operator creds + session cookie on the wire) | Mobile | IN PROGRESS | High | CWE-319 |
| [M8](Mobile/M8_Security_Misconfiguration.md) | Security Misconfiguration (pre-login disclosure of `/api/v0/` firmware route) | Mobile | IN PROGRESS | Medium | CWE-200 / CWE-212 |
| [M9](Mobile/M9_Insecure_Data_Storage.md) | Insecure Data Storage (backup-extractable plaintext session cookie) | Mobile | IN PROGRESS | Medium | CWE-312 / CWE-200 |

---

## Legend

| Badge | Meaning |
|-------|---------|
| DONE | Implemented in code and verified in the lab. |
| PENDING | Documented or scoped, not yet implemented/verified. |
| IN PROGRESS | Implemented and documented, not yet verified on the live lab. |

> `IoT:I5` is realized by the outdated Python web stack the OpenWRT feed already ships on the Pi gateway (Werkzeug 2.3.6 / Flask 2.0.2, both years out of date), fingerprintable from the Werkzeug `Server` header and mapping to CVE-2023-46136 and CVE-2023-30861. No version pinning was needed, the stale versions are already present.

---

## Cross-Reference to Other Layers

- **Layer 4 (Working Artifacts):** `labs/octobot/`, `cloud_api/octobot/`
- **Layer 3 (Plan):** [`../OPENWRT_INTEGRATION.md`](../OPENWRT_INTEGRATION.md) (build plan + OWASP catalog)
- **Layer 2 (Lab Contract):** [`../../../labs/octobot/CONTEXT.md`](../../../labs/octobot/CONTEXT.md)
- **Stage 01 Spec:** `stages/01_spec/output/octobot-spec.md`
- **Layer 0 (Global Identity):** [`../../../AGENTS.md`](../../../AGENTS.md)

---