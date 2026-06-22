# OctoBot - Vulnerability Index

> **Layer:** 3 (Reference Material) - MWP Methodology
> **Scope:** `labs/octobot/`, `cloud_api/octobot/`
> **Purpose:** Machine-parseable index of OctoBot vulnerabilities, organized by attack surface.
> **Status:** Implementation promoted (Stage 04). Items are `IN PROGRESS` pending an on-Pi lab-load verification, which flips them to `DONE`.

---

## How to Use This Index

This directory follows MWP Layer 3 conventions. Each vulnerability has its own file under `IoT/`. Implementation details and how-to-test steps are also summarized in [`../OPENWRT_INTEGRATION.md`](../OPENWRT_INTEGRATION.md) Section 7.

> **Agent instruction:** When a task mentions a vulnerability ID (e.g., "verify IoT:I4"), read the corresponding `IoT/` file directly.

---

## Active Vulnerabilities

| ID | Title | Category | Status | Severity | CWE |
|----|-------|----------|--------|----------|-----|
| [IoT:I1](IoT/IoT1_Weak_Guessable_Hardcoded_Passwords.md) | Weak / guessable / hardcoded passwords | IoT | IN PROGRESS | High | CWE-798 / CWE-1392 |
| [IoT:I2](IoT/IoT2_Insecure_Network_Services.md) | Insecure network services (serial bus, MQTT, Modbus/TCP, no auth) | IoT | IN PROGRESS | Critical | CWE-306 / CWE-319 |
| [IoT:I3](IoT/IoT3_Insecure_Ecosystem_Interfaces.md) | Insecure ecosystem interfaces (no-auth REST, IDOR, SSTI/XSS) | IoT | IN PROGRESS | High | CWE-639 / CWE-1336 / CWE-79 / CWE-306 |
| [IoT:I4](IoT/IoT4_Lack_of_Secure_Update_Mechanism.md) | Lack of secure update mechanism (unsigned OTA `.hex` via avrdude) | IoT | IN PROGRESS | Critical | CWE-494 / CWE-345 |
| [IoT:I5](IoT/IoT5_Use_of_Insecure_or_Outdated_Components.md) | Use of insecure / outdated components | IoT | PENDING | Medium | CWE-1104 / CWE-1035 |
| [IoT:I6](IoT/IoT6_Insufficient_Privacy_Protection.md) | Insufficient privacy protection (cleartext operator log) | IoT | IN PROGRESS | Medium | CWE-359 / CWE-200 |
| [IoT:I7](IoT/IoT7_Insecure_Data_Transfer_and_Storage.md) | Insecure data transfer and storage (no TLS, cleartext creds) | IoT | IN PROGRESS | High | CWE-319 / CWE-312 |
| [IoT:I8](IoT/IoT8_Lack_of_Device_Management.md) | Lack of device management (no rate-limit, audit, monitoring) | IoT | IN PROGRESS | Medium | CWE-778 / CWE-770 |
| [IoT:I9](IoT/IoT9_Insecure_Default_Settings.md) | Insecure default settings (default creds, permissive firewall) | IoT | IN PROGRESS | High | CWE-1188 / CWE-16 |
| [IoT:I10](IoT/IoT10_Lack_of_Physical_Hardening.md) | Lack of physical hardening (USB reflash, exposed UART, SD secrets) | IoT | IN PROGRESS | Medium | CWE-1263 / CWE-1191 |

---

## Legend

| Badge | Meaning |
|-------|---------|
| DONE | Implemented in code and verified in the lab. |
| PENDING | Documented or scoped, not yet implemented/verified. |
| IN PROGRESS | Implemented and documented, not yet verified on the live lab. |

> `IoT:I5` is `PENDING` because the deps hook installs current package versions and does not pin vulnerable ones, so the outdated-component vector is documented but not implemented.

---

## Cross-Reference to Other Layers

- **Layer 4 (Working Artifacts):** `labs/octobot/`, `cloud_api/octobot/`
- **Layer 3 (Plan):** [`../OPENWRT_INTEGRATION.md`](../OPENWRT_INTEGRATION.md) (build plan + OWASP catalog)
- **Layer 2 (Lab Contract):** [`../../../labs/octobot/CONTEXT.md`](../../../labs/octobot/CONTEXT.md)
- **Stage 01 Spec:** `stages/01_spec/output/octobot-spec.md`
- **Layer 0 (Global Identity):** [`../../../AGENTS.md`](../../../AGENTS.md)
