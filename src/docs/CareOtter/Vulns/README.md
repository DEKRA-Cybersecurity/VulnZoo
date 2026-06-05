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
| [IGP-01](IoT/IGP-01_Hardcoded_Credential.md) | Hardcoded Credential (`OtterMobile2026`) | IoT | ✅ DONE | Critical | CWE-798 |
| [API-01](API1_Broken_Object_Level_Authorization.md) | Broken Object Level Authorization (BOLA) — Cross-User Vitals Access | API | ✅ DONE | High | CWE-639 / CWE-863 |
| [API-02](API2_Broken_Authentication.md) | Broken Authentication — weak storage/JWT + misplaced rate limit on `/api/auth/login/patient` (role gate before limiter → unlimited admin brute force + 401/403 oracle) | API | ✅ DONE | High | CWE-287 / CWE-308 / CWE-759 / CWE-307 / CWE-204 |
| [API-03](API3_Broken_Objetc_Property_Level_Authorization.md) | Broken Object Property Level Authorization (BOPLA) — A: Caregiver PII Exposure (read) · B: Store Quantity Property Tampering (write) | API | ✅ DONE | High | CWE-213 / CWE-359 / CWE-200 · CWE-1287 / CWE-20 / CWE-840 |
| [API-04](API4_Unrestricted_Resource_Consumption.md) | Unrestricted Resource Consumption — careservice command-channel flood | API | ✅ DONE | High | CWE-770 / CWE-400 / CWE-799 |
| [API-05](API5_Broken_Function_Level_Authorization.md) | Broken Function Level Authorization (BFLA) | API | ✅ DONE | High | CWE-863 |
| [API-06](API6_Unrestricted_Access_to_Business_Flows.md) | Unrestricted Access to Sensitive Business Flows — Teleconsultation Appointment Booking (cancel counter-desync → slot hoarding / denial of care) | API | ✅ DONE | High | CWE-840 / CWE-696 / CWE-799 |
| [API-07](API7_Server_Side_Request_Forgery.md) | Server-Side Request Forgery — Device-Diagnostics whitelist bypass (embedded-credentials parser confusion) → loopback internal admin → delete user | API | ✅ DONE | High | CWE-918 / CWE-20 / CWE-346 |
| [BLE-07](Mobile/BLE-07_CSCP_Threshold_Forging.md) | CSCP v1 Threshold Forging (M3) | Mobile | ✅ DONE | Critical | CWE-306 / CWE-20 |

---

## Legend

| Badge | Meaning |
|-------|---------|
| ✅ DONE | Vulnerability is implemented in code and verified in the lab environment. |
| ⏳ PENDING | Vulnerability is documented but not yet implemented or not yet verified. |
| 🚧 IN PROGRESS | Implementation is in progress; do not use for lab verification yet. |

---

## Cross-Reference to Other Layers

- **Layer 4 (Working Artifacts):** `labs/careotter/`, `cloud_api/careotter/`, `vulnzoo_apps/careotter_app/`
- **Layer 3 (Other Reference):** `../CareOtter_Test_Suite.md` (full 28-vulnerability test suite)
- **Layer 2 (Stage Contract):** `../../../labs/careotter/CONTEXT.md`
- **Layer 0 (Global Identity):** `../../../AGENTS.md`
