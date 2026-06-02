---
id: API3:2023
title: Broken Object Property Level Authorization (BOPLA) — Patient Discovers Caregiver PII
category: API
status: DONE
severity: High
owasp: API3:2023 — Broken Object Property Level Authorization
cwe: CWE-213 (Exposure of Sensitive Information Due to Incompatible Policies) / CWE-359 (Exposure of Private Personal Information) / CWE-200
source_docs:
  - CareOtter_Test_Suite.md §API-03
  - CareOtter_API.md Vulnerability Surface
affected_components:
  - cloud_api/careotter/api_server/app.py
  - cloud_api/careotter/api_server/services/database_service.py
verified_date: 2026-06-01
---

# API3 — Broken Object Property Level Authorization (BOPLA) — Patient Discovers Caregiver PII

> **OWASP:** API3:2023 — Broken Object Property Level Authorization
> **CWE:** CWE-213 / CWE-359 / CWE-200
> **Severity:** High

---

## Why It Matters

**Broken Object Property Level Authorization (BOPLA)** occurs when an API correctly authorizes access to an *object* but fails to authorize access to individual *properties* of that object — returning fields the caller should never see (excessive data exposure) or accepting fields the caller should never set (mass assignment). It is the 2023 merge of the former "Excessive Data Exposure" and "Mass Assignment" categories.

CareOtter lets a patient see **who their assigned caregiver is** — a legitimate feature backed by the `caregiver_assignments` table. The endpoint `GET /api/patient/caregivers` is correctly scoped at the **object level**: a patient only ever receives their *own* assigned caregivers. The flaw is at the **property level**: the response exposes the caregiver's private personal information (`display_name`, `email`, `phone`, `address`, `profile_photo`) along with internal fields (`caregiver_id`, `password_hash`) that a patient has no authorization to read.

In a real remote-care platform, a patient learning their nurse's **home address, personal phone number, and email** is a serious privacy breach that enables stalking, harassment, and social engineering. Worse, the leaked `password_hash` is an **unsalted SHA-256** (see API2): a patient can crack it offline, take over the caregiver account, and then — via the caregiver role — pivot to the **API1 BOLA** endpoint and read the cardiac telemetry of *every* patient that caregiver monitors.

> **Why this is BOPLA and not BOLA:** object-level authorization is *intact* here — the patient cannot reach an arbitrary caregiver, only their own. The defect is purely which **properties** of that authorized object are returned. (The API1 > BOLA finding is the opposite: it lets a caller reach the wrong *object*.)

---

## Root Cause

### 1. The data layer over-projects the caregiver object

`database_service.py` → `get_caregivers_for_patient()` joins the assignment onto the caregiver's `users` row and selects **excessive properties**:

```python
SELECT ca.id, ca.caregiver_username, ca.patient_username, ca.created_at,
       u.role,
       u.id            AS caregiver_id,
       u.display_name,
       u.email,
       u.phone,
       u.address,
       u.profile_photo,
       u.password_hash          -- internal secret, never for a patient
FROM caregiver_assignments ca
JOIN users u ON ca.caregiver_username = u.username
WHERE ca.patient_username = ?    -- object scope is CORRECT
ORDER BY ca.created_at DESC
```

The `WHERE ca.patient_username = ?` clause keeps the **object** authorization correct. What is broken is the **projection**: PII and `password_hash` are returned to a caller (the patient) who is not authorized to read those properties. 

### 2. The route exposes the over-projected object in vulnerable mode

`app.py` → `list_patient_caregivers` (`GET /api/patient/caregivers`) returns the full object when `VULNERABLE=1`, and only strips it to a safe whitelist when `VULNERABLE=0`:

```python
caregivers = db.get_caregivers_for_patient(patient_username)
if vuln != 1:
    safe = ('id', 'caregiver_username', 'patient_username', 'created_at', 'role')
    caregivers = [{k: c[k] for k in safe if k in c} for c in caregivers]
```

In `vuln=1` the property-level filter is absent, so the caregiver's PII and password hash reach the patient.

### 3. No DTO / output contract

There is no response schema (DTO / serializer) that defines which caregiver properties a patient may see. The endpoint returns whatever the query produces, so a widened query silently widens the API response — the classic BOPLA failure mode.

---

## Affected Endpoint

| Method | Endpoint | Intended | Actual (vuln=1) |
|--------|----------|----------|-----------------|
| `GET` | `/api/patient/caregivers` | Patient sees the *identity* of their assigned caregiver(s) | **BOPLA** — also returns the caregiver's `email`, `phone`, `address`, `display_name`, `profile_photo`, `caregiver_id`, and `password_hash` |

---

## Steps to Reproduce

**Precondition:** `VULNERABLE=1`; system initialized; `care_john` assigned to `john_doe`.

```bash
# 0. Initialize (seeds users incl. care_john with PII) and assign the caregiver
curl -s http://localhost:5002/initialize_iot >/dev/null

JWT=$(curl -s -X POST http://localhost:5002/api/auth/login/patient \
  -H 'Content-Type: application/json' \
  -d '{"username":"john_doe","password":"johnny123"}' | jq -r .token)

curl -s -X POST http://localhost:5002/api/patient/caregivers \
  -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"caregiver_username":"care_john"}' >/dev/null
```

### Step 1 — As the patient, list your caregivers

```bash
curl -s -H "Authorization: Bearer $JWT" \
  http://localhost:5002/api/patient/caregivers | jq '.caregivers[0]'
```

### Step 2 — Observe the leaked caregiver PII + hash
![[api3_leaked_caregiver.png]]
### Step 3 — (Chain) crack the unsalted SHA-256 and take over the caregiver

```bash
# The hash is unsalted SHA-256 (API2). Crack offline, then:
curl -s -X POST http://localhost:5002/api/auth/login/caregiver \
  -H 'Content-Type: application/json' \
  -d '{"username":"care_john","password":"<cracked>"}'
# → caregiver JWT → pivot to API1 BOLA: /api/caregiver/patient/<any>/vitals
```

---

## Expected Result

In `VULNERABLE=1`, `GET /api/patient/caregivers` returns `200 OK` with each caregiver object containing `email`, `phone`, `address`, `display_name`, `profile_photo`, `caregiver_id`, and `password_hash`. In `VULNERABLE=0`, the same request returns only `id`, `caregiver_username`, `patient_username`, `created_at`, `role` — no PII, no hash.

---

## How It Should Be

Authorize at the **property level**, not just the object level. Define an explicit output contract for what a patient may see about a caregiver and never return more.

### Minimal fix

```python
# Project only the properties a patient is allowed to see — at the data layer.
SELECT ca.id, ca.caregiver_username, ca.patient_username, ca.created_at,
       u.role, u.display_name        -- name is by-design; no email/phone/address/hash
FROM caregiver_assignments ca
JOIN users u ON ca.caregiver_username = u.username
WHERE ca.patient_username = ?
```

### Architectural improvements

1. **Response DTO / serializer** — define a `CaregiverPublicView` schema with an explicit allow-list; serialize through it so a widened query cannot widen the API.
2. **Never select secrets for read endpoints** — `password_hash` should never appear in any query that feeds a client response.
3. **Classify properties** — tag user fields as public / private / internal and enforce per-role visibility centrally.
4. **Contract tests** — assert the response body of `/api/patient/caregivers` contains only the allow-listed keys, so a regression that re-widens the projection fails CI.

---

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Authorization | Property-level allow-list (DTO) on the caregiver view | Return only properties a patient may see |
| Data | Exclude `password_hash`/secrets from any read-path query | Prevent credential exposure |
| Privacy | Classify user fields (public/private/internal) + per-role visibility | Stop PII over-exposure systematically |
| Testing | Contract test asserting the exact response key set | Detect regressions that re-widen the projection |

---

## Verification Checklist

- [ ] `VULNERABLE=1`: `GET /api/patient/caregivers` returns `email`, `phone`, `address`, `profile_photo`, `caregiver_id`, `password_hash`
- [ ] `VULNERABLE=0`: the same request returns only `id`, `caregiver_username`, `patient_username`, `created_at`, `role`
- [ ] Object scope intact: a patient never sees a caregiver they are not assigned to (still BOPLA, not BOLA)
- [ ] The leaked `password_hash` matches the unsalted SHA-256 of the caregiver password (chains to account takeover)
- [ ] `caregiver_assignments` continues to scope the query by `patient_username`

---

## References

- `CareOtter_Test_Suite.md` §API-03
- `cloud_api/careotter/api_server/app.py` (`list_patient_caregivers`)
- `cloud_api/careotter/api_server/services/database_service.py` (`get_caregivers_for_patient`, `set_user_pii`)
- Related: `API1_BOLA.md` (object-level — the pivot target), `API2_Broken_Authentication.md` (unsalted SHA-256)
