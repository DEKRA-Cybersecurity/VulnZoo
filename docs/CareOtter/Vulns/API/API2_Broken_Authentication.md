---
id: API2:2023
title: Broken Authentication
category: API
status: DONE
severity: High
owasp: API2:2023 — Broken Authentication
cwe: CWE-287 (Improper Authentication) / CWE-308 (Use of Single-factor Authentication) / CWE-759 (Use of a One-Way Hash without a Salt)
source_docs:
  - CareOtter_API.md Vulnerability Surface
affected_components:
  - cloud_api/careotter/api_server/app.py
  - cloud_api/careotter/api_server/core/jwt_service.py
  - cloud_api/careotter/api_server/core/decorators.py
  - cloud_api/careotter/api_server/services/database_service.py
  - cloud_api/careotter/api_server/config.py
verified_date: 2026-05-20
---

# API2 — Broken Authentication

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
### 3. Sensitive operations without password confirmation

Multiple endpoints perform security-critical actions without requiring the user's current password:

| Endpoint                                    | Action                           | Password confirmation? |
| ------------------------------------------- | -------------------------------- | ---------------------- |
| `DELETE /api/devices/me`                    | Unregister patient's device      | ❌ No                   |
| `POST /api/patient/caregivers`              | Assign a caregiver               | ❌ No                   |
| `DELETE /api/patient/caregivers/<username>` | Remove a caregiver               | ❌ No                   |
| `POST /api/network/wifi`                    | Change device WiFi credentials   | ❌ No                   |
| `POST /api/config/thresholds`               | Modify clinical alert thresholds | ❌ No                   |
| `POST /api/services/restart`                | Restart device services          | ❌ No                   |

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
  -w /usr/share/wordlists/rockyou.txt \
  -mr "token" \
  -mc all
```

![[API-02-brute_force_john_doe.png]]

---
### 2. Perform sensitive operation without password confirmation

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

### Require password confirmation for sensitive operations

```python
# Example pattern for DELETE /api/devices/me
current_password = data.get('current_password', '')
if not db.verify_user(username, current_password):
    return jsonify({'error': 'Current password required'}), 403
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
## References

- `CareOtter_API.md` Vulnerability Surface
- `cloud_api/careotter/api_server/app.py` (`login`, `login_patient`, `login_caregiver`, `device_register`, `initialize_iot`, `delete_my_device`)
- `cloud_api/careotter/api_server/core/jwt_service.py`
- `cloud_api/careotter/api_server/core/decorators.py`
- `cloud_api/careotter/api_server/services/database_service.py` (`_hash_password`, `verify_user`, `register_device_with_signature`)
- `cloud_api/careotter/api_server/config.py`
