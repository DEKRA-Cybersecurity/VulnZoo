# CareOtter Cloud API Documentation

> **Path**: `cloud_api/careotter/`  
> **Port**: `:5002` (Docker)  
> **Purpose**: HTTP-to-IGP bridge between clients and the CareOtter medical device.

---

## Overview

The CareOtter Cloud API is a Flask application that acts as an intermediary between HTTP clients (mobile apps, web dashboards) and the CareOtter DAI device. It translates REST requests into the legacy IGP v4 binary protocol and provides persistent storage via SQLite.

### Operating Modes

| Mode | `VULNERABLE` | Behavior |
|------|-------------|----------|
| Vulnerable | `1` (default) | Debug mode ON, raw WiFi PSK exposed, format strings forwarded, Werkzeug debugger active |
| Safe | `0` | Debug OFF, sensitive data filtered, generic error messages |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     CareOtter Cloud API                         │
│                         (Docker :5002)                          │
├─────────────────────────────────────────────────────────────────┤
│  HTTP REST API  │  JWT Auth  │  IGP v4 Client  │  HTTP Client   │
│   (Flask)       │  (PyJWT)   │  (Binary TCP)   │  (vitals)      │
├─────────────────────────────────────────────────────────────────┤
│  SQLite DB — vitals_readings, device_events, device_config,     │
│  users (with roles)                                             │
└────────┬────────────────────────────────────────────────────────┘
         │                              │
         │ HTTP :5002                   │ IGP :9999 / HTTP :8081
         ▼                              ▼
┌─────────────────┐             ┌──────────────────────┐
│  Mobile Client  │             │   CareOtter Device   │
│  (Android App)  │             │   (192.168.2.1)      │
└─────────────────┘             └──────────────────────┘
```

---

## Database Schema

The API uses an embedded SQLite database (`/app/data/careotter.db` in Docker, fallback to `/tmp/careotter.db`).

### Tables

#### `vitals_readings`
Stores cardiac telemetry from the device.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK | Auto-increment |
| `timestamp` | REAL | Epoch time from sensor |
| `bpm` | INTEGER | Heart rate |
| `spo2` | INTEGER | Blood oxygen saturation |
| `ir_raw` | INTEGER | Raw IR sensor value |
| `red_raw` | INTEGER | Raw red sensor value |
| `source` | TEXT | "simulator" or "hardware" |
| `created_at` | TIMESTAMP | Insertion time |

#### `device_events`
Tracks administrative events.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK | Auto-increment |
| `event_type` | TEXT | auth_success, auth_fail, config_change, etc. |
| `details` | TEXT | Additional context |
| `ip_address` | TEXT | Client IP |
| `timestamp` | TIMESTAMP | Event time |

#### `device_config`
Key-value store for persistent settings.

| Column | Type | Description |
|--------|------|-------------|
| `key` | TEXT PK | Setting name |
| `value` | TEXT | Setting value |
| `updated_at` | TIMESTAMP | Last modification |

#### `devices`
Each physical device (identified by BLE MAC) is owned by one patient user.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK | Auto-increment |
| `mac` | TEXT UNIQUE | BLE MAC address |
| `patient_username` | TEXT FK → users.username | Owning patient |
| `device_name` | TEXT | Human-readable name |
| `auth_hash` | TEXT | 12-hex factory signature |
| `registered_at` | TIMESTAMP | Registration time |

#### `caregiver_assignments`
Links caregivers to the patients they are authorized to monitor.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK | Auto-increment |
| `caregiver_username` | TEXT FK → users.username | Caregiver user |
| `patient_username` | TEXT FK → users.username | Patient user |
| `created_at` | TIMESTAMP | Assignment time |

> **Note:** The `caregiver_assignments` table exists in the schema and is used by the UI to populate the caregiver dashboard dropdown. However, the BOLA-vulnerable endpoint (`/api/caregiver/patient/<username>/vitals`) does **not** query this table, so the vulnerability remains exploitable.

#### `users`
User accounts with role-based access control.

| Column          | Type        | Description                             |
| --------------- | ----------- | --------------------------------------- |
| `id`            | INTEGER PK  | Auto-increment                          |
| `username`      | TEXT UNIQUE | Login name                              |
| `password_hash` | TEXT        | SHA-256 hash of password                |
| `role`          | TEXT        | `admin`, `patient`, `caregiver` |
| `created_at`    | TIMESTAMP   | Account creation time                   |

### Default User

On first startup, the API automatically creates:

| Username | Password         | Role    |
| -------- | ---------------- | ------- |
| `admin`  | `CareOtter2026!` | `admin` |
| `patient` | `johnny123` | `patient` |
| `caregiver` | `Caregiver2026!` | `caregiver` |

> ⚠️ **Intentional vulnerability**: Passwords are stored with simple SHA-256 hashing (no salt, no bcrypt/Argon2), making them susceptible to rainbow table attacks if the database is exfiltrated.

---

## Authentication

### Admin Login

`POST /api/auth/login`

Authenticates against the local SQLite user database. The endpoint verifies the username and password (SHA-256 without salt) and **requires the user role to be `admin`**. On success, a JWT containing the role is issued.

```bash
curl -X POST http://localhost:5002/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "CareOtter2026!"}'
```

**Response (success):**
```json
{
  "token": "<JWT>",
  "expires_in": "8h",
  "type": "Bearer",
  "role": "admin"
}
```

**Response (invalid credentials):**
```json
{
  "error": "Invalid username or password",
  "code": "AUTH_FAIL"
}
```

**Response (non-admin user):**
```json
{
  "error": "Admin access required",
  "code": "FORBIDDEN"
}
```

> 🔒 **Note**: The old hardcoded device token login (`{"token": "OtterMobile2026"}`) has been removed from the web admin panel. The Admin Panel now exclusively uses database-backed username/password authentication with role enforcement.

### Caregiver Login

`POST /api/auth/login/caregiver`

Authenticates against the local SQLite user database and **requires the user role to be `caregiver`**.

```bash
curl -X POST http://localhost:5002/api/auth/login/caregiver \
  -H "Content-Type: application/json" \
  -d '{"username": "caregiver", "password": "Caregiver2026!"}'
```

**Response (success):**
```json
{
  "token": "<JWT>",
  "expires_in": "8h",
  "type": "Bearer",
  "role": "caregiver"
}
```

### Programmatic User Verification

The `DatabaseService.verify_user(username, password)` method is available for role-based authentication in custom scripts:

```python
from services.database_service import DatabaseService
db = DatabaseService()
user = db.verify_user('admin', 'CareOtter2026!')
# Returns: {'id': 1, 'username': 'admin', 'role': 'admin', 'created_at': '...'}
```

### JWT Protected Endpoints

Protected endpoints require:
```
Authorization: Bearer <JWT>
```

---

## API Endpoints

### Public Endpoints (No Auth)

| Method | Endpoint | IGP Cmd | Description |
|--------|----------|---------|-------------|
| GET | `/api/health` | — | API status, version, device connectivity |
| GET | `/hint` | — | Unauthenticated hint — reveals device needs provisioning |
| GET | `/initialize_iot` | — | **Out of scope** — lab playability fallback only. Auto-creates default users, uses Ethernet fallback (`192.168.2.1`), and optionally pushes WiFi credentials to the Pi via IGP if `WIFI_SSID`/`WIFI_PSK` env vars are set. Not part of attack chains. |
| GET | `/api/device/info` | 0x01 SYS_INFO | Kernel version and architecture |
| GET | `/api/device/status` | 0x05 VERIFY_STATUS | Module diagnostics (vulnerable to format string) |
| GET | `/api/vitals` | HTTP :8081 | Current BPM/SpO2 from sensor |
| GET | `/api/vitals/history` | HTTP :8081 | Vitals history buffer |
| POST | `/api/auth/login/patient` | — | Patient login → JWT |
| POST | `/api/auth/login/caregiver` | — | Caregiver login → JWT |

#### `/hint` — Device Provisioning Hint

```bash
curl http://localhost:5002/hint
```

**Response (200, plaintext):**
```
CareOtter is in an initial state where it needs an administrator to configure it
before it can connect to the cloud API. The use of CareOtter Medical Service
configuration software is not authorized, but you can analyze how this software
initializes the device and introduces it into a common network.
```

**Purpose in the lab:** This endpoint is intentionally unauthenticated and serves as the **starting point for reconnaissance**. It tells the attacker that the bedside monitor ships without a pre-configured Cloud URL and requires initialization via "CareOtter Medical Service configuration software." Reverse-engineering that software (the Android app) or simply enumerating BLE GATT services reveals the hidden Factory Provisioning Channel (`0xFF10`) where WiFi credentials and the Cloud API endpoint can be written.

**Vulnerability mapping:** CWE-200 (Information Disclosure) · OWASP IoT I3

---

#### `/initialize_iot` — Fallback Lab Initialization

> **⚠️ OUT OF SCOPE:** This endpoint is a **lab playability fallback** for Phase 2 (post-provisioning operational mode). It shortcuts the intended BLE provisioning flow and is **not part of any documented attack chain** in the CareOtter playbook. See `CareOtter.md` → *Lab Scope and Phases* for the boundary definition.

```bash
# No body required — one-click GET for lab operators
curl -X GET http://localhost:5002/initialize_iot
```

**Optional — automatic WiFi provisioning:**

If you want `/initialize_iot` to also push WiFi credentials to the bedside monitor over IGP (so the Pi joins your WiFi network without manual BLE provisioning), set the `WIFI_SSID` and `WIFI_PSK` environment variables before starting the container.

Using `docker run`:
```bash
docker run -e WIFI_SSID="MyNetwork" -e WIFI_PSK="secret123" -p 5002:5002 careotter-api
```

Using `docker compose` (add to `cloud_api/careotter/.env` or export in your shell):
```bash
# .env
WIFI_SSID=MyNetwork
WIFI_PSK=secret123
```

Then start the stack as usual:
```bash
cd cloud_api/careotter
docker compose up -d --build

# Trigger initialization — the Pi will receive the WiFi config over Ethernet
curl http://localhost:5002/initialize_iot
```

> **What happens:** The Cloud API temporarily switches its IGP target to `192.168.2.1`, authenticates with the hardcoded admin token (`OtterMobile2026`), sends command `0x06 SET_WIFI` with the supplied SSID/PSK, then restores the original `DEVICE_IP`. The Pi's wireless interface (`phy0-sta0`) will attempt to associate with the network using UCI (`uci set wireless...@wifi-iface[0].ssid='...'`).

![[initialize_iot.png]]

**Response (200) — when DB is empty:**
```json
{
  "status": "initialized",
  "message": "Default users created. For the real provisioning flow, discover the hidden BLE service (0xFF10).",
  "admin":     {"username": "admin",     "password": "CareOtter2026!"},
  "patient":   {"username": "patient",   "password": "patient123"},
  "caregiver": {"username": "caregiver", "password": "Caregiver2026!"},
  "device_ip": "192.168.2.1",
  "device_registered": false,
  "device_mac": null,
  "wifi_provisioned": false,
  "wifi_result": null,
  "devices_seeded": [
    {"mac": "AA:BB:CC:11:22:33", "ip": "192.168.10.47",
     "patient_username": "patient_alice",
     "auth_hash": "A1B2C3D4E5F6", "stored": true},
    {"mac": "DD:EE:FF:44:55:66", "ip": "192.168.10.63",
     "patient_username": "patient_bob",
     "auth_hash": "0F1E2D3C4B5A", "stored": true},
    {"mac": "B8:27:EB:79:53:C3", "ip": "192.168.2.1",
     "patient_username": null,
     "auth_hash": "9C0C306DEF2A", "stored": true}
  ]
}
```

**Response (409) — when users already exist:**
```json
{"error": "System already initialized. Use /admin/device/register for signature-based registration."}
```

**Purpose (playability only):** Ensures the lab remains playable if the attacker never discovers the BLE provisioning vector. Creates default accounts and falls back to Ethernet polling (`192.168.2.1`). This is **not a vulnerability** to be tested or reported; it exists solely to prevent a dead-end lab state.

##### Seeded Devices (3) — what `/initialize_iot` writes to SQLite

Since 2026-05-20, `initialize_iot` populates the `devices` table with three
rows so the patient self-service flow has something to bind to without
manual operator setup:

| # | Source | MAC | `auth_hash` (12 hex) | `patient_username` | `device_name` |
|---|---|---|---|---|---|
| 1 | Demo (randomised) | `secrets`-generated `AA:BB:CC:..` | `secrets.token_hex(6).upper()` | `patient_alice` (auto-created with random password) | `CareOtter_HR (demo-alice)` |
| 2 | Demo (randomised) | `secrets`-generated | `secrets.token_hex(6).upper()` | `patient_bob` (auto-created) | `CareOtter_HR (demo-bob)` |
| 3 | **Real Pi** | resolved from `http://192.168.2.1:8081/health` at seed time; falls back to `00:00:00:00:00:00` if the Pi is unreachable | `DatabaseService.EXPECTED_DEVICE_SIGNATURE` → `9C0C306DEF2A` (matches `careservice.c::DEVICE_SIGNATURE` and `cloud_uploader.py::device_hash`) | empty string `''` — **intentionally unclaimed**; the patient claims via `POST /api/devices/register-by-hash` | `CareOtter_HR` |

The two demo rows exist so `GET /api/devices` and the admin dashboard show
realistic-looking fleet data immediately after `/initialize_iot`. They use
random MACs/hashes so they can't be confused with the real Pi and are
already bound to demo patients so they don't compete for the `patient`
account.

The Pi row uses the canonical 12-hex factory code so two flows converge on
the same row:
- The **patient** logs in as `patient`, types `9C0C306DEF2A` in the
  Device Registration Code input → `POST /api/devices/register-by-hash`
  updates row #3 `patient_username` from `''` to `patient`.
- The **Pi** pushes vitals via `cloud_uploader.py` with
  `X-Device-Hash: 9C0C306DEF2A` → `device_push_vitals` matches the row
  by MAC; if seeded with placeholder MAC, `adopt_mac_for_signature` rewrites
  the row's MAC in-place on the first push (see
  `docs/CareOtter/IoT/CareOtter_IoT.md` § Push Architecture).

Schema constraint `patient_username TEXT NOT NULL` is honoured by storing
the empty string `''` as the "unclaimed" sentinel. `get_devices_for_patient`
filters by exact match, so an unclaimed row never leaks to any logged-in
user.

---

#### `/admin/device/register` — Signature-Based Device Registration

```bash
curl -X POST http://localhost:5002/admin/device/register \
  -H "Content-Type: application/json" \
  -d '{
    "signature": "9C0C306DEF2A",
    "mac": "B8:27:EB:XX:XX:XX",
    "patient": {"username":"alice","password":"secret1"},
    "admin": {"username":"dr_bob","password":"secret2"},
    "device_ip": "192.168.1.50"
  }'
```

**Response (200):**
```json
{"status":"registered","device_mac":"B8:27:EB:XX:XX:XX","device_ip":"192.168.1.50"}
```

**Response (403) — invalid signature:**
```json
{"error":"Registration failed — invalid signature or DB error"}
```

**What happens on success:**
1. The Cloud API verifies the hardcoded factory signature.
2. Creates (or updates) the patient and admin users in SQLite with the supplied passwords.
3. Registers the device MAC linked to the patient.
4. Stores `device_ip` as the vitals polling target.
5. Switches the vitals collector from idle/Ethernet to WiFi polling.

**Vulnerability:** The signature is hardcoded and identical across all devices. An attacker who intercepts this POST (by owning the `cloud_url` via BLE `cloud_set`) captures the signature and can replay it to register a rogue device or overwrite the real admin credentials.

---

#### `/api/devices/register-by-hash` — Patient self-service device binding

```bash
curl -X POST http://localhost:5002/api/devices/register-by-hash \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <patient JWT>" \
  -d '{"device_hash":"9C0C306DEF2A"}'
```

The patient types the 12-hex code printed on the device sticker. The cloud looks up the row in `devices` by `auth_hash`, then updates `patient_username` from the placeholder (empty string) to the patient's username from the JWT.

**Code format (since 2026-05-20):**
- **12 hexadecimal characters**, case-insensitive (`[0-9A-Fa-f]{12}`).
- Stored in SQLite as-is (no `CareOtter` prefix anymore — strip happens at the boundary via `DatabaseService.canonical_hash` for any legacy client that still sends the prefixed form).
- 48 bits of entropy per device; randomized per row in `/initialize_iot` for demo devices.

**Hardening on the endpoint:**

| Layer | What it does |
|---|---|
| Format guard | `len == 12` and hex-only — rejects with **400** before the DB lookup, does not count against rate limit (user typos shouldn't burn budget) |
| Rate limit | Per-user sliding window: **5 failures / 15 min**. Returns **429** with `Retry-After` header when exceeded. Successful registrations don't consume budget |
| Constant-time compare | `hmac.compare_digest` over canonicalised inputs — no timing oracle distinguishing "wrong hash" from "no such hash" |
| Uniform error | All failures return **404 "Invalid device hash"**, so an attacker can't enumerate which hashes exist vs. which exist-but-belong-to-someone-else |
| Audit log | Each failure: `[register-by-hash] FAIL user=<jwt-sub> ip=<remote_addr> hash_len=<n>`. Each rate-limit hit: `[register-by-hash] RATE_LIMITED user=<jwt-sub> ip=<…> retry_after=<n>s` |

**Response (200):**
```json
{"status":"registered","device_mac":"B8:27:EB:79:53:C3",
 "device_name":"CareOtter_HR","patient_username":"patient"}
```

**Response (400) — wrong format:**
```json
{"error":"Device hash must be 12 hexadecimal characters"}
```

**Response (404) — unknown / not owned (indistinguishable on purpose):**
```json
{"error":"Invalid device hash"}
```

**Response (429) — rate limited:**
```json
{"error":"Too many registration attempts. Try again later.",
 "retry_after_seconds": 873}
```

---

### JWT Protected Endpoints

| Method | Endpoint | IGP Cmd | Description |
|--------|----------|---------|-------------|
| GET | `/api/network` | 0x03 GET_NETWORK | WiFi config (raw exposes PSK) |
| POST | `/api/network/wifi` | 0x06 SET_WIFI | Configure WiFi (shell injection) |
| POST | `/api/config/preferences` | 0x04 SET_PREFS | TLV preferences (integer underflow) |
| POST | `/api/config/thresholds` | 0x08 SET_THRESHOLD | Clinical alert thresholds |
| POST | `/api/services/restart` | 0x09 REBOOT_SERVICE | Restart init.d services |
| GET | `/api/logs` | 0x0A GET_LOG | Last 512 bytes of device log |
| GET | `/api/caregiver/patient/<username>/vitals` | — | **VULN: BOLA** — caregiver vitals view lacks ownership check |
| GET | `/api/caregiver/patients` | — | List patients assigned to the authenticated caregiver |
| POST | `/api/patient/caregivers` | — | Patient adds a caregiver to their account |
| GET | `/api/patient/caregivers` | — | List caregivers assigned to the authenticated patient |
| DELETE | `/api/patient/caregivers/<username>` | — | Patient removes a caregiver |
| DELETE | `/api/devices/me` | — | Patient unregisters their own device |

### Web UI Pages

| URL | Auth | Page |
|-----|------|------|
| `/` | Cookie patient | Patient monitor — live vitals + caregiver management |
| `/patient/login` | Public | Patient login form |
| `/history` | Cookie patient | Historical vitals table |
| `/caregiver/dashboard` | Cookie caregiver | Caregiver dashboard — patient dropdown + vitals |
| `/admin/login` | Public | Admin login form |
| `/admin/dashboard` | Cookie admin | Admin dashboard |
| `/admin/network` | Cookie admin | WiFi configuration |
| `/admin/config` | Cookie admin | Clinical thresholds + TLV preferences |
| `/admin/services` | Cookie admin | Restart init.d services |
| `/admin/logs` | Cookie admin | Device log viewer |

### Admin Panel (Web UI)

| URL | Page |
|-----|------|
| `/` | Public dashboard — live vitals |
| `/admin/login` | Username/password login form |
| `/admin/dashboard` | Live vitals + device info |
| `/admin/network` | View/change WiFi configuration |
| `/admin/config` | Clinical thresholds + TLV preferences |
| `/admin/services` | Restart init.d services |
| `/admin/logs` | Device log viewer + vitals history table |
| `/history` | SQLite vitals history with stats and export |

---

## Database Service API

### User Management Methods

```python
from services.database_service import DatabaseService
,
db = DatabaseService()

# Create a new user
db.create_user(username="dr_smith", password="secret123", role="doctor")

# Verify credentials (returns user dict without password_hash)
user = db.verify_user("admin", "CareOtter2026!")

# List all users
users = db.list_users()  # [{'id': 1, 'username': 'admin', 'role': 'admin', ...}]

# Update role
db.update_user_role("dr_smith", "admin")

# Delete user
db.delete_user("dr_smith")
```

### Vitals Methods

```python
# Store vitals reading
db.store_vitals({"timestamp": 1758317888.48, "bpm": 72, "spo2": 98, ...})

# Get history
db.get_vitals_history(hours=24, limit=100)

# Get statistics
db.get_vitals_stats(hours=24)

# Database info
db.get_db_info()
```

---

## Vulnerability Surface

### Critical

| #   | Type                  | Location              | Evidence                                                  | OWASP API Top 10 2023 | CWE |
| --- | --------------------- | --------------------- | --------------------------------------------------------- | --------------------- | --- |
| 1   | Weak JWT Secret       | `config.py`           | `JWT_SECRET = 'careotter_jwt_2026'`                       | API2: Broken Authentication | CWE-798 |
| 2   | Debug Mode RCE        | `app.py`              | `debug=(vuln == 1)` enables Werkzeug console              | API8: Security Misconfiguration | CWE-489 |
| 3   | Format String Proxy   | `app.py`              | `/api/device/status?module=` passes unsanitized to device | API10: Unsafe Consumption of APIs | CWE-134 |
| 4   | Weak Password Storage | `database_service.py` | SHA-256 without salt (rainbow-table vulnerable)           | API2: Broken Authentication | CWE-916 |

### High

| # | Type | Location | Evidence | OWASP API Top 10 2023 | CWE |
|---|------|----------|----------|---------------------| --- |
| 5 | WiFi PSK Disclosure | `device_service.py` | `raw` field in `/api/network` | API1: Broken Object Level Authorization | CWE-200 |
| 6 | Info Leak | `app.py` | `/api/health` exposes device IP | API8: Security Misconfiguration | CWE-200 |
| 7 | Shell Injection | `careservice.c` | `SET_WIFI` uses `system()` without escaping | API10: Unsafe Consumption of APIs | CWE-78 |
| 8 | Cross-User Vitals Access | `app.py` | `/api/caregiver/patient/<username>/vitals` lacks ownership check | API1:2023 — Broken Object Level Authorization | CWE-639 / CWE-863 |

### Medium

| #   | Type                | Location | Evidence                                                                                                                                 | OWASP API Top 10 2023 | CWE |
| --- | ------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------- | --------------------- | --- |
| 8   | Partial Role Checks | `app.py` | Login enforces `admin` role, but JWT-protected API endpoints only validate token signature/expiry, not the `role` claim inside the token | API5: Broken Function Level Authorization | CWE-285 |
| 9   | No Rate Limiting    | Global   | `flask-limiter` not implemented                                                                                                          | API4: Unrestricted Resource Consumption | CWE-770 |
| 10  | Plaintext HTTP      | Global   | No TLS termination                                                                                                                       | API8: Security Misconfiguration | CWE-319 |

### IGP Authentication Flow and Race Condition (Cloud API → Device)

#### Auth → Cmd → Deauth cycle

Each protected admin operation follows the **auth → cmd → deauth** cycle
implemented in `DeviceService._exec_protected()`:

```
Admin HTTP request POST /api/network (with valid JWT)
  │
  ├─ TCP conn 1 → IGP 0x02 AUTHENTICATE  → authenticated=1  ← WINDOW OPENS
  │   [race window: external TCP client can inject privileged commands]
  ├─ TCP conn 2 → IGP 0x03 GET_NETWORK   → data returned
  │   [race window: external TCP client can still inject before deauth]
  └─ TCP conn 3 → IGP 0x0D DEAUTHENTICATE → authenticated=0  ← WINDOW CLOSES
```

The `threading.Lock` in `DeviceService._igp_lock` serializes concurrent Cloud API
requests so two admin HTTP endpoints cannot interleave their three connections.
**It does not protect against external TCP clients connecting directly to `:9999`.**

#### Vulnerability: Authentication State Race Condition (CWE-362)

> See primary entry: `docs/CareOtter/IoT/CareOtter_IoT.md` — IoT:I7.2

The problematic pattern is in `device_service.py`:

```python
# device_service.py — DeviceService._exec_protected()

def _exec_protected(self, cmd_fn, *args, **kwargs):
    with self._igp_lock:            # ← serializes Cloud API requests only
        self._igp.authenticate(…)   # TCP conn 1 → authenticated=1  [WINDOW OPENS]
        try:
            return cmd_fn(…)        # TCP conn 2 → command
        finally:
            self._igp.deauthenticate()  # TCP conn 3 → authenticated=0  [WINDOW CLOSES]
```

Each of the three calls inside `_exec_protected` opens **a new TCP socket**
(`IGPClient.send_command()` creates and destroys a socket per call). The Lock
prevents two Cloud API goroutines from interleaving, but between connection 1 and
connection 3 the device's `authenticated` flag is `1` and any external TCP client
on `192.168.2.0/24` can execute privileged commands without credentials.

#### Code path: from HTTP endpoint to IGP race window

```
POST /api/network
    │
    └─ app.py: get_network()
           @token_required  ← JWT verified (Cloud API layer)
           device.get_network_config()
               │
               └─ device_service.py: _exec_protected(self._igp.get_network)
                      _igp_lock.acquire()
                      self._igp.authenticate("OtterMobile2026")
                      │  ← igp_client.py: send_command(0x02)
                      │  ← socket.create_connection(:9999)  ← TCP SYN visible to attacker
                      │  ← socket.close()
                      │
                      │  ▼ authenticated=1 on device — WINDOW OPEN ▼
                      │
                      self._igp.get_network()
                      │  ← send_command(0x03) → socket.create_connection(:9999)
                      │  ← socket.close()
                      │
                      self._igp.deauthenticate()   [finally block]
                         ← send_command(0x0D) → socket.create_connection(:9999)
                         ← socket.close()
                         ▲ authenticated=0 — WINDOW CLOSED ▲
                      _igp_lock.release()
```

#### Impact table

| Window | Duration | Exploitable by |
|--------|----------|----------------|
| Between conn 1 (auth) and conn 2 (cmd) | ~1–5 ms | Direct TCP client on :9999 |
| Between conn 2 (cmd) and conn 3 (deauth) | ~1–5 ms | Direct TCP client on :9999 |
| Two concurrent Cloud API admin requests | Serialized by `_igp_lock` | Not exploitable via Cloud API |

---

## Deployment

### Recommended: `cloudctl.sh`

Use the provided helper script to start the stack. It auto-detects your host's active WiFi interface, extracts the SSID and PSK from NetworkManager, and exports them as `WIFI_SSID`/`WIFI_PSK` so `/initialize_iot` can push WiFi credentials to the Pi automatically.

```bash
cd cloud_api/careotter
./cloudctl.sh start        # build + up -d with auto WiFi detection
./cloudctl.sh start --no-wifi  # skip WiFi credential injection
./cloudctl.sh stop         # docker compose down -v
./cloudctl.sh restart      # stop + start

# Verify
curl http://localhost:5002/api/health
```

### Manual: `docker compose`

If you prefer full manual control:

```bash
cd cloud_api/careotter
docker compose up -d --build

# Verify
curl http://localhost:5002/api/health
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VULNERABLE` | `1` | Enable/disable vulnerable features |
| `DEVICE_IP` | `192.168.2.1` | CareOtter device IP |
| `IGP_PORT` | `9999` | IGP protocol port |
| `HTTP_PORT` | `8081` | Medical sensor HTTP port |
| `JWT_SECRET` | `careotter_jwt_2026` | JWT signing key |
| `JWT_EXPIRATION_HOURS` | `8` | Token validity |
| `PORT` | `5002` | API listening port |
| `DB_PATH` | `/app/data/careotter.db` | SQLite database path |
| `WIFI_SSID` | *(empty)* | WiFi network name to push to the device via `/initialize_iot` |
| `WIFI_PSK` | *(empty)* | WiFi passphrase to push to the device via `/initialize_iot` |

---

## References

- Parent Stage: `cloud_api/CONTEXT.md`
- Device Lab: `labs/careotter/CONTEXT.md`
- Mobile App: `vulnzoo_apps/careotter_app/CONTEXT.md`
- IGP Protocol: `docs/CareOtter/CareOtter.md`
