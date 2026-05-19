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

#### `users` *(new)*
User accounts with role-based access control.

| Column          | Type        | Description                             |
| --------------- | ----------- | --------------------------------------- |
| `id`            | INTEGER PK  | Auto-increment                          |
| `username`      | TEXT UNIQUE | Login name                              |
| `password_hash` | TEXT        | SHA-256 hash of password                |
| `role`          | TEXT        | `admin`, `user`, `operator`, `readonly` |
| `created_at`    | TIMESTAMP   | Account creation time                   |

### Default User

On first startup, the API automatically creates:

| Username | Password         | Role    |
| -------- | ---------------- | ------- |
| `admin`  | `CareOtter2026!` | `admin` |

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
  "admin": {"username": "admin", "password": "CareOtter2026!"},
  "patient": {"username": "patient", "password": "patient123"},
  "device_ip": "192.168.2.1"
}
```

**Response (409) — when users already exist:**
```json
{"error": "System already initialized. Use /admin/device/register for signature-based registration."}
```

**Purpose (playability only):** Ensures the lab remains playable if the attacker never discovers the BLE provisioning vector. Creates default accounts and falls back to Ethernet polling (`192.168.2.1`). This is **not a vulnerability** to be tested or reported; it exists solely to prevent a dead-end lab state.

---

#### `/admin/device/register` — Signature-Based Device Registration

```bash
curl -X POST http://localhost:5002/admin/device/register \
  -H "Content-Type: application/json" \
  -d '{
    "signature": "CareOtterFactorySig2026",
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

### JWT Protected Endpoints

| Method | Endpoint | IGP Cmd | Description |
|--------|----------|---------|-------------|
| GET | `/api/network` | 0x03 GET_NETWORK | WiFi config (raw exposes PSK) |
| POST | `/api/network/wifi` | 0x06 SET_WIFI | Configure WiFi (shell injection) |
| POST | `/api/config/preferences` | 0x04 SET_PREFS | TLV preferences (integer underflow) |
| POST | `/api/config/thresholds` | 0x08 SET_THRESHOLD | Clinical alert thresholds |
| POST | `/api/services/restart` | 0x09 REBOOT_SERVICE | Restart init.d services |
| GET | `/api/logs` | 0x0A GET_LOG | Last 512 bytes of device log |

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
