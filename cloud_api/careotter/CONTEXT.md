# CareOtter Cloud API (Layer 2 Sub-stage)

**Stage Purpose**: Deploy Dockerized cloud backend that acts as an intermediary between mobile clients and the CareOtter medical device, bridging HTTP REST API to the binary IGP v4 protocol with intentional security vulnerabilities for IoT/medical device security training.

**Parent Stage**: `cloud_api/`

## Inputs

| Layer | Source Path | Role/Description |
|-------|-------------|------------------|
| **Layer 2 (Parent)** | `cloud_api/CONTEXT.md` | Global cloud API routing and patterns |
| **Layer 3** | `docs/CareOtter/` | Medical device specifications, BLE protocol details |
| **Layer 4** | `docker-compose.yml` | Service orchestration for Flask API |
| **Layer 4** | `api_server/` | Flask API with JWT, IGP client, device services |
| **Layer 4** | `api_server/core/igp_client.py` | IGP v4 protocol implementation (binary TCP) |
| **Layer 4** | `api_server/services/` | Device, vitals and database service layers |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     CareOtter Cloud API                         │
│                   (network_mode: host :5002)                    │
├─────────────────────────────────────────────────────────────────┤
│  HTTP REST API  │  JWT Auth  │  IGP v4 Client  │  HTTP Client   │
│   (Flask)       │  (PyJWT)   │  (Binary TCP)   │  (vitals)      │
└────────┬────────────────────────────────────────────────────────┘
         │                              │
         │ HTTP :5002                   │ IGP :9999 / HTTP :8081
         ▼                              ▼
┌─────────────────┐             ┌──────────────────────┐
│  Mobile Client  │             │   CareOtter Device   │
│  (Android App)  │             │   (192.168.2.1)      │
└─────────────────┘             └──────────────────────┘
```

**Network topology:**
- Laptop ↔ Raspberry Pi: direct Ethernet cable (192.168.2.2 ↔ 192.168.2.1)
- Laptop WiFi: dynamic DHCP IP (auto-detected from `wlan0`)
- Android phone: WiFi only — uses laptop WiFi IP to reach the API
- `network_mode: host` allows the container to read host interfaces and route to 192.168.2.1

## Process

### 1. Analyze Deployment Requirements

**Components:**
| Component | Type | Technology | Port | Purpose |
|-----------|------|------------|------|---------|
| API Server | Docker (host network) | Python 3.11/Flask | 5002 | HTTP→IGP gateway |
| SQLite DB | Volume | `careotter_data:/app/data` | — | Vitals history, users, devices |

**Protocol Mapping:**

| HTTP Endpoint | Method | IGP Command | Auth | Description |
|---------------|--------|-------------|------|-------------|
| `/api/health` | GET | — | No | Status + WiFi IP for BLE advertising |
| `/api/device/info` | GET | 0x01 SYS_INFO | No | Kernel/architecture info |
| `/api/auth/login` | POST | — | No | Login with username+password → JWT |
| `/api/device/status` | GET | 0x05 VERIFY_STATUS | No | Module diagnostics (format string proxy) |
| `/api/vitals` | GET | — | No | Latest BPM/SpO2 from SQLite (pushed by device) |
| `/api/vitals/history` | GET | — | No | SQLite history (previously polled from device buffer) |
| `/api/vitals/db/history` | GET | — | No | SQLite history (device_mac, patient filter) |
| `/api/vitals/db/stats` | GET | — | No | Aggregated stats from SQLite |
| `/api/network` | GET | 0x03 GET_NETWORK | JWT | WiFi config (exposes PSK in vuln=1) |
| `/api/network/wifi` | POST | 0x06 SET_WIFI | JWT | Configure WiFi SSID/PSK |
| `/api/config/preferences` | POST | 0x04 SET_PREFS | JWT | TLV preferences (integer underflow vuln) |
| `/api/config/thresholds` | POST | 0x08 SET_THRESHOLD | JWT | Clinical alert thresholds |
| `/api/services/restart` | POST | 0x09 REBOOT_SERVICE | JWT | Restart init.d service |
| `/api/logs` | GET | 0x0A GET_LOG | JWT | Last 512 bytes of device log |
| `/api/devices` | GET | — | JWT | List registered devices with patient owner |
| `/api/devices` | POST | — | JWT | Register/update device MAC → patient |
| `/api/devices/<mac>` | GET | — | JWT | Get device + patient info by MAC |
| `/api/devices/me` | GET | — | JWT (patient) | Authenticated patient's own device |
| `/api/devices/me` | DELETE | — | JWT (patient) | Patient unregisters their own device |
| `/api/user/devices` | GET | — | JWT | Devices owned by the authenticated user |
| `/api/auth/login/patient` | POST | — | No | Patient-only login (rejects role≠patient) |
| `/api/auth/login/caregiver` | POST | — | No | Caregiver-only login (rejects role≠caregiver) |
| `/api/auth/logout` | POST | — | No | Clears `careotter_token` cookie |
| `/api/caregiver/patients` | GET | — | JWT (caregiver) | Patients assigned to authenticated caregiver |
| `/api/caregiver/patient/<username>/vitals` | GET | — | JWT | **BOLA** — caregiver vitals view (no ownership check) |
| `/api/patient/caregivers` | POST | — | JWT (patient) | Patient adds a caregiver |
| `/api/patient/caregivers` | GET | — | JWT (patient) | List patient's caregivers |
| `/api/patient/caregivers/<username>` | DELETE | — | JWT (patient) | Patient removes a caregiver |
| `/api/db/info` | GET | — | No | Database debug info |
| `/api/db/test` | GET | — | No | Inserts a dummy vitals reading (debug) |
| `/admin/device/register` | POST | — | Signature (`9C0C306DEF2A`) | BLE-driven provisioning: registers device MAC + admin/patient credentials |
| `/api/device/vitals` | POST | — | `X-Device-MAC` + `X-Device-Hash` | Push endpoint — receives vitals from Pi's `cloud_uploader.py` |
| `/api/device/alerts` | POST | — | `X-Device-MAC` + `X-Device-Hash` | Push endpoint — receives alert events from Pi |
| `/api/devices/register-by-hash` | POST | — | JWT | Patient claims a device by entering its factory hash |
| `/initialize_iot` | GET | — | No | Fallback seed (creates default users, no auto-device) |
| `/hint` | GET | — | No | Out-of-scope hint endpoint (API-07) |

> **Internal IGP command not exposed as HTTP:** `0x0D DEAUTHENTICATE` — invoked
> automatically by `device_service._exec_protected()` after every admin command
> as part of the **auth → cmd → deauth** pattern (see dedicated section below).

**HTML Pages (auth model):**
| Path | Auth | Description |
|------|------|-------------|
| `/` | Cookie patient (`@web_patient_required`) | Latest stored vitals monitor + caregiver management |
| `/history` | Cookie patient | Historical vitals table (device MAC + patient columns) |
| `/patient/login` | Public | Patient login form (redirects to `/` on success) |
| `/caregiver/dashboard` | Cookie caregiver (`@web_caregiver_required`) | Caregiver dashboard — patient dropdown + vitals |
| `/admin/login` | Public | Admin login form |
| `/admin/dashboard` | Cookie admin (`@web_admin_required`) | Admin dashboard |
| `/admin/network` | Cookie admin | Network configuration |
| `/admin/config` | Cookie admin | Device preferences |
| `/admin/services` | Cookie admin | Service management |
| `/admin/logs` | Cookie admin | Device log viewer |

> Web auth uses the `careotter_token` HttpOnly cookie populated by `/api/auth/login*`.
> REST clients use the `Authorization: Bearer …` header on the same JWT.

**IGP v4 Protocol Header:**
```
┌─────────────────┬──────┬────────┬──────────┐
│  Magic (4)      │ Cmd  │ Status │  Len (2) │
│  0x43415245     │ (1)  │  0x00  │ payload  │
│    "CARE"       │      │        │          │
└─────────────────┴──────┴────────┴──────────┘
```

### 2. Database Schema

```
users                           devices
─────────────────────           ────────────────────────────
id                              id
username (UNIQUE)               mac (UNIQUE)  ← BLE MAC address
password_hash (SHA-256, no salt)patient_username → users.username
role (admin | patient | caregiver) device_name
created_at                      registered_at
                                auth_hash

vitals_readings                 device_events
─────────────────────────────   ──────────────────────────────
id                              id
device_mac → devices.mac        device_mac → devices.mac
timestamp (Unix float)          event_type
bpm, spo2, source               payload (JSON)
created_at                      created_at

caregiver_assignments           device_config
────────────────────────────────────────────────
id                              key (PK)
caregiver_username → users.username  value
patient_username → users.username    updated_at
created_at

vitals_minute_agg               vitals_hour_agg
────────────────────────────────────────────────
device_mac (PK)                 device_mac (PK)
bucket_ts (PK)                  bucket_ts (PK)
bpm_avg, bpm_min, bpm_max       bpm_avg, bpm_min, bpm_max
spo2_avg, spo2_min, spo2_max    spo2_avg, spo2_min, spo2_max
samples                         samples
```

**Default seed data:**

The database starts **empty**. Users and the default device only appear after one of:

1. `POST /admin/device/register` (signature-based BLE provisioning) — registers
   device MAC + patient/admin credentials sent by `ble_server.py`.
2. `POST /initialize_iot` (fallback / lab convenience) — seeds the rows below.

| Table | Entry (after fallback or provisioning) |
|-------|----------------------------------------|
| users | `admin` / `CareOtter2026!` (admin) |
| users | `john_doe` / `johnny123` (patient) |
| users | `care_john` / `Caregiver2026!` (caregiver) |
| devices | Pi placeholder (unclaimed until patient registers by hash or pushes vitals) |

> Older revisions of this document listed `admin123 / admin123` as a third seed
> user. That entry **does not exist** in any current seed path — remove from any
> remaining notes.

**Hardcoded credentials (centralised):**

| Constant | Value | Location |
|----------|-------|----------|
| `JWT_SECRET` (default) | `careotter_jwt_2026` | `config.py` |
| `_ADMIN_TOKEN` (IGP) | `OtterMobile2026` | `services/device_service.py` |
| `EXPECTED_DEVICE_SIGNATURE` | `9C0C306DEF2A` | `services/database_service.py` |

### 3. Apply Vulnerability Configuration

**Authentication (Critical):**

| Vuln # | Type | Location | Evidence |
|--------|------|----------|----------|
| #1 | Weak JWT Secret | `config.py` | `JWT_SECRET = 'careotter_jwt_2026'` |
| #2 | Unsalted SHA-256 | `database_service.py` | `hashlib.sha256(password)` — rainbow table attack |
| #3 | Debug Mode | `app.py` | `debug=(vuln == 1)` enables Werkzeug interactive debugger |
| #4 | Verbose Error Exposure | `app.py` | Global handler exposes exception type + message |

**Information Disclosure (High):**

| Vuln # | Type | Location | Evidence |
|--------|------|----------|----------|
| #5 | WiFi PSK Disclosure | `device_service.py` | `raw` field returns `/etc/config/wireless` with PSK |
| #6 | Topology disclosure on `/api/health` (legacy) | `app.py` | `/api/health` still returns `wifi_ip` of the operator PC; the BLE auto-discovery consumer was removed but the endpoint remains a topology oracle |
| #7 | Device MAC in DB | `database_service.py` | `devices.mac` returned in plaintext via `/api/devices` |

**Injection (Critical):**

| Vuln # | Type | Location | Evidence |
|--------|------|----------|----------|
| #8 | Format String Proxy | `app.py` `/api/device/status` | `?module=` passed unsanitized to device `snprintf()` |
| #9 | TLV Injection | `app.py` `/api/config/preferences` | Raw hex accepted without validation |

**Hardcoded Credentials:** see the *Hardcoded credentials (centralised)* table in
section 2 — three values: `JWT_SECRET`, `_ADMIN_TOKEN` (IGP) and
`EXPECTED_DEVICE_SIGNATURE` (BLE provisioning factory signature).

### 4. BLE Provisioning Flow (current)

The legacy ManufacturerData[0x08D4] auto-discovery — where the Pi advertised the
Cloud API WiFi IP over BLE for the Android app to consume — **was removed** (it
was an IoT:I3.1 leak and tied service startup to Docker). The current flow is:

```
Operator launches Cloud API (Docker, network_mode: host) on the laptop.
   └─ /api/health still reports wifi_ip but no one consumes it via BLE.

LoginActivity (Android) — user enters API IP manually (prefix + host octet).
   └─ Auto-detect via WifiManager pre-fills the prefix.
   └─ ICMP-ping button validates reachability.

BLE provisioning channel (hidden service 0xFF10):
   technician/installer writes
       { "cmd":"cloud_set", "url":"http://<laptop-ip>:5002" }
       { "cmd":"wifi_set", ... }
       { "cmd":"patient_set", ... }
       { "cmd":"admin_set",   ... }
   ble_server.py then POSTs to <cloud_url>/admin/device/register with
   signature "9C0C306DEF2A", which makes the Cloud API:
     • upsert the device MAC into devices.
     • create patient/admin users with the supplied credentials.
     • update Config.DEVICE_IP at runtime so subsequent IGP calls reach the Pi.
```

> The `/api/health` `wifi_ip` field is kept for backwards compatibility (debug
> tooling), but it is now a *vestigial* topology oracle — see Vuln #6.

### 5. Transform (Deployment Steps)

**Step 1: Deploy Docker Environment:**
```bash
cd cloud_api/careotter
docker compose up -d --build
# API available at http://<host-wlan0-ip>:5002
```

> **Important:** use `--build` on every code change. `docker compose restart` does NOT
> rebuild the image — Python files are baked into it at build time.

**Environment Variables:**
| Variable | Default | Description |
|----------|---------|-------------|
| `VULNERABLE` | 1 | Enable vulnerabilities (0=secure mode) |
| `DEVICE_IP` | *(empty in `config.py`; `192.168.2.1` in `docker-compose.yml`)* | CareOtter device IP. The runtime value is overwritten dynamically when `/admin/device/register` succeeds, so the env var is only the *seed* until BLE provisioning lands. |
| `IGP_PORT` | 9999 | IGP protocol port |
| `HTTP_PORT` | 8081 | Medical sensor HTTP port |
| `JWT_SECRET` | careotter_jwt_2026 | JWT signing key (weak, intentional) |
| `JWT_EXPIRATION_HOURS` | 8 | Token validity |
| `PORT` | 5002 | API listening port |
| `DB_PATH` | /app/data/careotter.db | SQLite database path (persisted volume) |

**Step 2: Verify connectivity:**
```bash
# Health check — should return wifi_ip of the laptop's wlan0
curl http://localhost:5002/api/health

# Login and get JWT
TOKEN=$(curl -s -X POST http://localhost:5002/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"CareOtter2026!"}' | jq -r '.token')

# List registered devices
curl -H "Authorization: Bearer $TOKEN" http://localhost:5002/api/devices

# Register a real device MAC
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mac":"AA:BB:CC:11:22:33","patient_username":"patient","device_name":"CareOtter_HR"}' \
  http://localhost:5002/api/devices
```

**Step 3: Exploit Vulnerabilities:**

| Endpoint | Vulnerability | Payload |
|----------|---------------|---------|
| `/api/auth/login` | Weak JWT secret | Crack HS256 with `careotter_jwt_2026` |
| `/api/device/status?module=...` | Format String Proxy | `?module=%x.%x.%x.%x` |
| `/api/network` | WiFi PSK Disclosure | GET with JWT → `raw` field contains PSK |
| `/api/health` | Info Disclosure | `wifi_ip` + `device` fields reveal topology |
| Any error endpoint | Debug Mode (vuln=1) | Trigger exception → Werkzeug PIN → RCE |

## Outputs

| Artifact | Path/Port | Description |
|----------|-----------|-------------|
| CareOtter API | `:5002` | Flask gateway HTTP→IGP |
| IGP Client | `core/igp_client.py` | Binary protocol implementation |
| Device Service | `services/device_service.py` | Business logic layer |
| Vitals Service | `services/vitals_service.py` | Medical sensor HTTP client |
| Database Service | `services/database_service.py` | SQLite persistence (vitals, users, devices) |

## Vulnerability Chains

### Chain 1: JWT Weak Secret → Admin Access → WiFi PSK Disclosure
```
POST /api/auth/login {"username":"admin","password":"CareOtter2026!"}
  ↓
Receive JWT signed with "careotter_jwt_2026"
  ↓
Crack/forge new JWT with arbitrary claims (e.g. role=admin)
  ↓
GET /api/network with forged JWT
  ↓
Extract 'raw' field → contains WiFi PSK in plaintext
```

### Chain 2: Format String Proxy → Stack Leak
```
GET /api/device/status?module=%x.%x.%x.%x
  ↓
module string passed unsanitized to device IGP 0x05
  ↓
Device snprintf() interprets %x as format specifier
  ↓
Stack values leaked in response
```

### Chain 3: Debug Mode → Werkzeug PIN → RCE
```
Trigger any unhandled exception (malformed JSON, invalid route)
  ↓
Flask returns 500 with Werkzeug interactive debugger page (vuln=1)
  ↓
Obtain or brute-force Werkzeug console PIN
  ↓
Execute arbitrary Python on the API server
```

### Chain 4: BLE Provisioning Replay → Rogue Device Registration
```
Attacker captures (or knows) the factory signature "9C0C306DEF2A".
  ↓
Crafts a POST /admin/device/register with an attacker-chosen MAC + arbitrary
admin/patient credentials, signing it with the static factory signature.
  ↓
Cloud API accepts the request (no per-device MAC binding):
   • creates attacker-controlled admin/patient users in the DB,
   • overwrites Config.DEVICE_IP with the attacker's URL,
   • registers the attacker's MAC as a legitimate CareOtter device.
  ↓
Attacker logs into /api/auth/login and into AdminActivity with the fresh creds.
```

(The legacy "BLE passive scan of ManufacturerData[0x08D4]" chain is obsolete —
the Pi no longer emits the API WiFi IP over BLE. See section 4 above.)

### IGP Authentication Pattern (auth → cmd → deauth)

`services/device_service.py::_exec_protected()` wraps every admin IGP command
in the following sequence, guarded by a class-level `threading.Lock` so two
HTTP requests cannot interleave on the shared TCP session:

```
acquire _igp_lock
  → IGP 0x02 AUTHENTICATE   ("OtterMobile2026")
  → <command>               (0x03/0x04/0x06/0x08/0x09/0x0A/0x0B/0x0C…)
  → IGP 0x0D DEAUTHENTICATE (best-effort, in finally)
release _igp_lock
```

This **shortens** the IGP global-auth race window (CWE-362, IoT:I7.2) but does
not close it: a network attacker with TCP reachability to `:9999` can still
race their own connection between the AUTH and DEAUTH frames sent by the API.
See [`docs/CareOtter/IoT/CareOtter_IoT.md`](../../docs/CareOtter/IoT/CareOtter_IoT.md) §I7.2.

## API Vulnerabilities (OWASP API Top 10 2023)

| ID | Vulnerability | Endpoint | Evidence |
|----|---------------|----------|----------|
| API1:2023 | Broken Object Level Authorization (BOLA) | `/api/caregiver/patient/<username>/vitals` | No ownership check against `caregiver_assignments`; any authenticated JWT can access any patient's vitals |
| API2:2023 | Broken Authentication | `/api/auth/login` | Weak JWT secret, unsalted SHA-256 passwords |
| API3:2023 | Broken Object Property Level Authorization | `/api/network` | `raw` field exposes WiFi config with PSK |
| API5:2023 | Broken Function Level Authorization | `/api/services/restart` | JWT only, no role/ownership checks |
| API6:2023 | Unrestricted Access to Business Flows | `/api/config/preferences` | No rate limiting on TLV config writes |
| API7:2023 | Server Side Request Forgery | *(legacy — `/api/vitals` no longer proxies)* |
| API8:2023 | Security Misconfiguration | Global | Debug mode, verbose error messages |
| API9:2023 | Improper Inventory Management | `/api/health` | Exposes internal device address and WiFi IP |

## IoT Vulnerabilities (OWASP IoT Top 10 2018)

| ID | Vulnerability | Evidence |
|----|---------------|----------|
| IoT:I1 | Weak Passwords | Hardcoded JWT secret, weak default user credentials |
| IoT:I2 | Insecure Services | Werkzeug debug console, unauthenticated vitals endpoints |
| IoT:I5 | Insecure Components | PyJWT with weak secret, SHA-256 without salt |
| IoT:I6 | Insufficient Privacy | Device MAC + patient association in plaintext via API |
| IoT:I7 | No Secure Communication | JWT and IGP over unencrypted HTTP/TCP |

## Dependencies

| Component | Requirement |
|-----------|-------------|
| Platform | Docker + Docker Compose (Linux host) |
| Python | 3.11+ with flask, pyjwt, requests |
| Network | `network_mode: host` — container uses host interfaces |
| Ethernet | 192.168.2.0/24 direct cable to device (Pi at .1, laptop at .2) |
| Target Device | CareOtter at 192.168.2.1:9999 (IGP) and :8081 (HTTP sensor) |

## Verification Checklist

- [ ] `docker compose up -d --build` completes without errors
- [ ] `GET /api/health` returns `wifi_ip` matching laptop's `wlan0`
- [ ] `GET /api/device/info` returns system info without auth
- [ ] **Seed the DB first** — either `POST /initialize_iot` (fallback) or run
      BLE provisioning so `/admin/device/register` creates the default users.
      Otherwise `/api/auth/login` will return 401 in a fresh container.
- [ ] `POST /api/auth/login` with `admin`/`CareOtter2026!` returns JWT with `role=admin`
- [ ] `POST /api/auth/login/patient` with `patient`/`patient123` returns JWT with `role=patient`
- [ ] JWT can be cracked/forged with secret `careotter_jwt_2026`
- [ ] `GET /api/network` with JWT returns `raw` field containing WiFi PSK
- [ ] `GET /api/device/status?module=%25x.%25x` returns hex stack values
- [ ] `GET /api/vitals` returns BPM/SpO2 and stores reading in DB
- [ ] `GET /api/vitals/db/history` returns readings with `device_mac` and `patient_username`
- [ ] `GET /api/devices` (JWT) lists `AA:BB:CC:DD:EE:FF` → `patient` (after seed)
- [ ] `/history` page renders table with Patient and Device MAC columns
- [ ] `/patient/login` redirects to `/` after successful login with cookie
- [ ] Werkzeug debugger accessible at any error URL when `VULNERABLE=1`
- [ ] DB migration runs on existing database (adds `device_mac` column if missing)
- [ ] `device_events` and `device_config` tables exist after first boot
- [ ] Pi `cloud_uploader.py` pushes vitals every ~10 s via cron
- [ ] `POST /api/device/vitals` with valid `X-Device-MAC` + `X-Device-Hash` stores data
- [ ] Patient can register device via `/api/devices/register-by-hash` using factory hash

## References

- Parent Stage: `cloud_api/CONTEXT.md`
- Device Lab: `labs/careotter/CONTEXT.md`
- Mobile App: `vulnzoo_apps/CONTEXT.md`
- BLE Server: `labs/careotter/files/opt/medical-sensor/ble_server.py`
- OWASP API Top 10 2023: https://owasp.org/API-Security/
- OWASP IoT Top 10 2018: https://owasp.org/www-project-internet-of-things/
