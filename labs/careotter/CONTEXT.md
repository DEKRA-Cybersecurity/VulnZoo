# CareOtter - Medical Device Lab (Layer 2)

**Stage Purpose**: Deploy a functional medical pulse oximeter device simulator with BLE GATT services, HTTP REST API, and an admin backdoor service for comprehensive medical IoT security training.

## Scenario

A medical-grade pulse oximeter (CareOtter) has been deployed for patient monitoring. The device uses BLE for mobile app connectivity with HTTP fallback, and includes a vulnerable admin service for device management. The system contains multiple intentional vulnerabilities representing real-world medical device security flaws.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    RASPBERRY PI 3B+ (OpenWrt)                           │
│                                                                         │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐  │
│  │  Medical Sensor  │    │  Admin Service   │    │  BLE GATT        │  │
│  │  HTTP :8081      │    │  TCP :9999       │    │  Server          │  │
│  │                  │    │  (CareService)   │    │  (D-Bus)         │  │
│  │  • BPM/SpO2      │    │                  │    │                  │  │
│  │  • 1Hz sampling  │    │  • Format String │    │  • Heart Rate    │  │
│  │  • HTTP API      │    │  • Integer Under │    │  • Pulse Ox      │  │
│  └────────┬─────────┘    └────────┬─────────┘    └────────┬─────────┘  │
│           │                       │                       │            │
│           │                       │                       │            │
│           └───────────────────────┼───────────────────────┘            │
│                                   │                                     │
│                                   ▼                                     │
│                          ┌────────────────┐                             │
│                          │  Mobile App    │                             │
│                          │  (Android)     │                             │
│                          │                │                             │
│                          │  • BLE Vitals  │                             │
│                          │  • TCP Admin   │                             │
│                          └────────────────┘                             │
└─────────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Medical Sensor Service (Port 8081)
**Purpose**: Simulates MAX30102 pulse oximeter readings

**Location**: `/opt/medical-sensor/sensor_service.py`

**Features**:
- HTTP REST API on port 8081
- 1 Hz data generation (BPM 60-100, SpO2 98%)
- Endpoints: `/vitals`, `/health`, `/config`, `/log`
- Simulated or real hardware (I2C) support

### 2. BLE GATT Server (D-Bus)
**Purpose**: Expose vitals via Bluetooth Low Energy

**Location**: `/opt/medical-sensor/ble_server.py`

**Services**:
- Heart Rate (0x180D) - BPM notifications
- Pulse Oximeter (0x1822) - SpO2 notifications  
- Battery (0x180F) - Battery level

**Protocol**: IGP (IoT Gateway Protocol) v4

### 3. Admin Service - CareService (Port 9999)
**Purpose**: Device administration with intentional vulnerabilities

**Location**: 
- Binary: `/opt/careotter/careservice`
- Source: `/opt/careotter/careservice.c`
- Init: `/etc/init.d/careservice`

**Vulnerabilities**:
| Vuln # | Type | Command | Description |
|--------|------|---------|-------------|
| #1 | Format String | 0x05 | `snprintf(buf, size, user_input)` allows stack leak |
| #2 | Integer Underflow | 0x04 | TLV parser underflow in `remaining -= t_len` |
| #3 | Hardcoded Token | 0x02 | Token "OtterMobile2026" in plaintext |
| #4 | Info Disclosure | 0x03 | Reads `/etc/config/wireless` without auth check |

**Protocol**: IGP v4 - Binary protocol
```
Header: [Magic(4) | Cmd(1) | Status(1) | Len(2)]
Magic: 0x43415245 ("CARE")
Payload: variable
```

## BLE Auto-recovery (3-layer self-healing)

The Cypress BCM43430 firmware shipped with the Raspberry Pi 3B+ periodically stops
emitting LE advertising packets without notifying BlueZ. To keep the lab usable in an
unattended training scenario (no operator restarting `ble_server.py` between sessions),
three independent recovery layers cooperate so that any single failure mode converges
back to a discoverable device within ~1 minute.

| Layer | What | Where | Cadence | Recovers from |
|---|---|---|---|---|
| **L1** | `_advertising_watchdog()` asyncio task that re-registers the LE advertisement and stamps a heartbeat file | `ble_server.py` (`/opt/medical-sensor/`) | every 60 s + on process start | BlueZ silently stopped advertising |
| **L2** | `procd_set_param respawn` (preexistente) | `/etc/init.d/ble-server` | on process death | `ble_server.py` crash / OOM kill |
| **L3** | `careotter-ble-keepalive.sh` cron job that hard-resets the HCI stack when L1 heartbeat is stale | `/usr/local/sbin/careotter-ble-keepalive.sh` + cron entry in `/etc/crontabs/root` | every 60 s | Cypress controller wedged · `bluetoothd` hung · stack deadlocked at HCI level |

### L1 — internal asyncio watchdog

`ble_server.py` spawns `_advertising_watchdog()` from `main()`. The task:

1. Writes `/tmp/ble_advertising_heartbeat` **immediately at startup** (avoids race with L3 during the first 60 s warm-up).
2. Every `BLE_WATCHDOG_INTERVAL` seconds (default 60, override via env var) calls `_ensure_advertisement_registered()` (idempotent unregister + register) and refreshes the heartbeat.

Inspect:
```bash
cat /tmp/ble_advertising_heartbeat                  # epoch seconds; refreshed every 60 s
logread | grep "advertising watchdog armed"         # confirm task spawned this lifetime
logread | grep "Advertising registrado/renovado"    # see successful re-registers
```

### L2 — procd respawn (preexisting)

`/etc/init.d/ble-server` already declares `procd_set_param respawn`. No changes
required for this layer; procd restarts `ble_server.py` ~5 s after any process death.

### L3 — external keepalive (cron + hard HCI reset)

`/usr/local/sbin/careotter-ble-keepalive.sh` runs every minute via cron. It:

1. Checks the `ble_server.py` process is alive (start it if not).
2. Computes process uptime from `/proc/<pid>/stat` and `/proc/uptime` (busybox-safe, no `stat` binary needed).
3. Reads `/tmp/ble_advertising_heartbeat` and compares against `STALE_MAX` (default 180 s).
4. If the heartbeat is stale **and** the process has been alive longer than `STALE_MAX`, performs a hard reset:
   ```
   /etc/init.d/ble-server stop
   hciconfig hci0 down → up
   /etc/init.d/bluetoothd restart
   /etc/init.d/ble-server start
   ```

Inspect:
```bash
logread | grep careotter-ble-keepalive | tail
grep keepalive /etc/crontabs/root                   # cron entry should be active
```

### Failure modes covered

| Failure mode | Cured by | Recovery time |
|---|---|---|
| `ble_server.py` crashes / OOM | L2 procd respawn | ~5 s |
| BlueZ stops advertising silently | L1 watchdog | ≤60 s |
| Cypress HCI controller wedged | L3 `hciconfig down/up` | ≤60 s + ~5 s reset |
| `bluetoothd` hung | L3 `bluetoothd restart` | ≤60 s + ~5 s reset |
| All of the above simultaneously | L3 full chain (stop → HCI reset → daemon restart → start) | ≤60 s + ~5 s reset |

### Regression test

```bash
# Force the L1 watchdog to be unable to refresh the heartbeat by SIGSTOPing
# the python process. After STALE_MAX seconds, L3 should hard-reset.
ssh root@192.168.2.1 '
  rm -f /tmp/ble_advertising_heartbeat
  kill -STOP $(pgrep -f ble_server.py)
'

# Wait at least STALE_MAX + 1 cron tick (default ~3 min total)
sleep 200

# Verify the keepalive triggered and the stack recovered
ssh root@192.168.2.1 '
  logread | grep "hard reset complete" | tail -1
  cat /tmp/ble_advertising_heartbeat
  pgrep -af ble_server.py
'
# Pi must be visible again from the Kali host
bluetoothctl --timeout 8 scan le | grep CareOtter_HR
```

---

## Inputs

| Layer | Source Path | Role/Description |
|-------|-------------|------------------|
| **Layer 3** | `../../docs/CareOtter/` | Architecture and vulnerability docs |
| **Layer 4** | `files/opt/medical-sensor/` | Sensor + BLE services |
| **Layer 4** | `files/opt/careotter/` | Admin service (careservice) |
| **Layer 4** | `files/etc/init.d/` | OpenWRT init scripts |
| **Layer 4** | `files/etc/crontabs/root` | Cron entries (includes L3 BLE keepalive) |
| **Layer 4** | `files/usr/local/sbin/careotter-ble-keepalive.sh` | L3 external watchdog |
| **Layer 4** | `files/usr/lib/vulnzoo-hooks/` | Initialization hooks |
| **Layer 4** | `CareOtterClient.java` | Android client reference |

## Process

### 1. Deploy Services

**Service Startup Order**:
```bash
# 1. Medical Sensor (port 8081)
/etc/init.d/medical-sensor start

# 2. BLE GATT Server (D-Bus)
/etc/init.d/ble-server start  # or via hook

# 3. Admin Service (port 9999)
/etc/init.d/careservice start
```

### 2. Service Configuration

**Medical Sensor** (`/opt/medical-sensor/config.json`):
```json
{
  "use_real_hardware": false,
  "bpm": 72,
  "spo2": 98,
  "http_port": 8081,
  "sample_rate": 1
}
```

**CareService**: Compiled C binary with hardcoded port 9999

### 3. Verification

**HTTP API Test**:
```bash
curl http://192.168.2.1:8081/vitals
# {"bpm": 72, "spo2": 98, ...}
```

**CareService Test**:
```bash
# SYS_INFO (0x01)
printf '\x47\x4F\x41\x54\x01\x00\x00\x00' | nc 127.0.0.1 9999
# v:6.6.104|m:armv7l

# AUTH (0x02) with token
printf '\x47\x4F\x41\x54\x02\x00\x00\x0FOtterMobile2026' | nc 127.0.0.1 9999
# AUTH_SUCCESS
```

## Outputs

| Artifact | Path/Port | Description |
|----------|-----------|-------------|
| HTTP API | `:8081` | Medical sensor REST API |
| Vitals Endpoint | `:8081/vitals` | BPM/SpO2 JSON |
| BLE GATT | hci0 | Heart Rate + Pulse Ox services |
| Admin Service | `:9999` | CareService (vulnerable) |
| Logs | `/tmp/medical-logs/` | Sensor data logs |
| Binary | `/opt/careotter/careservice` | Admin service executable |

## Vulnerability Testing

### Format String (Command 0x05)
```bash
printf '\x47\x4F\x41\x54\x05\x00\x00\x08%x%x%x%x' | nc 192.168.2.1 9999
# Leaks stack addresses
```

### Integer Underflow (Command 0x04)
```bash
# Requires authentication first
printf '\x47\x4F\x41\x54\x02\x00\x00\x0FOtterMobile2026' | nc 192.168.2.1 9999
printf '\x47\x4F\x41\x54\x04\x00\x00\x06\xAA\xFFAAAA' | nc 192.168.2.1 9999
```

## Mobile App Integration

See: `vulnzoo_apps/careotter_app/CONTEXT.md`

The Android app connects to both services:
- **BLE**: For real-time vitals (medical data)
- **TCP 9999**: For admin functions (vulnerable service)

## Dependencies

| Component | Requirement |
|-----------|-------------|
| Hardware | Raspberry Pi 3B+ with Bluetooth |
| OS | OpenWRT v24.10.2 |
| Python | 3.11+ with standard library |
| Bluetooth | BlueZ with D-Bus support |
| Network | 192.168.2.0/24 |

## Verification Checklist

- [ ] HTTP API responds on port 8081
- [ ] `/vitals` returns BPM/SpO2 data
- [ ] BLE advertising as "CareOtter_HR"
- [ ] CareService running on port 9999
- [ ] SYS_INFO (0x01) returns kernel version
- [ ] AUTH (0x02) accepts "OtterMobile2026"
- [ ] Format string exploit leaks stack data
- [ ] WiFi config readable after auth
- [ ] `/tmp/ble_advertising_heartbeat` exists and is younger than 60 s (L1)
- [ ] `crontab -l` lists `careotter-ble-keepalive.sh` running every minute (L3)
- [ ] Regression test (`SIGSTOP` watchdog + wait 200 s) recovers automatically

## References

- Client: `CareOtterClient.java` (Protocol IGP v4)
- Service: `careservice.c` (Vulnerable admin service)
- Docs: `docs/CareOtter/Vulnerabilities.md`
