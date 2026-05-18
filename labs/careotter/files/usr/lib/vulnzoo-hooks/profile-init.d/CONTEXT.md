# CareOtter Medical Sensor Lab - Hook System Documentation

## Overview

**CareOtter** is a medical IoT laboratory for VulnZoo that simulates a cardiac/pulse oximeter sensor (MAX30102) in OpenWRT running on Raspberry Pi 3B.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Raspberry Pi 3B (OpenWRT)                │
│                                                             │
│  ┌─────────────────┐    ┌──────────────────┐               │
│  │ sensor_service  │───→│   ble_server     │               │
│  │   HTTP :8081    │    │   BLE GATT       │               │
│  │                 │    │   "CareOtter_HR" │               │
│  └─────────────────┘    └──────────────────┘               │
│           ↑                      ↓                          │
│   /tmp/medical-logs/     ┌──────────────┐                   │
│   vitals.log             │  Mobile App  │                   │
│                          │    (BLE)     │                   │
│                          └──────────────┘                   │
│                                                             │
│  Additional Services:                                       │
│  ┌─────────────────┐    ┌──────────────────┐               │
│  │ careservice     │    │   WiFi Client    │               │
│  │   IGP :9999     │    │   (Station Mode) │               │
│  │   Admin/Exploit │    │                  │               │
│  └─────────────────┘    └──────────────────┘               │
└─────────────────────────────────────────────────────────────┘
```

## Hook Execution Order

Hooks are executed alphabetically by the VulnZoo hook-manager when loading the `careotter` profile.

| Order | Hook | Purpose | Port/Interface | Status |
|-------|------|---------|----------------|--------|
| 1 | `5-preflight.sh` | System pre-flight checks | System | ✅ Active |
| 2 | `15-python-deps.sh` | Verify Python packages | System | ✅ Active |
| 3 | `40-i2c.sh` | Enable I2C for hardware sensor | /dev/i2c-1 | ✅ Active |
| 4 | `50-medical-sensor.sh` | Start HTTP sensor service | HTTP :8081 | ✅ Active |
| 5 | `55-ble-server.sh` | Start BLE GATT server | BLE "CareOtter_HR" | ⚠️ Needs Bluetooth |
| 6 | `60-cron.sh` | Configure log rotation | Cron | ✅ Active |
| 7 | `70-careotter-admin.sh` | Start admin/exploit service | IGP :9999 | ✅ Active |
| 8 | `80-wifi.sh` | Configure WiFi client mode | WiFi STA | ✅ Active |

## Detailed Hook Descriptions

### 5-preflight.sh
**Purpose:** System verification before loading the lab

**Checks:**
- Directory structure (`/root/careotter/*` for legacy, `/opt/medical-sensor/` for current)
- Python3 availability
- Bluetooth utilities presence
- I2C device availability
- Disk space (>100MB)

**Output:** Logs to `/root/vulnzoo.log`

**Exit Codes:**
- `0` - All checks passed
- `1` - Critical errors found (prevents lab loading)

---

### 15-python-deps.sh
**Purpose:** Verify Python dependencies

**Required Packages:**
- `bleak` - For BLE functionality
- `pyyaml` - For YAML config parsing
- `aiohttp` - For async HTTP (legacy)
- `smbus2` - For I2C hardware communication

**Missing packages:** Logs warning, does not fail

**Output:** Logs package status to `/root/vulnzoo.log`

---

### 40-i2c.sh
**Purpose:** Enable I2C bus for physical MAX30102 sensor

**Actions:**
1. Check if current device is `careotter` (skips otherwise)
2. Check if `/dev/i2c-1` already exists
3. Load `i2c-dev` kernel module if available
4. Run `/etc/init.d/i2c` to configure `config.txt` if needed

**Fallback:** If no I2C, sensor uses software simulation via `simulator.py`

**Logging:** Uses `logger -t careotter-i2c` and `/root/vulnzoo.log`

---

### 50-medical-sensor.sh
**Purpose:** Start the main medical sensor HTTP service

**Service Details:**
- **Binary:** `/opt/medical-sensor/sensor_service.py`
- **Port:** 8081 (HTTP)
- **Log:** `/tmp/medical-logs/vitals.log`
- **Init Script:** `/etc/init.d/medical-sensor`

**Actions:**
1. Verify device is `careotter`
2. Check that `sensor_service.py` and `simulator.py` exist
3. Create log directory `/tmp/medical-logs` (tmpfs for flash protection)
4. Stop any existing instance
5. Enable and start service via init.d
6. Verify process started and HTTP endpoint responds

**Endpoints:**
- `GET /vitals` - Current BPM, SpO2, raw values
- `GET /health` - Service health check
- `GET /config` - Active configuration
- `GET /log` - Full log buffer (1440 entries max)
- `GET /log/last` - Most recent entry
- `GET /reload` - Reopen log file (for logrotate)

**Summary Generation:**
- Every 60 seconds (configurable via `summary_every_s`)
- Calculates: min, max, avg for BPM and SpO2
- Writes to log buffer and file

---

### 55-ble-server.sh
**Purpose:** Start BLE GATT server for mobile app connectivity

**Service Details:**
- **Binary:** `/opt/medical-sensor/ble_server.py`
- **PID File:** `/var/run/careotter-ble.pid`
- **Log:** `/tmp/ble_server.log`
- **D-Bus:** Uses `DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket`

**BLE Characteristics:**
- **Device Name:** `CareOtter_HR`
- **Service UUID:** `0000180d-0000-1000-8000-00805f9b34fb` (Heart Rate)
- **HR Measurement:** `00002a37-0000-1000-8000-00805f9b34fb` (Notify/Read)
- **SpO2:** `c0a10001-0000-1000-8000-00805f9b34fb` (Custom, Notify/Read)
- **Battery:** `00002a19-0000-1000-8000-00805f9b34fb` (Read)

**Actions:**
1. Verify device is `careotter`
2. Check Bluetooth adapter (`hci0`) availability
3. Check `ble_server.py` exists
4. Stop any existing instance
5. Configure D-Bus environment
6. Set BLE emission interval (default: 1s)
7. Start BLE server with unbuffered output
8. Save PID and verify startup

**Configuration:**
- `BLE_INTERVAL` environment variable (default: 1 second)

**Known Issue:** Requires Bluetooth firmware BCM43430A1.hcd for RPi3 (not in standard OpenWRT).

**Workaround:** Use HTTP API on port 8081 instead.

---

### 60-cron.sh
**Purpose:** Configure log rotation for medical logs

**Actions:**
1. Verify device is `careotter`
2. Enable and start `cron` service
3. Add logrotate entry to `/etc/crontabs/root` if not present (idempotent)
4. Reload cron to apply changes

**Cron Entry:**
```
0 * * * * /usr/sbin/logrotate /etc/logrotate.d/medical-sensor
```

**Rotation Policy:**
- Rotate daily or when size > 1MB
- Keep 5 rotated files
- Compress old logs
- Post-rotate: Send SIGUSR1 to Python processes

**Logrotate Config:** `/etc/logrotate.d/medical-sensor`

---

### 70-careotter-admin.sh
**Purpose:** Start the device administration service (careservice) with intentional vulnerabilities

**Service Details:**
- **Binary:** `/opt/careotter/careservice`
- **Port:** 9999 (TCP)
- **Protocol:** Binary IGP (IoT Gateway Protocol) v4
- **PID File:** `/var/run/careservice.pid`
- **Log:** `/tmp/careservice.log`

**Intentional Vulnerabilities:**
1. **Format String** - Status command uses unsanitized input in snprintf()
2. **Integer Underflow** - TLV parser vulnerable to underflow
3. **Hardcoded Token** - Admin token "OtterMobile2026"
4. **Information Disclosure** - WiFi config exposed via network command

**Actions:**
1. Verify device is `careotter`
2. **Idempotency Check** - Skip if already running
3. Check for existing careservice processes and kill if found
4. Verify binary exists at `/opt/careotter/careservice`
5. Make binary executable if needed
6. Check port 9999 is available
7. Start careservice in background
8. Save PID and verify startup

**IGP Protocol Commands:**
- `0x01` - SYS_INFO (public)
- `0x02` - AUTHENTICATE (token: "OtterMobile2026")
- `0x03` - GET_NETWORK (requires auth, discloses WiFi PSK)
- `0x04` - SET_PREFS (TLV parser, vulnerable to underflow)
- `0x05` - VERIFY_STATUS (format string vulnerable)

**Protocol Header:**
```
┌─────────────────┬──────┬────────┬──────────┐
│  Magic (4)      │ Cmd  │ Status │  Len (2) │
│  0x43415245     │ (1)  │  0x00  │ payload  │
│    "CARE"       │      │        │          │
└─────────────────┴──────┴────────┴──────────┘
```

---

### 80-wifi.sh
**Purpose:** Configure WiFi client (station) mode for the careotter lab

**Description:**
The base image ships with WiFi disabled. This hook enables it and connects the device to an existing WPA2 network to simulate a realistic home-network environment.

**Actions:**
1. Enable radio in 2.4GHz mode (brcmfmac sched-scan fails on 5GHz)
2. Configure WiFi interface as client (station mode)
3. Set network interface for DHCP
4. Add wwan to WAN firewall zone
5. Commit UCI changes and restart WiFi

**Configuration:**
- **Band:** 2.4GHz (`2g`)
- **Channel:** Auto
- **HT Mode:** HT20
- **Country:** ES
- **Mode:** STA (Station/Client)
- **SSID:** `TuRedWiFi` (placeholder - should be changed)
- **Encryption:** WPA2-PSK
- **Key:** `TuPasswordSegura` (placeholder - should be changed)
- **Network:** DHCP on `wwan` interface

**Security Note:**
The default SSID and password are placeholders. For production deployment, change these values or use a configuration management system to inject credentials securely.

---

## File Locations

### Modern Sensor (Current)
```
/opt/medical-sensor/
├── sensor_service.py      # Main HTTP service (port 8081)
├── ble_server.py          # BLE GATT server
├── simulator.py           # MAX30102 simulator
├── config.json            # Configuration
└── requirements.txt       # Python dependencies

/opt/careotter/
├── careservice            # Admin service binary (port 9999)
├── careservice.c          # Source code
└── README.txt             # Documentation

/tmp/medical-logs/
└── vitals.log             # Sensor data log (tmpfs)

/tmp/
├── careservice.log        # Admin service log
└── ble_server.log         # BLE server log
```

### System Configuration
```
/etc/init.d/medical-sensor      # Init script for HTTP service
/etc/init.d/careservice         # Init script for admin service
/etc/config/vulnzoo             # UCI config with current_device
/root/vulnzoo.log               # Hook execution logs
/usr/lib/vulnzoo-hooks/execution.log  # Hook manager logs
/etc/logrotate.d/medical-sensor # Log rotation config
```

## Configuration Files

### /opt/medical-sensor/config.json
```json
{
    "use_real_hardware": false,
    "bpm": 72,
    "spo2": 98,
    "http_port": 8081,
    "sample_rate": 10,
    "log_file": "/tmp/medical-logs/vitals.log",
    "summary_every_s": 60,
    "log_buffer_max": 1440
}
```

### /etc/logrotate.d/medical-sensor
```
/tmp/medical-logs/vitals.log {
    daily
    size 1M
    rotate 5
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        killall -SIGUSR1 python3 2>/dev/null || true
    endscript
}
```

## Troubleshooting

### Bluetooth Not Working (No hci0)

**Symptoms:**
```
hciconfig                          # Empty output
bluetoothctl show                  # "No default controller available"
```

**Cause:** Missing firmware BCM43430A1.hcd for Raspberry Pi 3 BCM43438 chip

**Solution:**
1. Use HTTP API instead (recommended for lab)
2. Or manually download firmware:
   ```bash
   mkdir -p /lib/firmware/brcm
   wget -O /lib/firmware/brcm/BCM43430A1.hcd \
       https://github.com/RPi-Distro/bluez-firmware/raw/master/broadcom/BCM43430A1.hcd
   /etc/init.d/bluetoothd restart
   ```

### Sensor HTTP Not Responding

**Check:**
```bash
ps | grep sensor_service          # Process running?
netstat -tulnp | grep 8081        # Port listening?
curl http://127.0.0.1:8081/health # Health check
cat /root/vulnzoo.log | tail      # Hook execution logs
```

**Restart:**
```bash
/etc/init.d/medical-sensor restart
```

### Admin Service (IGP) Not Responding

**Check:**
```bash
ps | grep careservice             # Process running?
netstat -tulnp | grep 9999        # Port listening?
cat /tmp/careservice.log          # Service logs
cat /root/vulnzoo.log | grep careotter-admin  # Hook logs
```

**Restart:**
```bash
/etc/init.d/careservice restart
# Or manually:
/opt/careotter/careservice &
```

### Hook Failures

**Check execution status:**
```bash
/usr/lib/vulnzoo-hooks/hook-manager.sh status careotter
cat /usr/lib/vulnzoo-hooks/execution.log
```

**Force re-execution:**
```bash
/usr/lib/vulnzoo-hooks/hook-manager.sh init careotter force
```

## Usage Examples

### Read Current Vitals via HTTP
```bash
curl http://192.168.2.100:8081/vitals
# {"bpm": 72, "spo2": 98, "timestamp": 1234567890, ...}
```

### Query IGP Admin Service
```bash
# System info (no auth required)
echo -ne '\x47\x4F\x41\x54\x01\x00\x00\x00' | nc 192.168.2.100 9999

# Authenticate
echo -ne '\x47\x4F\x41\x54\x02\x00\x00\x0E\x4F\x74\x74\x65\x72\x4D\x6F\x62\x69\x6C\x65\x32\x30\x32\x36' | nc 192.168.2.100 9999
```

### Read Log Buffer
```bash
curl http://192.168.2.100:8081/log
# [{"bpm_avg": 72.5, "spo2_avg": 98.2, ...}, ...]
```

### Trigger Log Rotation
```bash
curl http://192.168.2.100:8081/reload
/usr/sbin/logrotate -f /etc/logrotate.d/medical-sensor
```

## Development Notes

### Hook Idempotency
All hooks check `VULNZOO_DEVICE` environment variable or UCI config before executing:
```bash
VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"
if [ "$VULNZOO_DEVICE" != "careotter" ]; then
    exit 0
fi
```

### Logging Convention
All hooks log to `/root/vulnzoo.log` with format:
```
YYYY-MM-DD HH:MM:SS [PID] [careotter] Message
```

### Dependencies Between Hooks
- `40-i2c.sh` → `50-medical-sensor.sh` (I2C for hardware sensor)
- `50-medical-sensor.sh` → `55-ble-server.sh` (BLE reads from HTTP)
- `50-medical-sensor.sh` → `60-cron.sh` (Cron rotates sensor logs)
- `5-preflight.sh` → All (pre-flight checks run first)

## Security Considerations

### Default Security (careotter profile)
- BLE pairing: secure_passkey (PIN required)
- Encryption: enabled
- HTTP: no auth on local network
- IGP Admin: hardcoded token (intentional vulnerability)

### IGP Service Vulnerabilities (Intentional)
The `careservice` on port 9999 contains intentional vulnerabilities for training:
- **Format String:** Pass `%x.%x.%x` to VERIFY_STATUS command
- **Integer Underflow:** Send TLV with length > remaining buffer
- **Info Disclosure:** GET_NETWORK reveals WiFi PSK after authentication
- **Hardcoded Token:** "OtterMobile2026" (XOR 0x5A in mobile app)

### Network Exposure
- HTTP port 8081: Exposed to LAN
- IGP port 9999: Exposed to LAN
- No authentication by default on HTTP
- Suitable for lab/training environment only

## References

- MAX30102 Datasheet: https://datasheets.maximintegrated.com/en/ds/MAX30102.pdf
- OpenWRT Bluetooth: https://openwrt.org/docs/guide-user/hardware/bluetooth/bluetooth.audio
- BLE GATT Services: https://www.bluetooth.com/specifications/gatt/
- VulnZoo Hook System: See `/usr/lib/vulnzoo-hooks/hook-manager.sh`
- IGP Protocol: Magic `0x43415245` ("CARE"), Big Endian

---

**Last Updated:** 2025-04-14  
**Maintainer:** VulnZoo Project  
**Version:** 3.0 (Updated with admin service and WiFi hooks)
