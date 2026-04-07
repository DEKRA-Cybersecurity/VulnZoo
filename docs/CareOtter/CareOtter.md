# Architecture

```plain
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

```zsh
$ curl http://192.168.2.1:8081/config
{"use_real_hardware": false, "bpm": 72, "spo2": 98, "http_port": 8081, "log_file": "/tmp/medical-logs/vitals.log", "sample_rate": 10, "summary_every_s": 60, "log_buffer_max": 1440}       
$ curl http://192.168.2.1:8081/vitals
{"bpm": 78, "spo2": 84, "red_raw": 61085, "ir_raw": 61036, "timestamp": 1773738799.8925164, "source": "simulator"}  

$ curl http://192.168.2.1:8081/log/last
{"bpm_avg": 78.0, "bpm_min": 72, "bpm_max": 84, "spo2_avg": 84.0, "spo2_min": 84, "spo2_max": 84, "samples": 600, "timestamp": 1773738765.0571454, "source": "simulator"}   

$ curl http://192.168.2.1:8081/health  
ok

$ curl http://192.168.2.1:8081/log     
[{"bpm_avg": 78.6, "bpm_min": 60, "bpm_max": 150, "spo2_avg": 84.0, "spo2_min": 84, "spo2_max": 84, "samples": 600, "timestamp": 1773737968.7881646, "source": "simulator"}, {"bpm_avg": 78.0, "bpm_min": 72, "bpm_max": 84, "spo2_avg": 84.0, "spo2_min": 84, "spo2_max": 84, "samples": 600, "timestamp": 1773738035.142162, "source": "simulator"}, {"bpm_avg": 78.0, "bpm_min": 72, "bpm_max": 84, "spo2_avg": 84.0, "spo2_min": 84, "spo2_max": 84, "samples": 600, "timestamp": 1773738101.4962459, "source": "simulator"}, {"bpm_avg": 78.0, "bpm_min": 72, "bpm_max": 84, "spo2_avg": 84.0, "spo2_min": 84, "spo2_max": 84, "samples": 600, "timestamp": 1773738167.8478281, "source": "simulator"}, {"bpm_avg": 78.0, "bpm_min": 72, "bpm_max": 84, "spo2_avg": 84.0, "spo2_min": 84, "spo2_max": 84, "samples": 600, "timestamp": 1773738234.2053628, "source": "simulator"}, {"bpm_avg": 78.0, "bpm_min": 72, "bpm_max": 84, "spo2_avg": 84.0, "spo2_min": 84, "spo2_max": 84, "samples": 600, "timestamp": 1773738300.5681176, "source": "simulator"}, {"bpm_avg": 78.0, "bpm_min": 72, "bpm_max": 84, "spo2_avg": 84.0, "spo2_min": 84, "spo2_max": 84, "samples": 600, "timestamp": 1773738366.9227927, "source": "simulator"}, {"bpm_avg": 78.0, "bpm_min": 72, "bpm_max": 84, "spo2_avg": 84.0, "spo2_min": 84, "spo2_max": 84, "samples": 600, "timestamp": 1773738433.2807875, "source": "simulator"}, {"bpm_avg": 78.0, "bpm_min": 72, "bpm_max": 84, "spo2_avg": 84.0, "spo2_min": 84, "spo2_max": 84, "samples": 600, "timestamp": 1773738499.635625, "source": "simulator"}, {"bpm_avg": 78.0, "bpm_min": 72, "bpm_max": 84, "spo2_avg": 84.0, "spo2_min": 84, "spo2_max": 84, "samples": 600, "timestamp": 1773738565.9906137, "source": "simulator"}, {"bpm_avg": 78.0, "bpm_min": 72, "bpm_max": 84, "spo2_avg": 84.0, "spo2_min": 84, "spo2_max": 84, "samples": 600, "timestamp": 1773738632.345027, "source": "simulator"}, {"bpm_avg": 78.0, "bpm_min": 72, "bpm_max": 84, "spo2_avg": 84.0, "spo2_min": 84, "spo2_max": 84, "samples": 600, "timestamp": 1773738698.701854, "source": "simulator"}, {"bpm_avg": 78.0, "bpm_min": 72, "bpm_max": 84, "spo2_avg": 84.0, "spo2_min": 84, "spo2_max": 84, "samples": 600, "timestamp": 1773738765.0571454, "source": "simulator"}, {"bpm_avg": 79.0, "bpm_min": 72, "bpm_max": 90, "spo2_avg": 84.0, "spo2_min": 84, "spo2_max": 84, "samples": 600, "timestamp": 1773738831.413544, "source": "simulator"}]
```


## 1. Communication Stack Pi ↔ Mobile (With Fallbacks)

### Primary Protocol: BLE GATT (Low Energy)

**Implementation:** BlueZ + Python `bleak` (server) / `flutter_blue_plus` (client)

**Exposed BLE Services (Vulnerable by Design):**
Service 0x180D (Heart Rate):
  - Characteristic 0x2A37: BPM Notifications (plaintext data, no encryption)
  - Characteristic 0x2A38: SpO2 (custom UUID, spoofable)
  
Service 0xFF00 (CareOtter Emergency):
  - UUID: "careotter-emergency-uuid-1234"
  - Properties: Write (no pairing authentication required)
  - Vulnerability: Any BLE device can write "trigger-emergency"

**Vulnerability #1 (Communications):**
- Pairing mode: `JustWorks` (without MITM protection)
- Hardcoded LTK (Long Term Key) in `/etc/bluetooth/careotter.conf`
- Sniffing possible with Ubertooth One or even Bettercap on rooted Android
```python
# Vulnerable Flask (app.py)
from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)

@app.route('/vitals/stream')
def stream_vitals():
    # No authentication, exposes everything
    return jsonify(get_last_vitals())

@app.route('/emergency/call', methods=['POST'])
def emergency_call():
    # VULNERABILITY #2: Command Injection
    number = request.json.get('number')
    os.system(f"asterisk -rx 'channel originate Local/{number} application Playback emergency'")
    return {"status": "calling", "number": number}
```

### Fallback 2: MQTT (For Administration Panel)

**Broker:** Mosquitto on port 1883 (without TLS) **Topics:**
- `careotter/patient/+/vitals` (data publication)
- `careotter/admin/config` (subscription for configuration changes)
- `careotter/emergency/activate` (retained message with emergency payload)

**Vulnerability #3:**
- No ACL: any client can publish to `careotter/emergency/activate`
- QoS 0 on critical messages (real-time data loss)
- Retained message poisoning: publish `{"spo2": 0, "bpm": 0}` with `-r` flag

## 2. Medical Actuation Services (CareOtter Actions)

### Multi-Level Emergency System

**A. Threshold Configuration (Vulnerable to IDOR)**
### Fallback 1: HTTP REST (If BLE Fails)
**Endpoint:** `http://192.168.4.1:8080/api/v1/`

```python
@app.route('/config/thresholds/<patient_id>', methods=['PUT'])
def set_thresholds(patient_id):
    # VULNERABILITY #4: IDOR - you can change other patients' thresholds
    # by changing patient_id in URL (1, 2, 3...)
    data = request.json
    query = f"UPDATE patients SET bpm_min={data['bpm_min']}, bpm_max={data['bpm_max']} WHERE id={patient_id}"
    execute_query(query)  # SQLi also possible here
    return {"updated": patient_id}
```

**B. Panic Button (Physical GPIO + Simulated)**
- **Physical:** GPIO 18 (input) on Pi → interrupt that publishes to MQTT/BLE
- **Remote:** HTTP endpoint `POST /panic` or BLE write to characteristic 0xFF01
- **Vulnerability #5:** Race Condition - spamming the panic button blocks the emergency service (DoS on the actuator)

**C. Simulated "Defibrillator" (Critical Actuator)** Controlled by GPIO 23 (Relay/LED simulating charge):
```python
@app.route('/defibrillator/charge', methods=['POST'])
def charge_defib():
    if request.json.get('auth_code') == "1234":  # Hardcoded credential
        gpio_set(23, HIGH)
        log_action("DEFIBRILLATOR ACTIVATED")
        return {"status": "charging", "joules": 200}
    return {"error": "unauthorized"}, 401

@app.route('/defibrillator/discharge', methods=['POST'])
def discharge():
    # VULNERABILITY #6: No verification of previous state
    # Allows discharge without prior charging (broken business logic)
    # or continuous discharge (dangerous latch)
    gpio_pulse(23, duration=10)  # 10 seconds of "shock"
    return {"status": "shock delivered"}
```

**D. Telephony Service (Simulated Asterisk)**

- Script at `/usr/lib/careotter/phone.sh` that simulates emergency calls
- Vulnerability #7: Path traversal in phone number
    - Payload: `number="../../../../etc/passwd"` in emergency POST

## 3. Web API and Storage (Data Exfiltration Targets)

### Data Schema (Intentionally Vulnerable SQLite)
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

### Vulnerable Endpoints (For CTF Flags)

1. **`GET /api/v1/patients/<id>/records`**
    - SQL Injection: `id=1 UNION SELECT * FROM patients--`

2. **`GET /api/v1/export?format=csv&patient_id=1`**
    - Path traversal: `patient_id=../../../../etc/shadow`
    - XXE if XML is used internally for processing

3. **`POST /api/v1/login`**
    - JWT signed with weak key `secret123` (crackable with jwt_tool)
    - SQLi in username: `admin' OR '1'='1`

## 4. Vulnerability Tree by Attack Type

### Physical/IoT Attacks

- **BLE Spoofing:** Clone the medical device by sending fake data (MAC spoofing)
- **Jamming:** 2.4GHz interference to force fallback to HTTP (easier to intercept)
- **Hardware Hacking:** Extract `/etc/careotter/secrets.conf` from Pi's UART port (if exposed)
### Network Attacks

- **BLE MITM:** Capture initial pairing (JustWorks) and decrypt LTK
- **MQTT Subscribe:** Connect to broker without auth and subscribe to `#` (all topics)
- **HTTP Interception:** Burp Proxy between App and Pi to modify BPM thresholds in transit

### Application Attacks (Business Logic)

- **Business Logic:** Send BPM=0 via API so defibrillator activates "automatically" (logic: if bpm < min_threshold → shock)
- **Race Condition:** Two simultaneous requests to `/defibrillator/charge` cause simulated overload (state bug)
- **Replay Attack:** Reuse old JWT tokens (no `iat` or `exp` verification)

### Database Attacks

- **SQLi:** Obtain all SSNs and medical notes
- **RCE via SQLite:** `load_extension()` if enabled (rare but possible in custom builds)
# Targets

1. **Phase 1 (Core):** MAX30102 → Python → Local MQTT → SQLite (basic functionality)
2. **Phase 2 (Comms):** Add BLE GATT server + HTTP fallback (multiprotocol)
3. **Phase 3 (Actuators):** GPIO for panic button + "defibrillator" (LED/Relay)
4. **Phase 4 (Vulnerabilities):**
    - Hardcode credentials in `/etc/careotter/config.ini`
    - Remove input validation in Flask.
    - Disable TLS on Mosquitto.
    - Enable `JustWorks` on BlueZ.