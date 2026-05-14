# CareOtter Monitor — Android Application (Layer 2)

**Stage Purpose**: Unified Android application for patient monitoring and clinical administration of the CareOtter medical device. Combines BLE vitals consumption, Cloud API authentication, and direct IGP v4 admin control in a single APK with role-based routing (patient vs. admin).

## Scenario

The CareOtter Monitor app is the single mobile client used by the lab. It demonstrates:

- **Patient flow**: login against the Cloud API → BLE GATT connection to `CareOtter_HR` → live vitals (HR, SpO₂, battery), threshold panel, history.
- **Admin flow**: same login (`role=admin`) → AdminActivity with direct **TCP** access to `careservice` on `192.168.2.1:9999` using the IGP v4 binary protocol.
- **Intentional vulnerabilities** spanning OWASP Mobile Top 10 (BLE pairing missing, plaintext SD-card logging, hidden diagnostic panel, hardcoded XOR-obfuscated admin token, hardcoded CSCP key) plus client-side exposure of all IGP v4 opcodes.
- **Auth → cmd → deauth pattern** in `AdminActivity` to shorten the IGP global-auth race window (IoT:I7.2 / CWE-362).

## Package

`com.vulnzoo.careotter_app` (note: legacy doc referenced `com.example.careotter_app` — that package name is obsolete).

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                       ANDROID DEVICE                               │
│                                                                    │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │                     CareOtter Monitor APK                  │    │
│  │                                                            │    │
│  │  LoginActivity ── HTTP/JSON ──► Cloud API (Docker :5002)   │    │
│  │       │                         /api/auth/login            │    │
│  │       │                         /api/auth/login/patient    │    │
│  │       │  JWT + role                                        │    │
│  │       ▼                                                    │    │
│  │  routeByRole()                                             │    │
│  │     │   role=patient ─► MainActivity                       │    │
│  │     │                       │                              │    │
│  │     │                       ├─► BleMonitorClient (GATT)    │    │
│  │     │                       └─► VitalsLogger (/sdcard)     │    │
│  │     │                                                      │    │
│  │     │   role=admin   ─► AdminActivity                      │    │
│  │     │                       └─► IgpClient (TCP :9999)      │    │
│  │     │                              auth → cmd → deauth     │    │
│  └─────┼──────────────────────────────────────────────────────┘    │
└────────┼──────────────────────────────────────────────────────────┘
         │
         ├── BLE ─────► Raspberry Pi 192.168.2.1 ble_server.py
         │                 (0x180D/0x1822/0x180F/0x180A/0xFF00,
         │                  hidden 0xFF10 provisioning)
         ├── HTTP ────► Operator PC <wifi-prefix>.x:5002 (Cloud API, Docker)
         └── TCP :9999► Raspberry Pi 192.168.2.1 careservice (IGP v4)
```

## Components (current sources)

All sources live under `app/src/main/java/com/vulnzoo/careotter_app/`.

### 1. `LoginActivity.java`

**Purpose**: Entry point. Manual entry of the Cloud API IP (network prefix + host octet), WiFi-prefix auto-detect, ICMP ping test, and HTTP login against the Cloud API. Routes by `role` claim in the returned JWT.

**Highlights**:

- BLE-based API auto-discovery has been **removed** (was an IoT:I3.1 leak). The user types the API IP manually.
- `detectWifiNetworkPrefix()` reads the phone's `wlan0` IP via `WifiManager` to pre-fill the prefix.
- `pingApi()` uses `InetAddress.isReachable(3000)` for a quick ICMP check.
- Persists `KEY_TOKEN`, `KEY_ROLE`, `KEY_USERNAME`, `KEY_API_URL` in `SharedPreferences`.

### 2. `MainActivity.java`

**Purpose**: Patient view. Connects to the BLE peripheral `CareOtter_HR`, displays live HR / SpO₂ / battery, exposes a hidden diagnostic threshold panel (5 quick taps on the title — see BLE-04 in the Test Suite), and logs vitals to `/sdcard/careotter_vitals.log` via `VitalsLogger`.

### 3. `AdminActivity.java`

**Purpose**: Admin view. Direct **TCP** access to `careservice` on port 9999 using `IgpClient`. Implements the **auth → cmd → deauth** pattern via `execProtected(NetworkTask)`:

```
1. IGP 0x02 AUTHENTICATE   → authenticated=1 on device
2. <admin command>         → e.g. 0x03 GET_NETWORK, 0x06 SET_WIFI, …
3. IGP 0x0D DEAUTHENTICATE → authenticated=0 on device  (always runs in finally)
```

This shortens but does not close the IoT:I7.2 race window — see [`docs/CareOtter/IoT/CareOtter_IoT.md`](../../docs/CareOtter/IoT/CareOtter_IoT.md).

### 4. `IgpClient.java`

**Purpose**: TCP client for the IGP v4 admin protocol.

**Wire format**:

```
Header (8 bytes, big-endian):
    [Magic(4) | Cmd(1) | Status(1) | Len(2)]
    Magic   = 0x43415245  ("CARE")
    Status  = 0x00 on request
    Len     = payload length in bytes
Payload (variable)
```

**Opcode table (current)**:

| Cmd  | Name             | Auth | Notes                                                  |
|------|------------------|------|--------------------------------------------------------|
| 0x01 | SYS_INFO         | No   | Kernel, arch.                                          |
| 0x02 | AUTHENTICATE     | No   | Sets global `authenticated=1`. Token via `decodeToken()`. |
| 0x03 | GET_NETWORK      | Yes  | Returns `/etc/config/wireless` (PSK in cleartext).     |
| 0x04 | SET_PREFS        | Yes  | TLV parser — integer underflow → stack BOF.            |
| 0x05 | VERIFY_STATUS    | No   | `snprintf(buf, size, user_input)` → format string.     |
| 0x06 | SET_WIFI         | Yes  | SSID/PSK concatenated into `system()` — OS injection.  |
| 0x07 | GET_VITALS       | Yes  | Proxies sensor service.                                |
| 0x08 | SET_THRESHOLD    | Yes  | Writes `/tmp/careotter.thresholds`.                    |
| 0x09 | REBOOT_SERVICE   | Yes  | `fork()` without `waitpid()` — zombie leak.            |
| 0x0A | GET_LOG          | Yes  | Reads `/tmp/careotter_events.log`.                     |
| 0x0B | DEFIBRILLATE     | Yes  | Second `snprintf` uses payload as format → log fmt-str.|
| 0x0C | EMERGENCY_ALERT  | Yes  | `curl -d 'msg=<payload>'` via `system()` → OS injection.|
| 0x0D | DEAUTHENTICATE   | Yes  | Sets global `authenticated=0`. Advisory only.          |

**Admin token (XOR-obfuscated, NOT plaintext in the APK)**:

```java
// VULNERABILITY: admin token XOR-obfuscated with key 0x5A — trivially reversible
private static final byte[] ENCODED_TOKEN = {
    0x15, 0x2F, 0x3E, 0x3E, 0x26, 0x06, 0x1B, 0x3E,
    0x2F, 0x33, 0x6C, 0x68, 0x6C, 0x63, 0x6C
};
// decodeToken() reverses each byte with ^ 0x5A → "OtterMobile2026"
```

The literal `"OtterMobile2026"` does **not** appear in `strings base.apk` — it is reconstructed at runtime by `decodeToken()`. See [`docs/CareOtter/CareOtter_Test_Suite.md`](../../docs/CareOtter/CareOtter_Test_Suite.md#igp-01--hardcoded-credential-ottermobile2026), Path B, for the three recovery techniques (decoder replay, single-byte XOR brute force, Frida hook).

### 5. `BleMonitorClient.java`

**Purpose**: BLE GATT client. Subscribes to Heart Rate (`0x2A37`), SpO₂ (`0x2A5E`), Battery (`0x2A19`) and consumes the CareOtter custom service `0xFF00` (alert/config — including the unauthenticated threshold write at `0xFF01` exploited in BLE-05/BLE-07).

### 6. `VitalsLogger.java`

**Purpose**: Plaintext log of vitals to `/sdcard/careotter_vitals.log` — VULN exposed by BLE-03 (CWE-312, M9 Insecure Data Storage).

### 7. `CareOtterConfig.java`

**Purpose**: Compile-time defaults (API host, port, BLE service UUIDs, hardcoded thresholds — the M4 hardcoded clinical defaults).

## Layouts

| File                  | Used by         | Notes                                                    |
|-----------------------|-----------------|----------------------------------------------------------|
| `activity_login.xml`  | LoginActivity   | Two-card layout: sign-in + API server (prefix + host octet input, Detect WiFi prefix + Ping API buttons). |
| `activity_main.xml`   | MainActivity    | Patient view; hidden DIAG panel (`visibility="gone"` until 5 quick taps). |
| `activity_admin.xml`  | AdminActivity   | Admin command buttons, output console, status indicator. |

## Manifest essentials

`AndroidManifest.xml` declares:

- `INTERNET`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE` (for the API ping/auto-detect).
- `BLUETOOTH` / `BLUETOOTH_ADMIN` (≤ API 30), `BLUETOOTH_SCAN`, `BLUETOOTH_CONNECT` (API 31+).
- `ACCESS_FINE_LOCATION` (required for BLE scan on Android ≤ 11).
- `WRITE_EXTERNAL_STORAGE` / `READ_EXTERNAL_STORAGE` (vitals log on `/sdcard`).
- Three activities: `LoginActivity` (LAUNCHER), `MainActivity`, `AdminActivity`.

## Inputs

| Layer    | Source Path                                         | Role/Description                                  |
|----------|-----------------------------------------------------|---------------------------------------------------|
| Layer 3  | `../../docs/CareOtter/CareOtter.md`                 | Protocol/vuln reference                           |
| Layer 3  | `../../docs/CareOtter/Mobile/CareOtter_App.md`      | Mobile-layer vuln catalogue                       |
| Layer 3  | `../../docs/CareOtter/CareOtter_Test_Suite.md`      | Reproduction tests (BLE-01..14, IGP-01..08)       |
| Layer 4  | `../../labs/careotter/careservice.c`                | IGP v4 protocol authority                         |
| Layer 4  | `../../labs/careotter/files/opt/medical-sensor/`    | BLE GATT server (peer)                            |
| Layer 4  | `../../cloud_api/careotter/api_server/`             | Cloud API (login + JWT issuer)                    |

## Process

### 1. Build

```bash
cd vulnzoo_apps/careotter_app
./gradlew assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

### 2. Deploy

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

### 3. First-run flow (patient)

1. Open the app → LoginActivity.
2. Tap **Detect WiFi prefix** (auto-fills the network portion from `wlan0`).
3. Set the host octet to the operator PC running the Cloud API.
4. Tap **Ping API** to confirm reachability (3 s ICMP).
5. Enter `patient` / `patient123` (default Cloud API seed).
6. Routed to **MainActivity** → BLE auto-connects to `CareOtter_HR`.

### 4. First-run flow (admin)

1. Login as `admin` / `CareOtter2026!` (default Cloud API seed).
2. Routed to **AdminActivity**.
3. Each button press triggers `execProtected()` (auth → cmd → deauth) against `192.168.2.1:9999`.

> **Architectural note**: AdminActivity targets `192.168.2.1` (the Ethernet segment). If the phone is on WiFi only, that IP is unreachable. The lab assumes a phone bridged to the Pi segment, or a tethered USB connection. This is a known open issue.

## Outputs

| Artifact      | Location                                  |
|---------------|-------------------------------------------|
| APK (debug)   | `app/build/outputs/apk/debug/`            |
| APK (release) | `app/build/outputs/apk/release/`          |
| AAB           | `app/build/outputs/bundle/`               |
| Vitals log    | `/sdcard/careotter_vitals.log` (on device)|

## Verification Checklist

- [ ] App builds with Gradle 8 / AGP current.
- [ ] LoginActivity auto-detects WiFi prefix and pings Cloud API.
- [ ] Patient login → MainActivity → BLE notifications stream.
- [ ] Admin login → AdminActivity buttons execute auth → cmd → deauth (3 frames visible in tcpdump on `:9999`).
- [ ] `decodeToken()` invocation produces `OtterMobile2026` (verifiable via Frida hook).
- [ ] Hidden DIAG panel appears after 5 quick taps on the MainActivity title.
- [ ] `/sdcard/careotter_vitals.log` accumulates plaintext vitals.

## Vulnerability Inventory (this APK contributes to)

| ID     | Layer doc                                          | Component                |
|--------|----------------------------------------------------|--------------------------|
| BLE-01 | `Mobile/CareOtter_App.md` VULN #1 / M4             | BleMonitorClient         |
| BLE-02 | `Mobile/CareOtter_App.md` VULN #5                  | BleMonitorClient         |
| BLE-03 | `Mobile/CareOtter_App.md` VULN #3                  | VitalsLogger             |
| BLE-04 | `Mobile/CareOtter_App.md` VULN #6                  | MainActivity (DIAG)      |
| BLE-05 | `Mobile/CareOtter_App.md` VULN #2                  | BleMonitorClient (0xFF01)|
| BLE-06 | `Mobile/CareOtter_App.md` M1                       | BleMonitorClient (CSCP)  |
| BLE-07 | `Mobile/CareOtter_App.md` M3                       | BleMonitorClient (CSCP)  |
| IGP-01 | `CareOtter_Test_Suite.md` IGP-01 Path B            | IgpClient (XOR token)    |
| IGP-06 / I7.2 | `IoT/CareOtter_IoT.md` I6 / I7.2            | AdminActivity (race)     |

## References

- IoT side:   [`docs/CareOtter/IoT/CareOtter_IoT.md`](../../docs/CareOtter/IoT/CareOtter_IoT.md)
- API side:   [`docs/CareOtter/API/CareOtter_API.md`](../../docs/CareOtter/API/CareOtter_API.md)
- Test Suite: [`docs/CareOtter/CareOtter_Test_Suite.md`](../../docs/CareOtter/CareOtter_Test_Suite.md)
- Attack chains: [`docs/CareOtter/Attack_Playbook.md`](../../docs/CareOtter/Attack_Playbook.md)
- careservice authority: [`labs/careotter/careservice.c`](../../labs/careotter/careservice.c)
