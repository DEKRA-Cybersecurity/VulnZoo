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

The source code explicitly documents five vulnerabilities via inline comments:

| # | Type | Location | Description |
|---|------|----------|-------------|
| 1 | **Missing BLE pairing / bonding** | `BleMonitorClient.startScan()` | Connects to any peripheral advertising the name `CareOtter_HR` without MAC whitelist, pairing, or authentication. |
| 2 | **Unvalidated GATT writes** | `BleMonitorClient.writeThreshold()` | Raw JSON string is written directly to the `ALERT_THRESHOLD` characteristic without schema or length validation. |
| 3 | **Plaintext external storage logging** | `VitalsLogger` | All BPM/SpO₂ readings are appended to `/sdcard/careotter_vitals.log` in cleartext. |
| 4 | **Hardcoded thresholds** | `MainActivity.DEFAULT_THRESHOLDS` | Default clinical thresholds (`bpm_min=40`, `bpm_max=120`, `spo2_min=90`) are visible via static analysis / APK decompilation. |
| 5 | **Unencrypted BLE channel** | `BleMonitorClient` | No LE Secure Connections, no encryption, no MITM protection. Data travels in plaintext over 2.4 GHz. |

---

## Pentest Test Cases

### 1. BLE Spoofing & Impersonation

| Test | Tool / Method | Expected Result |
|------|---------------|-----------------|
| **Rogue device spoofing** | Second Raspberry Pi, ESP32, or Bettercap broadcasting the name `CareOtter_HR` with identical GATT service UUIDs. | The app auto-connects to the attacker-controlled device without requesting pairing or verifying the MAC address. Confirms **VULN #1**. |
| **Passive BLE sniffing** | Ubertooth One, nRF Sniffer, or rooted Android with `btmon` / HCI snoop. | Captured GATT notifications reveal BPM and SpO₂ values in plaintext. Confirms **VULN #5**. |
| **Characteristic cloning** | The rogue peripheral responds to reads/writes on `ALERT_THRESHOLD` (0xFF01) with attacker-controlled values. | The app accepts spoofed threshold data as legitimate because there is no signature or authenticity check. |

### 2. Medical Data Injection

| Test | Tool / Method | Expected Result |
|------|---------------|-----------------|
| **Vitals falsification** | Rogue device sends HR notifications with BPM = 0, BPM = 250, or SpO₂ = 0. | The app displays critical values and triggers the local alert banner, proving an attacker can inject clinical panic. |
| **Malicious threshold manipulation** | In the app UI, edit the JSON threshold field to `{"bpm_min":0,"bpm_max":300,"spo2_min":0}` and tap *Write Threshold*. | The raw JSON is sent unvalidated to the DAI (**VULN #2**). If accepted by `ble_server.py`, life-saving alerts are effectively disabled (*therapeutic suppression*). |
| **BLE fuzzing** | Use *nRF Connect* or a custom GATT client to write malformed payloads (e.g., `AAAA`, `<script>`, null bytes, oversized buffers) to `0xFF01`. | Observe whether `ble_server.py` crashes, throws a D-Bus exception, or writes garbage to `/tmp/careotter.thresholds`. |

### 3. Data Exfiltration & Privacy

| Test | Tool / Method | Expected Result |
|------|---------------|-----------------|
| **External storage log extraction** | `adb shell cat /sdcard/careotter_vitals.log` | All historical BPM/SpO₂ readings with timestamps are exposed in plaintext. On Android ≤ 10, any app with `READ_EXTERNAL_STORAGE` can access this file (**VULN #3**). |
| **APK static analysis** | Decompile with JADX or apktool. | Hardcoded UUIDs, default thresholds, and the target device name `CareOtter_HR` are trivially recoverable (**VULN #4**). |
| **ADB backup extraction** | `adb backup com.vulnzoo.careotter_app` | Because `android:allowBackup="true"`, app data can be extracted without root, potentially including cached thresholds and logs. |

### 4. Denial of Service (Patient-Side)

| Test | Tool / Method | Expected Result |
|------|---------------|-----------------|
| **Forced disconnection** | 2.4 GHz jamming (Wi-Fi flood on BLE-adjacent channels) or scripted GATT disconnect from the rogue device. | The app shows "Desconectado" and stops receiving vitals. There is **no HTTP fallback**, so monitoring ceases entirely. |
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
