You are working on VulnZoo, a medical IoT hacking lab. The Android project structure is:

vulnzoo_apps/
├── careotter_app/     ← PATIENT MONITORING app (BLE only)
└── careotter_admin/   ← DEVICE ADMIN app (IGP :9999 only)

## Current situation

The existing careotter_admin app incorrectly handles both BLE and IGP connections in the same application. This needs to be separated into two fully independent Android apps.

---

## Task 1 — Create careotter_app (patient monitoring via BLE)

Create a complete Android app in `vulnzoo_apps/careotter_app/` that connects exclusively via Bluetooth Low Energy to the CareOtter device.

### Functionality

The app simulates a patient-facing cardiac monitor. It must:

1. Scan for BLE devices and connect to the CareOtter device by name ("CareOtter Medical") or MAC address entered manually
2. Subscribe to GATT notifications on:
   - Service `0x180D`, Characteristic `0x2A37` — Heart Rate Measurement (BPM)
   - Service `0x1822`, Characteristic `0x2A5F` — Pulse Oximeter (SpO2)
3. Read device info from Service `0x180A`:
   - Characteristic `0x2A29` Manufacturer Name
   - Characteristic `0x2A24` Model Number
4. Read and write the custom alert threshold characteristic `0000ff01-0000-1000-8000-00805f9b34fb`
   - Display current thresholds: bpm_min, bpm_max, spo2_min
   - Allow the user to write new threshold values (raw JSON string, no validation)
5. Display live BPM and SpO2 values updating in real time as notifications arrive
6. Show a visual alert (red banner) when a received value is outside the threshold range

### UI layout (activity_main.xml)

- `tvDeviceName` — connected device name/MAC
- `tvBpm` — large display of current BPM value
- `tvSpo2` — large display of current SpO2 %
- `tvAlertBanner` — hidden by default, visible red banner when alert fires
- `tvManufacturer` / `tvModel` — device info fields
- `etThresholdJson` — EditText showing raw JSON threshold string
- `btnScan` — start BLE scan
- `btnConnect` — connect to selected device
- `btnDisconnect` — disconnect
- `btnReadThreshold` — read current threshold from characteristic
- `btnWriteThreshold` — write etThresholdJson content to characteristic (no validation)
- `tvOutput` — scrollable log of BLE events

### Intentional vulnerabilities

1. **No BLE pairing** — connect without any pairing or bonding
2. **No input validation on threshold write** — whatever is in `etThresholdJson` is written directly to the characteristic as raw bytes, including injected or malformed JSON
3. **Plaintext logging** — all received BPM/SpO2 values are logged to `/sdcard/careotter_vitals.log` with timestamp, no permission check beyond WRITE_EXTERNAL_STORAGE
4. **Hardcoded default thresholds** — the app initializes `etThresholdJson` with `{"bpm_min":40,"bpm_max":120,"spo2_min":90}` hardcoded in the source, visible via static analysis
5. **No certificate / no transport security** — BLE is used with no encryption, and the app does not warn the user

### Package and class structure
package com.vulnzoo.careotter_app
MainActivity.java         — UI, BLE event handling, alert logic
BleMonitorClient.java     — BLE scan, connect, GATT callbacks, read/write
VitalsLogger.java         — writes to /sdcard/careotter_vitals.log
---

## Task 2 — Refactor careotter_admin (device admin via IGP only)

Refactor the existing app in `vulnzoo_apps/careotter_admin/` to remove ALL BLE code. This app connects exclusively via TCP to IGP v4 on port 9999.

### Keep from current implementation

- `CareOtterClient.java` — all existing IGP commands (0x01–0x05) unchanged
- `MainActivity.java` — all existing buttons and output logic unchanged
- All four existing intentional vulnerabilities (XOR token, exploit helpers, StrictMode.permitNetwork, plaintext TCP)

### Add to CareOtterClient.java

```java
// Command 0x06 - DEFIBRILLATE_CMD (auth required)
public String triggerDefibrillator() throws IOException
// Returns "DEFIB_TRIGGERED:200J:<timestamp>" or "RESTRICTED"

// Command 0x07 - EMERGENCY_ALERT (auth required)
// VULNERABILITY: payload fed into system() on server — OS command injection
public String sendEmergencyAlert(String alertMessage) throws IOException
// Returns "ALERT_SENT:<echo>" or "RESTRICTED"

// Exploit helper for command injection
public String exploitCommandInjection() throws IOException
// Sends alertMessage = "test'; reboot #"
```

### Add to MainActivity.java

New buttons in the existing layout:
- `btnDefibrillate` — calls `triggerDefibrillator()`, requires isAuthenticated(), shows result
- `btnEmergencyAlert` — calls `sendEmergencyAlert()` using `etModuleName` text as message
- `btnCmdInjection` — calls `exploitCommandInjection()`, label: "CMD INJECTION EXPLOIT"

Remove from MainActivity.java:
- Any BLE scanning, connecting, or GATT code
- Any Bluetooth permission requests
- Any BLE status indicator

Update the package to `com.vulnzoo.careotter_admin` if it differs.

---

## Constraints

- Both apps target Android API 26+ (minSdk 26)
- No third-party BLE libraries — use Android's native `android.bluetooth.le` stack
- No Kotlin — Java only
- careotter_app has no network permissions (no INTERNET in manifest)
- careotter_admin has no Bluetooth permissions (no BLUETOOTH_SCAN / BLUETOOTH_CONNECT in manifest)
- Do not add any input sanitization, authentication, or security improvements to either app
- Both apps must compile without errors with standard Android SDK
- careotter_app must request BLUETOOTH_SCAN, BLUETOOTH_CONNECT, and WRITE_EXTERNAL_STORAGE permissions at runtime

## Deliverables

For each app provide the complete file contents of:
- `AndroidManifest.xml`
- `MainActivity.java`
- All supporting Java classes
- `res/layout/activity_main.xml`
- `build.gradle` (app level)