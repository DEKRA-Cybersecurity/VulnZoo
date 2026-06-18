---
id: M8
title: "Security Misconfiguration"
category: Mobile
status: DONE
severity: Medium
owasp: "Mobile M8 - Security Misconfiguration"
cwe: "CWE-912 (Hidden Functionality) / CWE-489 (Active Debug Code) / CWE-656 (Reliance on Security Through Obscurity)"
source_docs:
  - "CareOtter_App.md (VULN #6 hidden diagnostic panel, Pentest Test Cases section 6)"
  - "Vulns/Mobile/M3_Insecure_Authentication_Authorization.md (the threshold-write surface the panel targets)"
affected_components:
  - "vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/MainActivity.java - tvTitle 5-tap gesture, diagnosticPanel reveal, btnReadThreshold/btnWriteThreshold handlers, DEFAULT_THRESHOLDS"
  - "vulnzoo_apps/careotter_app/app/src/main/res/layout/activity_main.xml - diagnosticPanel (android:visibility=gone) wrapping etThresholdJson + btnReadThreshold + btnWriteThreshold"
  - "vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/BleMonitorClient.java - writeThreshold (plain-JSON write to 0xFF01)"
verified_date: ""
---

# M8 - Security Misconfiguration

> **Status:** DONE
> **OWASP:** Mobile M8 - Security Misconfiguration
> **CWE:** CWE-912 / CWE-489 / CWE-656
> **Severity:** Medium

---

## Why It Matters

A production medical app should ship only the functionality its users are meant to have. CareOtter ships more. Hidden inside the patient monitoring screen is a diagnostic panel that exposes clinical-threshold read and write controls. It is never shown in normal use, it is not gated by any role or credential, and it is revealed by an undocumented gesture. That is the textbook shape of OWASP Mobile M8: a debug or diagnostic capability left enabled in the release build and protected only by obscurity.

The panel is concealed two ways, both cosmetic. The layout marks it `android:visibility="gone"`, and the code only flips it to visible after a secret tap sequence on the title. Neither is a security control. A `gone` view still ships in the APK, and the gesture that unlocks it is a plain integer counter that any pentester reads out of the decompiled app in seconds. Once unlocked, the panel hands an end user controls that were meant for a factory or service technician.

The exposure is the vulnerability here, independent of downstream impact. As implemented today the panel speaks the legacy plain-JSON threshold protocol while the device has moved to CSCP v1, so the panel's write is rejected by current firmware (see [[#8.4 - Functional reality against current firmware]]). The hidden functionality is still present, still unlockable, and still a misconfiguration. The working threshold-suppression attack against the live device is the M1 and M3 chain (forged CSCP v1 over direct BLE), not this panel.

---

## OWASP Classification

| Category | Role |
|---|---|
| **M8 - Security Misconfiguration** | Primary - a diagnostic/debug panel is shipped in the production build, not removed or access-controlled, and is hidden only by `visibility=gone` plus an obscure gesture (CWE-912 hidden functionality, CWE-489 active debug code, CWE-656 security through obscurity) |
| **M3 - Insecure Authentication/Authorization** | Related - the controls the panel exposes (threshold write to `0xFF01`) are themselves unauthenticated. Owned by [[M3_Insecure_Authentication_Authorization]] |
| **M1 - Improper Credential Usage** | Related - the actual working threshold-forging path uses the hardcoded CSCP key. Owned by [[M1_Improper_Credential_Usage]] |
| **M4 - Insufficient Input/Output Validation** | Related - the panel's write goes out unvalidated via `BleMonitorClient.writeThreshold`. Owned by [[M4_Insufficient_Input_Output_Validation]] |

**Why M8.** The defect is not the threshold write itself (that is M1/M3/M4) but the fact that a concealed diagnostic surface was left in the shipped app and is reachable by a normal user through an undocumented gesture. Shipping enabled debug/diagnostic functionality, relying on obscurity to hide it, is exactly OWASP Mobile M8's scope.

---

## 8.1 - A hidden diagnostic panel ships in the production build

The patient screen contains a diagnostic panel that is laid out but hidden. In `activity_main.xml` the panel and its threshold controls are declared with `android:visibility="gone"`:

```xml
<!-- activity_main.xml -->
<LinearLayout
    android:id="@+id/diagnosticPanel"
    ...
    android:visibility="gone">
    <EditText android:id="@+id/etThresholdJson" ... />
    <Button   android:id="@+id/btnReadThreshold"  ... />
    <Button   android:id="@+id/btnWriteThreshold" ... />
</LinearLayout>
```

`gone` removes the view from the rendered UI, but it is still compiled into the APK and instantiated at runtime. `MainActivity` wires the controls in `onCreate`, pre-filling the editor with the hardcoded default thresholds and binding the read/write buttons straight to BLE:

```java
// MainActivity.onCreate()
diagnosticPanel   = findViewById(R.id.diagnosticPanel);
etThresholdJson   = findViewById(R.id.etThresholdJson);
etThresholdJson.setText(DEFAULT_THRESHOLDS);   // {"bpm_min":40,"bpm_max":120,"spo2_min":90}
btnReadThreshold.setOnClickListener(v -> bleClient.readThreshold());
btnWriteThreshold.setOnClickListener(v -> {
    String raw = etThresholdJson.getText().toString();
    bleClient.writeThreshold(raw);   // plain JSON written to 0xFF01
    parseThresholds(raw);
});
```

There is no `BuildConfig.DEBUG` guard around any of this. The panel and its gesture are present in every build type, release included.

---

## 8.2 - It is unlocked by an obscure gesture, not a control

The only thing standing between a normal user and the panel is a tap counter on the title text. Five taps within three seconds reveal the panel:

```java
// MainActivity - fields
private int     diagTapCount  = 0;
private long    diagLastTapMs = 0;
private static final int  DIAG_TAP_TARGET  = 5;
private static final long DIAG_TAP_WINDOW  = 3000; // ms

// MainActivity.onCreate() - secret unlock gesture
tvTitle.setOnClickListener(v -> {
    long now = System.currentTimeMillis();
    if (now - diagLastTapMs > DIAG_TAP_WINDOW) diagTapCount = 0;
    diagLastTapMs = now;
    diagTapCount++;
    if (diagTapCount >= DIAG_TAP_TARGET) {
        diagTapCount = 0;
        diagnosticPanel.setVisibility(View.VISIBLE);
        Toast.makeText(this, "Diagnostic mode enabled", Toast.LENGTH_SHORT).show();
        appendLog("[DIAG] Threshold panel unlocked");
    }
});
```

This is security through obscurity (CWE-656). The gesture is a convenience lock, not an authentication or authorization check. Any user who knows or guesses the gesture, or who reads it out of the app, gets the panel.

---

## 8.3 - The hidden functionality is trivially discoverable in the shipped APK

A pentester does not need the source. The unlock gesture and the panel are recoverable from the release artifact with `strings` or `jadx`. Running `strings` over the app's `classes.dex` surfaces every marker:

```sh
# from the built APK
for d in $(unzip -Z1 app-debug.apk | grep '\.dex$'); do unzip -p app-debug.apk "$d"; done \
  | strings -n 5 | grep -iE "diagnostic|DIAG_TAP|threshold panel|bpm_min"
```

```
Diagnostic mode enabled
[DIAG] Threshold panel unlocked
diagnosticPanel
diagTapCount
DIAG_TAP_TARGET
DIAG_TAP_WINDOW
{"bpm_min":40,"bpm_max":120,"spo2_min":90}
```

### Finding the threshold misconfigurations with jadx

`jadx` makes the whole threshold story recoverable offline. Decompile once - it writes `sources/` (decompiled Java) and `resources/` (layouts, strings, the `R` id mapping) - then grep both trees:

```sh
jadx -d "$(pwd)/out" "$(pwd)/careotter_app.apk"          # CLI; or open in jadx-gui careotter_app.apk
```

1. Hardcoded clinical thresholds - the values an attacker wants to neutralise (cross-ref [[M1_Improper_Credential_Usage]] / [[M4_Insufficient_Input_Output_Validation]]):

```sh
grep -rn "DEFAULT_THRESHOLDS\|bpm_min\|bpm_max\|spo2_min" out/sources/
# out/sources/com/vulnzoo/careotter_app/MainActivity.java:
#   DEFAULT_THRESHOLDS = "{\"bpm_min\":40,\"bpm_max\":120,\"spo2_min\":90}";
```

2. The hidden diagnostic panel and its unlock gesture - the M8 misconfiguration itself:

```sh
grep -rn "diagnosticPanel\|DIAG_TAP_TARGET\|DIAG_TAP_WINDOW\|diagTapCount" out/sources/
# MainActivity.java:
#   private static final int  DIAG_TAP_TARGET  = 5;
#   private static final long DIAG_TAP_WINDOW  = 3000;
#   tvTitle.setOnClickListener(...) { ... diagnosticPanel.setVisibility(0); }  // 0 = View.VISIBLE
```

3. Confirm the panel is shipped-but-hidden in the extracted layout (`gone` is not a control):

```sh
grep -n "diagnosticPanel\|etThresholdJson\|btnWriteThreshold\|visibility" \
    out/resources/res/layout/activity_main.xml
# android:id="@id/diagnosticPanel" ... android:visibility="gone"
```

4. The writable threshold characteristic and the plain-JSON write path the panel uses:

```sh
grep -rn "writeThreshold\|ALERT_THRESHOLD\|0000ff01\|getBytes" out/sources/
# BleMonitorClient.java:
#   ALERT_THRESHOLD = UUID.fromString("0000ff01-0000-1000-8000-00805f9b34fb");
#   chr.setValue(rawJson.getBytes(StandardCharsets.UTF_8));  // raw JSON to 0xFF01, no CSCP framing
```

In jadx-gui the same trail is faster: open `MainActivity`, run "Find Usage" on `diagnosticPanel` to land on the `tvTitle` gesture, then "Go to declaration" on `btnWriteThreshold` to reach `BleMonitorClient.writeThreshold` and the `0xFF01` UUID. One more search turns the rejected plain-JSON write into the real, forgeable CSCP v1 write - `grep -rn "CSCP_KEY\|careotter-key" out/sources/` recovers the hardcoded AES key (see [[M1_Improper_Credential_Usage]] and §8.4). The app documents its own hidden functionality to an attacker.

---

## 8.4 - Functional reality against current firmware

The panel exists and unlocks, but its operations target the legacy plain-JSON threshold protocol, which the current device no longer speaks. The write path sends raw JSON bytes:

```java
// BleMonitorClient.writeThreshold() - no CSCP framing, raw JSON bytes
chr.setValue(rawJson.getBytes(StandardCharsets.UTF_8));
gatt.writeCharacteristic(chr);
```

The device firmware accepts only CSCP v1 (24 bytes, magic `0xCAFE0DDA`, CRC32, AES-128-ECB) and silently drops anything else:

```python
# ble_server.py - AlertThresholdChrc.WriteValue()
raw = bytes(value)
thresholds = self._decrypt_and_unpack(raw)   # requires 24B + magic + CRC
if thresholds is None:
    print(f"[BLE] CSCP v1 WriteValue: rejected (bad magic/CRC/size) {raw.hex()}")
    return
```

So tapping `Write Threshold` in the unlocked panel produces a write the device rejects, and `Read Threshold` returns a CSCP-encrypted blob that the app renders as garbage in the editor. The consequence for triage: the M8 finding is the hidden-functionality exposure, not a live alert-suppression. The live alert-suppression attack is M1 + M3, which forges a valid CSCP v1 packet and writes it to `0xFF01` directly over BLE, bypassing the app entirely. The panel is a stale diagnostic relic, which is itself a security-misconfiguration smell: dead privileged code left in production.

---

## Attack flow

1. **Discover.** Decompile the APK with `jadx` (or run `strings`). Find `diagTapCount` / `DIAG_TAP_TARGET` in `MainActivity` and `diagnosticPanel` in the resources. The gesture is now known: five taps on the title within three seconds.
2. **Unlock.** Launch the app, log in as a patient, reach the monitor screen, and tap the `CareOtter Monitor` title five times quickly. The panel appears with a `Diagnostic mode enabled` toast.
3. **Operate.** The panel exposes `Read Threshold`, an editable JSON field pre-filled with the hardcoded defaults, and `Write Threshold` bound directly to BLE `0xFF01`.
4. **Impact (current firmware).** The write is rejected by CSCP v1, so no thresholds change via the panel. The realized impact is the exposure of hidden, technician-only functionality and the hardcoded clinical defaults to an ordinary user.
5. **Pivot to a working attack.** Use the surface this reveals (the writable `0xFF01` characteristic and the hardcoded CSCP key from the same APK) to run the M1/M3 chain over direct BLE for real threshold suppression. See [[M3_Insecure_Authentication_Authorization]] and [[M1_Improper_Credential_Usage]].

---

## Verification Checklist

- [ ] `activity_main.xml` declares `diagnosticPanel` with `android:visibility="gone"` wrapping `etThresholdJson`, `btnReadThreshold`, `btnWriteThreshold`.
- [ ] `MainActivity` reveals the panel after five taps on the title within three seconds (`DIAG_TAP_TARGET=5`, `DIAG_TAP_WINDOW=3000`); no role or credential is checked.
- [ ] No `BuildConfig.DEBUG` guard wraps the panel or gesture (it ships in release builds).
- [ ] `strings` / `jadx` over the built APK recover `Diagnostic mode enabled`, `[DIAG] Threshold panel unlocked`, `diagnosticPanel`, `DIAG_TAP_TARGET`, and the hardcoded `{"bpm_min":40,"bpm_max":120,"spo2_min":90}`.
- [ ] Dynamic: perform the gesture on a device and confirm the panel appears (the `Diagnostic mode enabled` toast and `[DIAG] Threshold panel unlocked` log line fire).
- [ ] Confirm the panel's plain-JSON write is rejected by the current device (`ble_server.py` logs `CSCP v1 WriteValue: rejected (bad magic/CRC/size)`), confirming the panel is a legacy relic and the live attack is M1/M3.

```sh
# Dynamic observation
adb logcat -s MainActivity:V
# expect on unlock: "[DIAG] Threshold panel unlocked"
```

---

## Remediation

For reference only - do not apply in the lab.

- Remove diagnostic/debug functionality from release builds. If it must exist for development, gate it behind `BuildConfig.DEBUG` so it is stripped from production.
- Do not rely on `visibility=gone` or a secret gesture as a security boundary. Obscurity is not access control (CWE-656).
- If a service/technician mode is genuinely required in production, put it behind real authentication and authorization (a backend-verified service role), not a tap counter.
- Delete dead/stale privileged code paths. The plain-JSON threshold panel no longer matches the device protocol and should not be shipping at all.
