---
id: BULB-APP
title: "Android app: hardcoded pairing PIN (extractable) + plaintext credential storage"
category: Mobile
status: IN PROGRESS
severity: Medium
owasp: "OWASP Mobile Top 10 M1 (Improper Credential Usage) / M9 (Insecure Data Storage)"
standard: "ETSI EN 303 645 5.4 (securely store sensitive parameters)"
regulation: "CRA (EU) 2024/2847 Annex I Part I - protect stored data"
cwe: "CWE-798 (Use of Hard-coded Credentials) / CWE-312 (Cleartext Storage of Sensitive Information)"
source_docs:
  - "stages/01_spec/output/bulbbee-app-spec.md"
affected_components:
  - "vulnzoo_apps/bulbbee_app/app/src/main/java/com/vulnzoo/bulbbee_app/MainActivity.java"
verified_date: "2026-09-04"
---

## Why It Matters

The BulbBee Android app is the device's controller over BLE. It embeds the factory pairing PIN `8080` in the source, so it ships inside the APK, is identical on every install, and is recovered by unzipping and reading the app (M1). This is the client side of BULB-01, the "the PIN is extractable from the app" claim made literal. The app also saves the home WiFi PSK and the cloud pairing token in plaintext `SharedPreferences` and writes them to Logcat (M9), so malware, a backup, or anyone with device access reads the home network credentials, the client side of BULB-05.

## Root Cause

Hardcoded credential (M1 / CWE-798):

```java
// MainActivity.java
private static final String PAIRING_PIN = "8080";   // extractable from the APK, same on every unit
```

Cleartext storage + log leak (M9 / CWE-312):

```java
SharedPreferences prefs = getSharedPreferences("bulbbee", Context.MODE_PRIVATE);
prefs.edit().putString("wifi_psk", psk).putString("cloud_token", cloudToken).apply();  // plaintext at rest
Log.d(TAG, "stored creds ssid=" + ssid + " psk=" + psk + " token=" + cloudToken);       // leaked to Logcat
```

Missing controls: no secret in the app binary (the pairing secret should be per-device and provisioned, not baked in), and no protected storage (Android Keystore / EncryptedSharedPreferences) for the WiFi PSK and token, and no secrets in logs.

## Steps to Reproduce

```sh
# M1: recover the hardcoded PIN from the built APK
unzip -p bulbbee_app.apk classes.dex | strings | grep 8080          # or apktool + read MainActivity
# M9: read the plaintext credentials from device storage (rooted / adb backup / malware)
adb shell run-as com.vulnzoo.bulbbee_app cat shared_prefs/bulbbee.xml   # wifi_psk / cloud_token in cleartext
adb logcat -s BulbBee                                                   # creds printed to Logcat
```

## Expected Result

The PIN `8080` is present in the APK, and after onboarding the WiFi PSK and cloud token are readable in `shared_prefs/bulbbee.xml` and in Logcat.

## How It Should Be

- Do not embed a shared secret in the app, use a per-device pairing code (QR / label) provisioned at runtime.
- Store the WiFi PSK and token with the Android Keystore / EncryptedSharedPreferences, never in plain SharedPreferences.
- Never log secrets.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| App (creds) | Per-device pairing code, no hardcoded PIN | Remove the extractable shared secret (CWE-798) |
| App (storage) | Android Keystore / EncryptedSharedPreferences | Protect secrets at rest (CWE-312) |
| App (logging) | Strip secrets from logs | No Logcat leak |

## Verification Checklist

- [ ] `PAIRING_PIN = "8080"` is present in the app source / APK (M1).
- [ ] the WiFi PSK and cloud token are written to plain SharedPreferences and Logcat (M9).
- [ ] (blocked here) the app builds and drives the device over BLE, needs the Android toolchain and a device.
