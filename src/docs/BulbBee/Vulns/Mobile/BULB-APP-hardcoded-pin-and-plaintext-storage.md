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
affected_components:
  - "vulnzoo_apps/bulbbee_app/app/src/main/java/com/vulnzoo/bulbbee_app/ui/SetupFragment.java"
  - "vulnzoo_apps/bulbbee_app/app/src/main/java/com/vulnzoo/bulbbee_app/ble/BleController.java"
  - "vulnzoo_apps/bulbbee_app/app/src/main/java/com/vulnzoo/bulbbee_app/cloud/CloudRepository.java"
  - "vulnzoo_apps/bulbbee_app/app/src/main/java/com/vulnzoo/bulbbee_app/cloud/CloudClient.java"
  - "vulnzoo_apps/bulbbee_app/app/src/main/java/com/vulnzoo/bulbbee_app/local/LocalClient.java"
  - "vulnzoo_apps/bulbbee_app/app/src/main/java/com/vulnzoo/bulbbee_app/MainActivity.java"
  - "vulnzoo_apps/bulbbee_app/app/src/main/java/com/vulnzoo/bulbbee_app/ui/LightViewModel.java"
  - "vulnzoo_apps/bulbbee_app/app/src/main/java/com/vulnzoo/bulbbee_app/ui/LightFragment.java"
  - "vulnzoo_apps/bulbbee_app/app/src/main/java/com/vulnzoo/bulbbee_app/ui/LoginFragment.java"
verified_date: "2026-09-04"
---

## Why It Matters

The BulbBee Android app is the device's controller over BLE. It embeds the factory pairing PIN `8080` in the source, so it ships inside the APK, is identical on every install, and is recovered by unzipping and reading the app (M1). This is the client side of BULB-01, the "the PIN is extractable from the app" claim made literal. The app also saves the home WiFi PSK and the cloud pairing token in plaintext `SharedPreferences` and writes them to Logcat (M9), so malware, a backup, or anyone with device access reads the home network credentials, the client side of BULB-05.

## Root Cause

Hardcoded credential (M1 / CWE-798):

```java
// ui/SetupFragment.java
private static final String PAIRING_PIN = "8080";   // extractable from the APK, same on every unit
```

Cleartext storage + log leak (M9 / CWE-312):

```java
SharedPreferences prefs = getSharedPreferences("bulbbee", Context.MODE_PRIVATE);
prefs.edit().putString("wifi_psk", psk).putString("cloud_token", cloudToken).apply();  // plaintext at rest
Log.d(TAG, "stored creds ssid=" + ssid + " psk=" + psk + " token=" + cloudToken);       // leaked to Logcat
```

Missing controls: no secret in the app binary (the pairing secret should be per-device and provisioned, not baked in), and no protected storage (Android Keystore / EncryptedSharedPreferences) for the WiFi PSK and token, and no secrets in logs.

Cloud transport (M9 + insecure transport, client side of BULB-CLD): the remote leg (BULB-R4) logs in to the cloud API and drives the bulb over plain HTTP, then stores the returned bearer JWT in the same plaintext prefs and logs it:

```java
// cloud/CloudRepository.connect(...)
prefs.edit().putString("cloud_jwt", jwt).apply();          // bearer stored in the clear
Log.d(TAG, "cloud login user=" + user + " jwt=" + jwt);    // and leaked to Logcat
// cloud/CloudClient talks http:// (no TLS), so the JWT and the commands are on the wire in the clear
```

Persisted session (M9, BULB-U1): login is the app's mandatory first screen, and the bearer, the cloud base URL and the user are saved in the same plaintext prefs and auto-resumed on launch, so the cleartext token is now long-lived and re-authenticates with no re-login:

```java
// cloud/CloudRepository.signIn(...) / resumeSession()
prefs.edit().putString("cloud_jwt", token).putString("cloud_base", base)
    .putString("cloud_user", user).apply();     // the whole session in the clear
// on the next launch resumeSession() reloads it and marks the account signed in
```

## Steps to Reproduce

```sh
# M1: recover the hardcoded PIN from the built APK
unzip -p bulbbee_app.apk classes.dex | strings | grep 8080          # or apktool + read MainActivity
# M9: read the plaintext credentials from device storage (rooted / adb backup / malware)
adb shell run-as com.vulnzoo.bulbbee_app cat shared_prefs/bulbbee.xml   # wifi_psk / cloud_token / cloud_jwt in cleartext
adb logcat -s BulbBee                                                   # creds + cloud jwt printed to Logcat
# BULB-R4: the remote leg drives the bulb over plain HTTP, so the JWT and commands are sniffable on the wire
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
| App (cloud) | HTTPS + cert pinning, JWT in the Keystore | Protect the remote leg on the wire and at rest (BULB-R4) |

## Verification Checklist

- [x] `PAIRING_PIN = "8080"` is present in the app source / APK (M1). Verified in the debug APK: `strings classes3.dex | grep 8080`.
- [x] the WiFi PSK and cloud token are written to plain SharedPreferences and Logcat (M9), in `ui/SetupFragment.storeCredentials`.
- [ ] end-to-end BLE drive on a device is still pending hardware. The app builds (`assembleDebug` produces an APK) and implements BLE scan/connect, ring control (Control `0xFF31`, State notify `0xFF32`) and WiFi provisioning (Auth `0xFF41`, Config `0xFF42`) in `ble/BleController`. The UI is a fragment-based redesign (bottom nav: Light / Scenes / Routines / Setup) over `ble/BleRepository` + `ui/LightViewModel`.
- [x] BULB-R4: the remote leg (`cloud/CloudClient`, dependency-free) logs in and drives a bulb over the cloud API, and `cloud/CloudRepository` stores the bearer JWT in plaintext (`shared_prefs/bulbbee.xml` key `cloud_jwt`) and logs it, over plain HTTP. `CloudClient` verified against the live stack (login, control, scene, state).
- [x] BULB-R5: the local leg (`local/LocalClient`) embeds the static firmware key `bulbbee-local-16` and drives the bulb over AES-CCM `:6668` (proximity = control, BULB-P03/P06). Frame codec verified wire-compatible both directions against the reference CCM.
- [x] BULB-R6 binding: during onboarding `ble/BleController` reads the device serial (`device_id`) from the provisioning characteristic (`onDeviceId`) and stashes it in plaintext prefs (`cloud_device_id`, M9). On cloud sign-in `cloud/CloudRepository` `POST /api/register`s it, so remote control targets the real device (`bulbbee/<serial>/cmd`) instead of the first seeded bulb. The serial is enumerable and the app-driven registration has no proof of possession (BULB-P04 / P05).
- [x] BULB-U1..U5 (connection lifecycle): login is the mandatory first screen and the session (bearer + base + user) is persisted in plaintext prefs and auto-resumed on launch (M9 broadened into a long-lived cleartext bearer). The control screen auto-selects BLE proximity then Cloud (Decision U-1), resolving the bound bulb by the real device serial (`cloud_device_id`, so a seeded bulb the account owns does not shadow the provisioned one), with explicit Offline (from the cloud `online` / `last_seen` field, BULB-U3) and "Vincular device" (BULB-U4) states. The control-screen header holds Sign out (clears the session) and a client-side Forget device (clears the stored serial + per-user list, leaving the cloud binding). The app builds (`assembleDebug` BUILD SUCCESSFUL); the on-device runtime flow needs a phone + the peripheral.
