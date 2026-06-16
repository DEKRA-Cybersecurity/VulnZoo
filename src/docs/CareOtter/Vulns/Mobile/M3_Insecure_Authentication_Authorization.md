---
id: M3
title: "Insecure Authentication/Authorization"
category: Mobile
status: DONE
severity: High
owasp: "Mobile M3 — Insecure Authentication/Authorization"
cwe: "CWE-294 (Authentication Bypass by Capture-replay) / CWE-306 (Missing Authentication for Critical Function) / CWE-285 (Improper Authorization)"
source_docs:
  - "CareOtter_App.md §M3 (BLE pairing not required to write 0xFF01)"
  - "CareOtter_Vulnerability_Resolution.md §BLE-07 (original mobile M3 lens — no session authentication)"
  - "CareOtter_Test_Suite.md §BLE-07 (forge_threshold reproduction)"
  - "Vulns/Mobile/M1_Improper_Credential_Usage.md (the CSCP key the token is built from)"
  - "Vulns/Mobile/M5_Insecure_Communication.md (the channel + the app never bonding the peer)"
  - "Vulns/IoT/IoT7_Insecure_Data_Transfer_and_Storage.md (device-side data handling, no range check, the DoS)"
affected_components:
  - "vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/CareOtterConfig.java — buildThresholdPacket (the app treats a CSCP packet as the sole authenticator)"
  - "vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/BleMonitorClient.java — connect/writeThreshold (no authenticated session before the config write)"
  - "labs/careotter/files/opt/medical-sensor/ble_server.py — AlertThresholdChrc (evidence: accepts any correctly-framed packet, no freshness, no requester check)"
verified_date: ""
---

# M3 — Insecure Authentication/Authorization

> **Status:** DONE
> **OWASP:** Mobile M3 — Insecure Authentication/Authorization
> **CWE:** CWE-294 / CWE-306 / CWE-285
> **Severity:** High

---

## Why It Matters

Setting a clinical alert threshold is a safety-critical operation — it decides whether a tachycardic arrest or a hypoxic crash raises an alarm. OWASP Mobile M3 asks how the app authenticates and authorizes operations like this. CareOtter doesn't authenticate or authorize operations in any meaningful sense. The app's *entire* proof of authority for writing thresholds to characteristic `0xFF01` is the ability to produce a correctly-framed CSCP v1 packet, and that packet is built from a static key shipped to every patient's phone, carries no session, no nonce, and no notion of *which* user or *which* operation it authorizes.

The sharp consequence is replay. Because CSCP is AES-128-ECB over a fixed-shape plaintext with a fleet-wide key and no freshness field, a given threshold-set always serializes to the byte-identical 24-byte packet. An attacker who captures one legitimate threshold write over the air can replay it verbatim to reconfigure the device, with no key, no pairing, and no account. That is an authentication failure that stands even if the key were perfectly secret — the protocol simply has no mechanism to tell a fresh, authorized request from a recorded one. Layer the extractable key ([[M1_Improper_Credential_Usage]]) on top and the attacker is no longer limited to replaying captured values, they can author arbitrary lethal ones.

This page owns the *authentication-and-authorization* defect: no authenticated session gates the write, no per-operation authorization binds it to a user, and the token is replayable.

---

## OWASP Classification

| Category | Role |
|---|---|
| **M3 — Insecure Authentication/Authorization** | Primary — the app authenticates a safety-critical config write by possession of a static, replayable CSCP token, with no authenticated session (CWE-306), no anti-replay (CWE-294), and no per-user/per-operation authorization (CWE-285) |
| **M1 (the credential)** | Cross-ref — the CSCP token is built from the fleet-wide AES key hard-coded in the APK. That the *credential* is recoverable is M1. That *possession of it is treated as authentication* is this page. Owned by [[M1_Improper_Credential_Usage]] |
| **M5 (the channel + peer)** | Cross-ref — M5 owns the unencrypted link and the app's failure to authenticate the *peer device* (no `createBond`). This page owns the failure to authenticate the *operation and the requester*. Owned by [[M5_Insecure_Communication]] |
| **IoT I7 (the data)** | Cross-ref — the device-side acceptance of the bytes, the absence of a clinical range check, and the deferred `ZeroDivisionError` DoS are the *data* lens. Owned by [[IoT7_Insecure_Data_Transfer_and_Storage]] §7.1 |

> **Where the line sits with IoT7.** [[IoT7_Insecure_Data_Transfer_and_Storage]] also names CWE-306, but for the *data* it carries: a hard-coded transport key and no validation of the received values, ending in the divide-by-zero DoS. This page is the *authentication/authorization* lens on the same write: even granting that the bytes are well-formed, nothing proves the request is fresh, came over an authenticated session, or was issued by a user authorized to configure this device. The DoS and the missing range check are referenced here in one line each and are not re-derived — read IoT7 for them.

---

## 3.1 — Possession of a CSCP packet is the only authenticator (CWE-306)

The app's threshold feature performs no authenticated handshake before the write. It builds a CSCP packet and sends it. The packet *is* the credential, the session, and the proof of authority, all at once:

```java
// CareOtterConfig.java — the app's "authentication" for a clinical-config write
// is the ability to emit these 24 bytes. No login, no session token, no
// pairing-derived per-user key is involved in producing or sending them.
byte[] ciphertext = cipher.doFinal(plaintext);          // AES-128-ECB, fleet key
buf.putInt(CSCP_MAGIC); buf.putInt((int) crc32.getValue()); buf.put(ciphertext);
return buf.array();                                     // -> written straight to 0xFF01
```

The device end confirms the design: the alert-threshold characteristic is a plain writable GATT attribute, and the write handler accepts the bytes from whoever sent them.

```python
# ble_server.py — AlertThresholdChrc (device side, cited as evidence)
self.flags = ["read", "write", "notify"]     # a plain writable characteristic:
                                             # no encrypted/authenticated write requirement is attached

def WriteValue(self, value: "ay", options: "a{sv}"):
    raw = bytes(value)                       # `options` (which carries the remote
                                             # device path and link type) is never
                                             # inspected — no bond/trust/identity check
    thresholds = self._decrypt_and_unpack(raw)
    ...
```

Two things are absent and both belong to M3. First, no *authenticated session*: BLE LE Secure Connections pairing is never required before the write, so there is no cryptographically authenticated peer behind the operation (the channel and the un-bonded peer are M5's subject — here the point is that the *operation* rides on no authenticated session). Second, no *application-layer identity*: the handler discards `options`, so it cannot and does not check that the writer is a known, trusted client. The write is a critical function with no authentication in front of it — CWE-306.

---

## 3.2 — The token is replayable: no session, no nonce, no freshness (CWE-294)

This is the defect M3 uniquely owns. CSCP carries nothing that ties a packet to a single use:

```python
# ble_server.py — _decrypt_and_unpack validates ONLY structure, never freshness
if len(packet) != 24:                  return None     # size
magic, crc = struct.unpack(">II", packet[:8])
if magic != self.CSCP_MAGIC:           return None     # magic
ciphertext = packet[8:]
if (binascii.crc32(ciphertext) & 0xFFFFFFFF) != crc: return None   # CRC
plaintext = AES.new(self.CSCP_KEY, AES.MODE_ECB).decrypt(ciphertext)
bpm_min, bpm_max, spo2_min = struct.unpack("BBB", plaintext[:3])    # 3 bytes used
# the other 13 plaintext bytes are fixed 0x00 padding — no nonce, counter, or timestamp
```

The 16-byte plaintext is `bpm_min, bpm_max, spo2_min` followed by 13 constant null bytes. There is no nonce, no monotonic counter, no timestamp, and no per-session challenge anywhere in the format, and the mode is ECB, so encryption is deterministic. A given threshold-set therefore always produces the same 24 ciphertext-bearing bytes, and the validator accepts any packet that merely re-derives the same magic and CRC. The direct result: a packet captured once is valid forever.

That capture needs no key. A passive over-the-air sniff of a legitimate caregiver setting thresholds (the M5 Variant C sniff) yields a complete, replayable 24-byte packet. Replaying it later re-applies those thresholds on demand. The authentication failure is independent of M1 — even if `careotter-key-16` were a per-device secret the attacker never learns, the recorded packet still replays, because the protocol has no way to reject a stale one. M1 only *widens* the attack from "replay values you have seen" to "author any values you want."

---

## 3.3 — No authorization binds the write to a user or a device (CWE-285)

Even an authenticated client should only be allowed to configure devices it owns. CSCP encodes no authorization context at all — no user id, no device id, no role, no capability. The packet that a patient's own phone produces for their own monitor is byte-identical to the one an attacker produces for the same model, because the only input is the three threshold values under the shared key. The device cannot distinguish "this patient configuring their device" from "a stranger in range configuring it for them," and it does not try. Any party able to reach the characteristic can set thresholds for any unit — missing function-level authorization on a clinical operation.

---

## 3.4 — Exploiting

The runnable BLE plumbing (discovery under the relaxed BlueZ filter, an unpaired `BleakClient` connect) is documented once in [[M5_Insecure_Communication]] Variants A–E and is not duplicated here. This section is the M3-specific sequence on top of it.

**Step 1 — Confirm the write gate is open with no pairing.** Connect as in M5 Variant B (no `createBond`, no security level requested) and verify the link is unauthenticated:

```bash
bluetoothctl info 43:45:C0:00:1F:AC
# Paired: no
# Bonded: no
```

The characteristic is also readable, so a *structurally valid* packet is obtainable with zero key knowledge — `ReadValue` returns `_pack_and_encrypt(current_thresholds)`. Writing that exact packet back is accepted, which proves the operation gate is open. Note honestly that this write-back is a semantic no-op (it re-applies the current values), so it demonstrates "no authentication," not an attack outcome.

```python
# m3_gate_open.py — prove 0xFF01 accepts a write with Paired:no / Bonded:no.
# `client` is the unpaired BleakClient from M5 Variant B (find_careotter + connect).
FF01 = "0000ff01-0000-1000-8000-00805f9b34fb"

async def demo(client):
    valid = await client.read_gatt_char(FF01)              # no key needed to obtain a valid packet
    await client.write_gatt_char(FF01, valid, response=True)  # accepted with no pairing challenge
    print("[+] 0xFF01 accepted a write over an unauthenticated, unbonded link")
```

**Step 2 — Replay a captured packet (no key, the CWE-294 path).** Take a 24-byte write captured in the M5 Variant C sniff (a caregiver legitimately changing thresholds) and write those exact bytes. It is accepted, because nothing makes it stale. This is the pure authentication bypass: attacker-chosen *timing* of a victim-authored packet, with no key and no account.

**Step 3 — Lethal end-to-end (chained, needs the key).** Replaying only reproduces values the attacker has observed. To set *arbitrary* lethal thresholds (`bpm_max=255`, `spo2_min=0`, or `bpm_min >= bpm_max` for the DoS) the attacker forges a fresh packet, which requires the extracted key — that is the M1 contribution, built in [[M1_Improper_Credential_Usage]] §1.3 and written end-to-end as [[M5_Insecure_Communication]] Variant E. M3 is the reason the forged or replayed packet is *accepted as authority*, the device-side outcome (acceptance matrix, range check, DoS) is [[IoT7_Insecure_Data_Transfer_and_Storage]] §7.1.

The acceptance matrix below (from the original BLE-07 lens) is what "no authentication on the operation" looks like in practice — the only gate is structural, never identity or freshness:

| Packet written to `0xFF01`       | Magic | CRC  | Size     | Authenticated/paired client? | Result                              |
| -------------------------------- | ----- | ---- | -------- | ---------------------------- | ----------------------------------- |
| Forged CSCP (lethal `0, 255, 0`) | ok    | ok   | 24       | not checked                  | Accepted — thresholds applied       |
| Replayed CSCP (captured, no key) | ok    | ok   | 24       | not checked                  | Accepted — values re-applied        |
| Bad magic                        | fail  | —    | 24       | not checked                  | Rejected (structure)                |
| Bad CRC                          | ok    | fail | 24       | not checked                  | Rejected (structure)                |
| Wrong size (≠ 24)                | —     | —    | —        | not checked                  | Rejected (structure)                |
| Plain JSON `{"bpm_min":0,...}`   | fail  | —    | variable | not checked                  | Rejected (magic mismatch, not auth) |

The last row is the tell: a plain-JSON write is rejected for failing the *format*, never for failing an *authentication* — there is no authentication step that could reject it.

---

## Clinical Impact

| Vector | Consequence | Patient Safety Risk |
|---|---|---|
| Captured packet replayed (no key) | Re-apply any threshold-set the attacker has sniffed, at a time of their choosing | High — a benign-looking replay can re-impose a previously-set wide window |
| Forged packet accepted (key, chained M1) | Set clinically impossible thresholds the device trusts | Critical — silent suppression of cardiac / hypoxia alarms |
| No per-operation authorization | A stranger in range reconfigures a device they do not own | High — clinical configuration by an unauthorized party |
| No authenticated session | No trusted identity is ever bound to the write, so no audit or accountability exists | Medium — incident response cannot attribute the change |

---

## How It Should Be

- **Require an authenticated session before any write to `0xFF01`.** Gate the characteristic behind LE Secure Connections pairing and bonding, so the write rides on a cryptographically authenticated peer rather than on possession of a shared packet (closes CWE-306).
- **Make the operation non-replayable.** Put a server-issued nonce or a monotonic counter inside the authenticated payload and reject any packet that reuses one, or use a challenge-response per write. Deterministic ECB over a constant-shape plaintext must go (closes CWE-294).
- **Authorize the requester per device.** Bind the write to an authenticated user identity and check that this user is permitted to configure this specific unit, rather than trusting anyone who can frame a packet (closes CWE-285).
- **Authenticate, do not merely encrypt.** Replace the "encrypt and assume authentic" CSCP design with an AEAD construction (for example AES-GCM) whose tag, key, and nonce are tied to the authenticated session, so confidentiality and authenticity are separate, session-bound properties.
- **Out of scope here, see siblings.** Per-device keys instead of a fleet-wide constant is the M1 control ([[M1_Improper_Credential_Usage]]). Clinical range validation on the received values is the IoT7 control ([[IoT7_Insecure_Data_Transfer_and_Storage]]). They are complementary and not restated here.

---

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| BLE session | LE Secure Connections pairing + bonding required before `0xFF01` writes | Bind the write to an authenticated peer (CWE-306) |
| Protocol | Server nonce / monotonic counter / challenge-response inside the signed payload | Make captured packets non-replayable (CWE-294) |
| Authorization | Per-user identity bound to the operation + per-device ownership check | Stop unauthorized parties configuring devices they do not own (CWE-285) |
| Cryptography | AEAD (AES-GCM) with a session-bound key and nonce, replacing AES-ECB+CRC | Authenticity as a real property, not a serialization side effect |
| Audit | Log each accepted write with the authenticated identity and a fresh request id | Enable attribution and post-incident forensics |

---

## Verification Checklist

- [ ] **§3.1 (no session)**: connecting and writing `0xFF01` per [[M5_Insecure_Communication]] Variant B succeeds with `bluetoothctl info` reporting `Paired: no` and `Bonded: no` — no pairing or PIN challenge precedes the write.
- [ ] **§3.1 (gate open, no key)**: `read_gatt_char(0xFF01)` returns a valid CSCP packet, and writing it back is accepted (semantic no-op, proves the operation gate, not an attack).
- [ ] **§3.2 (replay, no key)**: a 24-byte packet captured in [[M5_Insecure_Communication]] Variant C, written again later, is accepted and re-applies its thresholds with no key and no account.
- [ ] **§3.2 (no freshness)**: the decrypted plaintext is `bpm_min, bpm_max, spo2_min` + 13 null bytes — confirm there is no nonce, counter, or timestamp field in the format.
- [ ] **§3.3 (no authz)**: the packet your phone produces for its monitor is byte-identical to one produced for another unit of the same model — the format encodes no user or device identity.
- [ ] **§3.4 (chained lethal)**: a forged lethal packet (key per [[M1_Improper_Credential_Usage]] §1.3, written per [[M5_Insecure_Communication]] Variant E) is accepted, and the device-side outcome matches [[IoT7_Insecure_Data_Transfer_and_Storage]] §7.1.

---

## Glossary

| Term | Definition |
|---|---|
| **CSCP** | **CareOtter Secure Config Protocol** (version 1, "CSCP v1"). The vendor's proprietary BLE format for writing clinical alert thresholds (`bpm_min`, `bpm_max`, `spo2_min`) to GATT characteristic `0xFF01`. A 24-byte packet: `[magic 4B = 0xCAFE0DDA][CRC32 4B over the ciphertext][AES-128-ECB(3 threshold bytes + 13 null pad) 16B]`, keyed with the fleet-wide constant `careotter-key-16`. Marketed as "AES-128 military-grade encryption," but for M3 the point is that possession of one of these packets is treated as authentication, and the packet has no freshness, no session, and no requester identity. Expanded in `docs/CareOtter/Architecture_Analysis.md`. |

---

## References

- `labs/careotter/files/opt/medical-sensor/ble_server.py` — `AlertThresholdChrc`: `flags = ["read", "write", "notify"]`, `WriteValue` (discards `options`), `_decrypt_and_unpack` (validates size/magic/CRC/AES only, no freshness). Cited as device-side evidence.
- `vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/CareOtterConfig.java` — `buildThresholdPacket`: the app emits a CSCP packet as the sole authenticator for the config write.
- `vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/BleMonitorClient.java` — `connect` (no `createBond`) / `writeThreshold`: no authenticated session precedes the write.
- `docs/CareOtter/CareOtter_Vulnerability_Resolution.md` §BLE-07 — original mobile M3 lens (no session authentication, no clinical validation), re-cut here around the app design.
- `docs/CareOtter/CareOtter_Test_Suite.md` §BLE-07 — `forge_threshold.py` reproduction and the acceptance matrix.
- `docs/CareOtter/Mobile/CareOtter_App.md` §M3 — BLE pairing not required to write `0xFF01`.
- [[M1_Improper_Credential_Usage]] — the hard-coded CSCP key the token is built from (the credential lens, and the §1.3 forge).
- [[M5_Insecure_Communication]] — the unencrypted channel and the un-bonded peer (the channel lens, Variants A–E supply the runnable BLE steps).
- [[IoT7_Insecure_Data_Transfer_and_Storage]] — device-side data handling, the missing clinical range check, and the deferred `ZeroDivisionError` DoS (the data lens, §7.1).
