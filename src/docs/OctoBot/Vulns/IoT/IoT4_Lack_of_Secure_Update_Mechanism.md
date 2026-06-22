---
id: IoT:I4
title: "Lack of Secure Update Mechanism"
category: IoT
status: IN PROGRESS
severity: Critical
owasp: "IoT I4 - Lack of Secure Update Mechanism"
cwe: "CWE-494 (Download of Code Without Integrity Check) / CWE-345 (Insufficient Verification of Data Authenticity)"
source_docs:
  - "src/docs/OctoBot/OPENWRT_INTEGRATION.md §4, §7 (IoT:I4)"
  - "stages/01_spec/output/octobot-spec.md"
  - "stages/02_implement/output/manifest.md"
affected_components:
  - "labs/octobot/files/opt/octobot/octobot_gateway.py"
  - "labs/octobot/files/usr/lib/vulnzoo-hooks/profile-init.d/40-octobot-flash-firmware.sh"
verified_date: ""
---

## Why It Matters

The gateway accepts a firmware image over plain HTTP and flashes it straight to the Arduino with no signature, no version check, and no origin check. An attacker who can POST to the arm replaces the controller firmware, which is the deepest possible compromise: the malicious build can ignore the servo angle clamps that are the device's last safety control, driving servos past their mechanical limits.

## Root Cause

```python
# labs/octobot/files/opt/octobot/octobot_gateway.py
@app.route('/update', methods=['POST'])     # [IoT:I4] unsigned OTA, flashed over plain HTTP
def update():
    request.files['firmware'].save(path)
    ...
    cmd = (f'avrdude -c arduino -p atmega328p -P {SERIAL_DEV} '
           f'-b 115200 -U flash:w:{path}:i')   # [IoT:I4] flashes attacker-supplied firmware
```

Whatever `.hex` is uploaded is flashed verbatim. There is no signature verification, no firmware version gate, and the transport is cleartext HTTP, so the image can also be tampered with in transit.

## Steps to Reproduce

```bash
# 1. Build (or obtain) a modified sketch with the angle clamps removed, compile to evil.hex.
# 2. Push it over HTTP - no auth, no signature.
curl -s -F 'firmware=@evil.hex' http://192.168.2.1:8090/update
# -> {"flashed": true, "log": "...avrdude: ... bytes of flash verified"}

# 3. The arm now runs attacker firmware; servo limits no longer enforced.
```

(In simulation mode, with no Arduino attached, `/update` returns `{"flashed": false, "note": "no Arduino attached"}`.)

## Expected Result

The uploaded image is accepted and flashed, and the arm subsequently executes attacker-controlled firmware that no longer honors the `servo_min_angle`/`servo_max_angle` clamps.

## How It Should Be

Sign firmware and verify the signature on-device before flashing, reject downgrades with a monotonic version counter, and serve updates over TLS from an authenticated endpoint. The flash path must refuse any image whose signature does not chain to a trusted vendor key.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Integrity | Verify a vendor signature before flashing | Reject unsigned/tampered images |
| Anti-rollback | Monotonic firmware version gate | Block downgrade attacks |
| Transport | TLS + authenticated `/update` | Stop MITM and anonymous upload |

## Verification Checklist

- [ ] `POST /update` with an unsigned `.hex` flashes successfully (with hardware)
- [ ] No signature or version check is performed
- [ ] The flashed image can remove the servo angle clamps
