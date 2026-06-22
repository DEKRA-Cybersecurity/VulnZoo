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

The robot arm is reachable over three unauthenticated network services on the flat lab LAN: a raw serial-over-TCP bus (`:2000`), Modbus/TCP (`:502`), and MQTT (`:1883`). Any host that can route to the Pi can drive the actuator with no credential. This is the canonical ICS exposure: a serial-to-Ethernet gateway and an industrial protocol that ship without authentication, turning network reachability into physical control.

## Root Cause

The serial bus binds all interfaces and forwards any line it receives straight to the arm, with no authentication:

```python
# labs/octobot/files/opt/octobot/serial_bus.py
srv.bind(('0.0.0.0', BUS_PORT))                # [IoT:I9] binds all interfaces
...
for line in conn.makefile('r'):                # [IoT:I2] no auth, raw forward
    forward(line, client)
```

Modbus/TCP has no authentication by protocol design, and the server forwards register writes to the bus:

```python
# labs/octobot/files/opt/octobot/robot_modbus_server.py (stdlib socket, no pymodbus)
srv.bind(('0.0.0.0', MODBUS_PORT))               # [IoT:I2] no auth by design
# write to register 0-3 -> clamp -> forward "Sx:angle" to the serial bus
```

The MQTT bridge subscribes to a broker that runs with `mosquitto-nossl` and no credentials, then forwards every payload to the bus.

## Steps to Reproduce

```bash
# Service discovery
nmap -sV -p 2000,502,1883 192.168.2.1

# A. Raw serial bus - close the claw with no auth
printf 'S3:0\n' | nc 192.168.2.1 2000

# B. Modbus/TCP - write base servo angle (register 40001 -> offset 0)
python3 -c 'from pymodbus.client import ModbusTcpClient as C; c=C("192.168.2.1",port=502); c.connect(); c.write_register(0,10); c.close()'

# C. MQTT - publish a command, no username/password
mosquitto_pub -h 192.168.2.1 -t cell01/cmd -m 'S0:0'
```

## Expected Result

Each path moves the arm (or, in simulation mode, updates the bus state and appends to the operator log) with no authentication exchange. `nmap` fingerprints all three open ports.

## How It Should Be

Put the OT services behind authentication and transport security: client certificates or a token on the bus and MQTT, Modbus wrapped in TLS (stunnel) or replaced with an authenticated channel, and bind to the management interface only rather than `0.0.0.0`.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Network | Bind to LAN-mgmt interface, firewall to a jump host | Remove blanket reachability |
| Transport | TLS on the bus, MQTT over TLS, Modbus via stunnel | End cleartext control |
| Auth | Token / client cert on every northbound service | No anonymous actuation |

## Verification Checklist

- [ ] `nmap -sV` shows `:2000`, `:502`, `:1883` open
- [ ] `nc :2000` line moves the arm with no auth
- [ ] Modbus register write moves the arm with no auth
- [ ] `mosquitto_pub` to `cell01/cmd` moves the arm with no credentials
