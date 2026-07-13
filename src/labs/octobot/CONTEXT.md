# OctoBot - Industrial Robotic Arm Lab (Layer 2)

> **Status: IMPLEMENTED (Stage 04 promoted).** The overlay lives under `files/`. Remaining verification is a real lab load on the Pi (hooks via procd, `opkg`, `uci`, `avrdude`), which cannot be exercised off-device. The architecture, `Sx:angle` serial protocol, gateway endpoints, Modbus register map, and the OWASP IoT catalog live in [`../../docs/OctoBot/OPENWRT_INTEGRATION.md`](../../docs/OctoBot/OPENWRT_INTEGRATION.md) (single source of truth) and are not restated here.

**Stage Purpose**: Deploy a robot-arm ICS cell where the Arduino UNO drives the arm in real time and the OpenWRT Pi is the network gateway, exposing the OWASP IoT Top 10 over a raw serial bus, MQTT, Modbus/TCP, an HMI/REST surface, and an unsigned OTA path.

## Scenario

A 4-DOF robot arm (HU-M16 shield + Arduino UNO) is fronted by a Raspberry Pi gateway that translates network protocols into the serial command bus. The joystick path stays wired for local manual control. The Pi is the exposed attack surface, and the arm provides the physical impact. See `OPENWRT_INTEGRATION.md` Section 1 for the topology.

## Components

| Component | Location (`files/`) | Port | Role |
|---|---|---|---|
| Gateway HMI / REST | `opt/octobot/octobot_gateway.py` | 8090 | `/api/move`, `/api/claw`, `/admin`, `/logs`, `/update`; forwards to the bus and echoes accepted commands to MQTT `cell01/cmd/telemetry` |
| Serial bus | `opt/octobot/serial_bus.py` | 2000 | Raw serial-over-TCP, single tty owner, simulation fallback; parses `ANG:` reports to `/tmp/octobot/angles`; echoes accepted commands to MQTT `cell01/cmd/telemetry` |
| Modbus/TCP server | `opt/octobot/robot_modbus_server.py` | 502 | Holding registers -> `Sx:angle` (stdlib socket, no pymodbus); feedback 40011-40014 from `/tmp/octobot/angles`; auth-failure path leaks password into 40038-40053 |
| MQTT bridge | `opt/octobot/robot_mqtt_bridge.py` | 1883 | Subscribes to `cell01/cmd` and forwards to the bus; auto-injects actuator password |
| Firmware image | `opt/octobot/firmware/robot_arm.hex` | - | Build artifact (see `firmware/README.md`), flashed by hook |
| UCI config | `etc/config/octobot` | - | Per-item `VULNERABLE`/`SECURE` toggle + `use_real_hardware` (default `0`) |
| Cloud API (PC, not in overlay) | `src/cloud_api/octobot/` | 5002 | REST + web UI + Modbus master, single-operator login (SQLite) |

## Inputs

| Layer | Source | Role |
|---|---|---|
| Layer 3 | `../../docs/OctoBot/OPENWRT_INTEGRATION.md` | Architecture, protocol, register map, OWASP catalog |
| Layer 3 | `../../../stages/01_spec/output/octobot-spec.md` | Scope, per-vuln targets, deploy strategy |
| Layer 4 | `arduino_stuff/.../*.ino` | Firmware (Section 4 serial patch is the source of the `.hex`) |
| Layer 4 | `files/opt/octobot/` | Serial bus, gateway, bridges |
| Layer 4 | `files/usr/lib/vulnzoo-hooks/profile-init.d/` | Init hooks (deps, firmware flash, services, firewall) |

## Process

1. **Build firmware (PC) -> ship `.hex`.** Compile the patched sketch and drop the `.hex` into `opt/octobot/firmware/`. See `OPENWRT_INTEGRATION.md` Section 4. With no Arduino attached this step is unnecessary (the bus simulates the arm).
2. **Package the overlay.** Create `octobot.tar.gz` from the `files/` directory. Exclude markdown files so Layer 3 documentation does not leak into the deployed overlay.
   ```sh
   cd src/labs/octobot/files
   tar -czf octobot.tar.gz --exclude="*.md" opt etc usr
   mv octobot.tar.gz ../../vulnzoo/files/usr/lib/vulnzoo-devices/octobot.tar.gz
   ```
3. **Deploy services (start order below).** Hooks run in numeric order on lab load.
4. **Config toggle.** `uci get octobot.main.mode` selects `vulnerable` (default) or `secure`.
5. **Hardware presence.** With `use_real_hardware=0` or no `/dev/ttyACM*`/`/dev/ttyUSB*` present, the serial bus binds a simulated sink so the lab loads and all network paths respond on a bare Pi (platform requirement). The flash hook is skipped in that case. Plugging the arm in after the lab is up is auto-detected by `etc/hotplug.d/tty/20-octobot`, which re-runs preflight and restarts the serial bus.

## Service start order

| Order | Hook | Purpose |
|---|---|---|
| 05 | `05-octobot-preflight.sh` | Workspace setup, detect `/dev/ttyACM*`/`ttyUSB*`, set `use_real_hardware` |
| 15 | `15-octobot-python-deps.sh` | Verify baked deps are present (`serial`, `flask`, `paho.mqtt`), no runtime install |
| 40 | `40-octobot-flash-firmware.sh` | Conditional `avrdude` flash (skipped with no Arduino, version-gated) |
| 50 | `50-octobot-services.sh` | Enable + start `octobot-serialbus`, `-gateway`, `-modbus`, `-mqtt` (+ mosquitto) |
| 70 | `70-octobot-firewall.sh` | Permissive LAN rules (vulnerable mode) |

## Outputs

| Artifact | Path / Port | Description |
|---|---|---|
| HMI / REST | `:8090` | Web HMI + `/api/*` |
| Serial bus | `:2000` | Raw serial gateway + tty owner |
| Modbus/TCP | `:502` | Register map (integration doc Section 5) |
| MQTT | `:1883` | `cell01/cmd` (control), `cell01/cmd/telemetry` (command echo leak) |
| Serial line | `/dev/ttyUSB0` | `Sx:angle` to the Arduino (or simulated) |
| Package | `labs/vulnzoo/files/usr/lib/vulnzoo-devices/octobot.tar.gz` | Lab overlay |

## Verification checklist

- [ ] `octobot.tar.gz` extracts via Device Manager and hooks run in order.
- [ ] On a bare Pi (no arm), the lab loads and all network paths respond in simulation mode (`use_real_hardware=0`).
- [ ] With hardware: firmware flashed; arm homes to init angles on reset.
- [ ] Arm moves from all six paths: shell serial, raw bus telnet (`:2000`), `/api/move`, MQTT publish, Modbus write, cloud REST.
- [ ] Each `IoT:Ix` reproducible per its `Vulns/IoT/` doc.
- [ ] Angle clamps hold under normal commands, defeated only via OTA (`IoT:I4`).

## Dependencies

| Component | Requirement |
|---|---|
| Hardware | Raspberry Pi 3B+, Arduino UNO + HU-M16 shield, 4 servos, external 5 V / 2-3 A servo PSU with common GND |
| OS | OpenWRT v24.10.2 |
| Python | 3.11+ with `pyserial`, `paho-mqtt`, `flask` baked into the base image (the hook only verifies); the Modbus server is stdlib (no pymodbus) |
| Tooling | `avrdude` (base image), `arduino-cli` on the PC for compiling |
| Network | `192.168.2.0/24`, Pi at `192.168.2.1`, direct Ethernet |

## References

- Plan / single source of truth: [`../../docs/OctoBot/OPENWRT_INTEGRATION.md`](../../docs/OctoBot/OPENWRT_INTEGRATION.md)
- Spec: [`../../../stages/01_spec/output/octobot-spec.md`](../../../stages/01_spec/output/octobot-spec.md)
- Hardware: [`arduino_stuff/bot-overview.md`](arduino_stuff/bot-overview.md)
- Vuln index: [`../../docs/OctoBot/Vulns/README.md`](../../docs/OctoBot/Vulns/README.md)
