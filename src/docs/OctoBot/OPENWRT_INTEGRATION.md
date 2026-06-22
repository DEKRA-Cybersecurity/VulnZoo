# OctoBot - OpenWRT Integration & MWP Build Plan

This is the build plan for the **OctoBot** industrial lab: turn the joystick-controlled HU-M16 robot arm into a networked ICS/IoT pentest target where a **Raspberry Pi 3B+ running OpenWRT** sits as the field gateway between the **Arduino UNO** (which keeps driving the arm in real time) and the **cloud API / Android app**. It is written to kick off the MWP stages pipeline (Section 8): the device hardware analysis is in [`../../labs/octobot/arduino_stuff/bot-overview.md`](../../labs/octobot/arduino_stuff/bot-overview.md), the firmware is the Youfang v1.71 sketch beside it, and the per-vulnerability docs land under `Vulns/IoT/` once Stage 03 runs.

> **Isolation is mandatory.** Everything below is deliberately vulnerable. Never connect this lab to the Internet or a production network. Run it on a dedicated, air-gapped LAN with the Pi as the only router of a physically separate segment. Snapshot the SD card before you start.

---

## 1. Architecture Decision

The central decision is **not** to insert the Pi into the real-time control path. The Arduino stays the controller that does the PWM (its role as the "PLC / microcontroller"), and the Pi sits on top as the network gateway / HMI. The whole OWASP IoT attack surface then lives on the Pi, which is the part exposed to the network, while the arm supplies the physical impact that makes each finding tangible: an attacker who exploits a web flaw ends up moving real hardware.

- **Arduino UNO** = real-time controller. Reads joysticks locally (manual plant fallback) and accepts remote `Sx:angle` commands over USB serial. Keeps the PWM loop.
- **Raspberry Pi 3B+ (OpenWRT)** = OT field gateway / HMI. Translates network protocols (HTTP/REST, MQTT, Modbus/TCP) into the serial command protocol. This is where the vulnerabilities are seeded.
- **PC / Docker** = IT / operator plane. Hosts the cloud REST API, web UI, mobile backend, and the Modbus/TCP master that drives the Pi.
- **Android app** = talks only to the cloud REST API, never directly to the Pi or Modbus.

```
 [Joysticks/HU-M16] --> [Arduino UNO] --PWM--> [4 servos]   (LOCAL manual control)
                              ^
                              | USB serial 115200, "Sx:angle\n" frames
                              v
 [Android app] --HTTP/REST--> [PC / Docker cloud]  --Modbus/TCP :502-->  [Raspberry Pi - OpenWRT]
                              (web UI, REST, mobile API,                  (gateway: serial bus / MQTT /
                               Modbus/TCP master)                         Modbus server / HMI / OTA)
                                                                          + router on the flat
                                                                          industrial LAN (Ethernet)
```

Control data path end to end: Mobile/Web -> Cloud REST -> Modbus/TCP -> Pi gateway -> USB serial `Sx:angle` -> Arduino -> PWM -> servos. The joystick path stays wired in parallel so the arm is always usable locally.

---

## 2. Hardware & Serial Link

1. Power the Pi from a 5 V / 2.5 A+ supply. Connect the Arduino UNO to the Pi with a USB-A-to-USB-B cable.
2. Leave the HU-M16 module, the four servos, and the two joysticks wired exactly as they are today.

On OpenWRT the Arduino enumerates as a serial device depending on the USB-serial chip:

| UNO chip | Device node | OpenWRT kmod |
|---|---|---|
| ATmega16U2 (genuine UNO) | `/dev/ttyACM0` | `kmod-usb-acm` |
| CH340/CH341 (clone) | `/dev/ttyUSB0` | `kmod-usb-serial-ch341` |
| FTDI FT232 (clone) | `/dev/ttyUSB0` | `kmod-usb-serial-ftdi` |

This matches the Windows drivers shipped in the repo (`CH341SER` / `FTDI232`). On the Pi you install the equivalent kmod instead of the `.exe`.

> **Power gotcha (the classic mistake).** Do **not** power the four servos from the Arduino 5 V / USB rail. Four servos moving at once draw several amps in peaks and will brown out and reset the board (or the Pi). Feed the HU-M16 servo power input from an **external 5 V / 2-3 A** supply, and keep a **common GND** between that supply, the Arduino, and the Pi. The Arduino itself is powered over USB from the Pi, and only the servos use the external supply.

**GPIO-UART alternative (optional).** Instead of USB you can use the Pi GPIO serial: Pi TXD (GPIO14) -> Arduino RX (D0), Pi RXD (GPIO15) -> Arduino TX (D1), common GND. The Pi is 3.3 V and the Arduino is 5 V, so you need a level shifter (or a resistor divider on the Arduino-TX -> Pi-RX line), never feed 5 V straight into the GPIO. The port is then `/dev/ttyAMA0` / `/dev/serial0` and you must free the kernel serial console. USB is simpler and is the recommended starting point.

**Persistent device name (optional).** Create `/etc/udev/rules.d/99-robot-arm.rules` so the Arduino always gets the same symlink:

```udev
SUBSYSTEM=="tty", ATTRS{idVendor}=="1a86", ATTRS{idProduct}=="7523", SYMLINK+="robotarm"
SUBSYSTEM=="tty", ATTRS{idVendor}=="0403", ATTRS{idProduct}=="6001", SYMLINK+="robotarm"
SUBSYSTEM=="tty", ATTRS{idVendor}=="2341", ATTRS{idProduct}=="0043", SYMLINK+="robotarm"
```

---

## 3. OpenWRT Preparation

The lab runs **air-gapped**, so every package is **baked into the base image at build time** (`make menuconfig`), never installed at runtime. The hooks only verify presence (`15-octobot-python-deps.sh`), they do not run `opkg`. Select in the image build:

```text
# Arduino tty + flashing
kmod-usb-acm  kmod-usb-serial-ch341  kmod-usb-serial-ftdi  avrdude
# Python + network services (all in the OpenWRT feed)
python3-light  python3-pyserial  python3-flask  python3-paho-mqtt
mosquitto-nossl  mosquitto-client-nossl
```

`python3-flask` pulls its stack (`jinja2`, `werkzeug`, `itsdangerous`, `markupsafe`, `click`). The Modbus server is stdlib, so **no `pymodbus`** is required (it is not in the OpenWRT feed anyway). `kmod-usb-serial-ch341` / `-ftdi` are only needed for CH340/FTDI clone Arduinos, a genuine UNO uses `kmod-usb-acm`.

Verify the device node and the serial link:

```sh
dmesg | tail -n 30                          # look for cdc_acm / ch341 + the ttyXXX
ls -l /dev/ttyACM* /dev/ttyUSB* 2>/dev/null
stty -F /dev/ttyACM0 115200 raw
printf 'S0:90\n' > /dev/ttyACM0             # base servo to 90 degrees
```

**Lab network.** The Pi is the gateway on the platform-standard direct-Ethernet LAN: Pi at `192.168.2.1` (fixed), the operator PC / attacker laptop on `192.168.2.0/24`, matching `PROJECT_OVERVIEW.md` and the other labs. The segment is deliberately **flat and unsegmented** (no VLANs), so the attacker host and the OT serial-to-Ethernet gateway share one broadcast domain, which is what makes the segmentation-bypass exercise (Section 9) meaningful. The OpenWRT firewall is left permissive on the LAN side for the offensive exercises and tightened only in the hardening pass. A Wi-Fi AP on a separate subnet (for example `192.168.50.0/24`) is an optional variant for a wireless cell.

---

## 4. Firmware: Add Remote Serial Control

The shipped Youfang v1.71 sketch only reads joysticks. Its `loop()` calls `move_by_joystick_contrl()` and `learning_actions()`, and the serial port is print-only at 115200. To drive the arm from the Pi, add a newline-terminated command parser and keep the joystick loop intact as a local fallback. Servo names, pins, and per-servo angle clamps are defined in the sketch (`servo_min_angle[]` / `servo_max_angle[]`: base 65-135, left 80-140, right 70-120, claw 5-30).

| Frame | Effect |
|---|---|
| `S0:90` | Set servo 0 (base) to 90 degrees, clamped to that servo's range |
| `S1:45` / `S2:120` / `S3:5` | Set servo 1 (left) / 2 (right) / 3 (claw) |
| `DEMO` | Run the built-in `demo_actions` sequence |
| `LEARN` / `RECORD` / `PLAY` / `STOP` | Teach-and-repeat: enter learning, save pose, replay, halt |
| `SPD:n` | Set playback speed 1..`MAXSPEED` |

Minimal parser to add (uses the sketch's real symbols):

```cpp
void handle_serial() {
  static String line;
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n')      { process_command(line); line = ""; }
    else if (c != '\r') { line += c; }
  }
}

void process_command(String &cmd) {
  cmd.trim();
  if (cmd.startsWith("S") && cmd.indexOf(':') == 2) {
    int servo = cmd.charAt(1) - '0';
    int angle = cmd.substring(3).toInt();
    if (servo >= 0 && servo < SERVOS &&
        angle >= servo_min_angle[servo] && angle <= servo_max_angle[servo]) {
      arm_servos[servo].write(angle);
      Serial.print("OK S"); Serial.print(servo); Serial.print(":"); Serial.println(angle);
    } else {
      Serial.println("ERR RANGE");
    }
  } else if (cmd == "DEMO")  { play_demo_mode = true;  play_demo(); play_demo_mode = false; }
  else if (cmd == "LEARN")   { learning_mode = true;   learn_action_count = 0; }
  else if (cmd == "PLAY")    { repeat_mode = true;     play_learned_actions(); }
  else if (cmd == "STOP")    { learning_mode = repeat_mode = play_demo_mode = false; }
  else if (cmd.startsWith("SPD:")) { demo_speed = constrain(cmd.substring(4).toInt(), 1, MAXSPEED); }
  else { Serial.println("ERR UNKNOWN"); }
}

void loop() {
  handle_serial();
  move_by_joystick_contrl();
  learning_actions();
}
```

> Two implementation notes for Stage 02. (1) `play_demo()` and `play_learned_actions()` in v1.71 are blocking `while(1)` loops that only exit on a joystick button, so a remote `STOP` cannot interrupt them as written. Make them loop-serviced (flag-driven, one step per `loop()` pass) so the serial `STOP` works. (2) The unbounded Arduino `String` in `process_command` (no length cap) is the firmware-side memory-exhaustion surface for the physical-hardening item (`IoT:I10`). Leave it as a study target, do not harden it.

**Build and ship the firmware (compile on the PC, flash on the Pi).** OpenWRT carries no AVR toolchain, so compile the sketch to a `.hex` on your PC and ship the prebuilt binary inside the lab overlay. At deploy the overlay extracts onto the Pi rootfs, and the Pi flashes the Arduino from the bundled `.hex`.

1. Compile the sketch on the PC with `arduino-cli` (or in the Arduino IDE: Sketch > Export Compiled Binary):

```sh
arduino-cli core install arduino:avr
arduino-cli compile --fqbn arduino:avr:uno \
  --output-dir /tmp/octobot-fw \
  "src/labs/octobot/arduino_stuff/Youfang Smart-ARM-code-v1.71-joystick"
# produces /tmp/octobot-fw/Youfang Smart-ARM-code-v1.71-joystick.ino.hex
```

2. Drop the `.hex` into the overlay so it ships with the lab package. The `opt/` tree is already part of the `octobot.tar.gz` packaging (Section 8), so the file lands at `/opt/octobot/firmware/robot_arm.hex` on the Pi when the lab is launched:

```sh
mkdir -p src/labs/octobot/files/opt/octobot/firmware
cp /tmp/octobot-fw/*.ino.hex \
   src/labs/octobot/files/opt/octobot/firmware/robot_arm.hex
```

3. Flash the Arduino on the Pi from the bundled `.hex` (`-c arduino` uploads through the UNO bootloader, no external programmer). Use `/dev/ttyUSB0` for a CH340/FTDI clone:

```sh
# avrdude ships in the VulnZoo base image, no opkg install needed
avrdude -c arduino -p atmega328p -P /dev/ttyACM0 -b 115200 \
  -U flash:w:/opt/octobot/firmware/robot_arm.hex:i
```

A deploy hook (`##-flash-firmware.sh`) can run step 3 automatically when the lab transforms, or you can leave it manual. This is the same `.hex` the `/update` OTA endpoint flashes (Section 5, `IoT:I4`), so the shipped binary doubles as the baseline that the firmware-tampering scenario (Section 9) replaces with an unclamped build.

---

## 5. Pi Gateway: Network to Serial (deliberately vulnerable)

The gateway is the OWASP IoT surface. Each network entry point maps to an OWASP IoT item and is gated behind a **per-item config toggle** (a `VULNERABLE` / `SECURE` flag in UCI `/etc/config/octobot`), so the lab can enable one flaw at a time and teach the before/after of its remediation. This matches the platform's `--vulnerable` / `--secure` convention used by the other labs.

The control paths and their tags (implemented under `labs/octobot/files/opt/octobot/`):

| Path | Listener | OWASP item | Flaw when VULNERABLE |
|---|---|---|---|
| Direct shell serial | `stty` + `printf > /dev/ttyACM0` | - | Operator convenience / quick check |
| Serial bus (`serial_bus.py`) | `:2000` | `IoT:I2` | Unauthenticated, cleartext serial-over-IP gateway, single tty owner |
| HMI / REST (Flask) | `:8090` | `IoT:I3` | `/api/move`, `/api/claw` no auth; IDOR by servo index; SSTI/XSS in `/admin` |
| MQTT (mosquitto-nossl) | `:1883` topic `cell01/cmd` | `IoT:I2` `IoT:I7` | No username/password, no TLS |
| Modbus/TCP | `:502` | `IoT:I2` | No authentication by protocol design |
| OTA update | `POST /update` | `IoT:I4` | Unsigned `.hex` flashed via `avrdude` over plain HTTP |
| Operator log | `GET /logs` | `IoT:I6` | Cleartext operator history, no auth |

Gateway endpoint contract (REST/HMI side):

| Endpoint | Method | Action |
|---|---|---|
| `/api/move?servo=<n>&angle=<a>` | GET | Send `S<n>:<a>` to the serial bus |
| `/api/claw?state=OPEN\|CLOSE` | GET | Open/close the gripper |
| `/admin?msg=<text>` | GET | Render the HMI panel (intentional SSTI/XSS sink) |
| `/logs` | GET | Dump the operator action log |
| `/update` | POST | Accept and flash a firmware `.hex` |

Modbus/TCP holding-register map, the protocol contract the cloud master writes (`4xxxx` numbers map to protocol offsets `0..N-1`):

| Register | Address | Access | Description |
|---|---|---|---|
| Base angle | 40001 | R/W | Servo 0, 65-135 |
| Left angle | 40002 | R/W | Servo 1, 80-140 |
| Right angle | 40003 | R/W | Servo 2, 70-120 |
| Claw angle | 40004 | R/W | Servo 3, 5-30 |
| Command | 40005 | W | 1=RECORD, 2=PLAY, 3=STOP, 4=DEMO |
| Speed | 40006 | R/W | Playback speed 1-10 |
| Status | 40007 | R | 0=idle, 1=moving, 2=learning, 3=playing |
| Base/Left/Right/Claw current | 40011-40014 | R | Live servo angle feedback |

The gateway runs as a procd service under `/etc/init.d/octobot-gateway`. The Modbus server clamps each register write to the servo range and forwards `Sx:angle` to the serial bus.

Feedback path: the Arduino reports its live servo angles every 250 ms as `ANG:base,left,right,claw`. `serial_bus.py` parses those into `/tmp/octobot/angles`, the Modbus server loads them into registers 40011-40014, and the cloud `/api/state` returns them. With no arm attached the bus mirrors each commanded `Sx:angle` into the same file, so the feedback still tracks in simulation.

---

## 6. Cloud API & Mobile (IT plane)

The PC runs a Dockerized cloud that owns the operator-facing plane and is the Modbus/TCP master to the Pi. It exposes a login-gated REST API and web UI (a single operator account stored in SQLite, signed-session auth), and is the only thing the Android app talks to. The container, `app.py`, `docker-compose.yml`, and `static/` are produced in `stages/02_implement/output/code/` and promoted to `src/cloud_api/octobot/` (see promotion map).

REST endpoints the web UI and the app consume:

| Endpoint | Method | Body | Action |
|---|---|---|---|
| `/api/state` | GET | - | Read servo angles + status (Modbus read) |
| `/api/servo/<n>` | POST | `{"angle": 90}` | Move servo n (Modbus write) |
| `/api/command/<name>` | POST | - | `record` / `play` / `stop` / `demo` |

The Android client uses plain HTTP/REST to the cloud (Retrofit or `HttpURLConnection`), and never speaks Modbus. In the hardened pass it gets TLS pinning and a JWT, which is itself the before/after for the transport and auth items.

> `cloud_api/octobot/` does not exist yet. Creating it is Stage 02 work, and `octobot` must first be added to the device tables in `_config/promotion-map.md` and the routing table in `src/AGENTS.md`.

---

## 7. OWASP IoT Top 10 -> OctoBot Implementation (vuln catalog)

This table is the catalog that drives the lab. Stage 03 writes one doc per row under `docs/OctoBot/Vulns/IoT/`, each paired with its CWE and a `VULNERABLE`/`SECURE` toggle.

| ID | OWASP IoT risk | CWE | Implementation in this lab | How to test on your own lab |
|---|---|---|---|---|
| `IoT:I1` | Weak / guessable / hardcoded passwords | CWE-798 / CWE-1392 | `admin/admin` HMI login, hardcoded `API_KEY` in the gateway, weak `root` on SSH/LuCI | Trivial login; grep the script/binary; key reuse |
| `IoT:I2` | Insecure network services | CWE-306 / CWE-319 | Telnet/SSH open, raw TCP `:2000`, MQTT no-auth, Modbus/TCP no-auth | `nmap -sV` the Pi; connect to each port with no credentials |
| `IoT:I3` | Insecure ecosystem interfaces | CWE-639 / CWE-1336 / CWE-79 / CWE-306 | `/api/move` with no auth, IDOR by `servo`, SSTI/XSS in `/admin` | `curl` with no token; `{{7*7}}` in `msg`; move the arm from a browser |
| `IoT:I4` | Lack of secure update mechanism | CWE-494 / CWE-345 | `/update` accepts an unsigned `.hex` over HTTP and flashes with `avrdude` | Upload a modified firmware and watch it run on the arm |
| `IoT:I5` | Use of insecure / outdated components | CWE-1104 / CWE-1035 | Pinned old Dropbear / uHTTPd / Flask / jQuery, stale OpenWRT | `nmap` / CVE lookup by detected version |
| `IoT:I6` | Insufficient privacy protection | CWE-359 / CWE-200 | `/logs` exposes who operated, when, and which movements, in cleartext | Download the log with no authentication |
| `IoT:I7` | Insecure data transfer and storage | CWE-319 / CWE-312 | All HTTP/MQTT without TLS; credentials in cleartext config; cleartext serial bus | Capture with Wireshark / `tcpdump` and read commands and keys |
| `IoT:I8` | Lack of device management | CWE-778 / CWE-770 | No access revocation, no audit, no rate-limit or monitoring | Flood `/api/move`; observe no blocking or alerting |
| `IoT:I9` | Insecure default settings | CWE-1188 / CWE-16 | Default AP SSID/key, default LuCI, permissive firewall, gateway binds `0.0.0.0` plain HTTP | Access with factory credentials; join the default AP |
| `IoT:I10` | Lack of physical hardening | CWE-1263 / CWE-1191 | Exposed serial/UART header, USB-reflashable UNO, removable SD with cleartext secrets | Reflash with `avrdude` over USB; mount the SD elsewhere and read secrets |

---

## 8. MWP Stages Plan

Build this through the pipeline (`stages/01_spec` -> `02_implement` -> `03_document` -> `04_integrate`), promoting into `src/` only through `_config/promotion-map.md`.

**Pre-requisite (register the new device).** OctoBot is not yet known to the workspace. Before Stage 02 promotion, add `octobot` to the device tables in `_config/promotion-map.md` (lab overlay `src/labs/octobot/`, cloud API `src/cloud_api/octobot/`, docs `src/docs/OctoBot/`) and to the routing tables in `src/AGENTS.md`. Fill the currently-empty `docs/OctoBot/OctoBot.md` device landing doc.

| Stage | Produces | Promotes to (`src/`) |
|---|---|---|
| **01_spec** | The OctoBot spec: architecture, `Sx:angle` protocol, gateway endpoints, Modbus register map, the `IoT:I1..I10` item list with per-item config toggle, and the flat-LAN network model. First concrete artifact: a draft `labs/octobot/CONTEXT.md` (Layer 2 lab contract). | (spec only; no code) |
| **02_implement** | Firmware serial patch (Section 4) compiled to a prebuilt `.hex` under `opt/octobot/firmware/`; the `labs/octobot/files/` overlay (gateway procd service `octobot-gateway`, init.d, hooks `##-*.sh` including `##-flash-firmware.sh`, UCI `/etc/config/octobot` with the `VULNERABLE` toggle, serial bus / mosquitto / Modbus server); `cloud_api/octobot/` Docker stack (REST + web UI + Modbus master); the Android client. `manifest.md` records every target path. | `src/labs/octobot/files/...`, `src/cloud_api/octobot/...`, `src/vulnzoo_apps/...` |
| **03_document** | One `Vulns/IoT/IoT*_*.md` per row of the Section 7 table, plus the `Vulns/README.md` index (plain-text `DONE` badges, CWE per item). | `src/docs/OctoBot/Vulns/IoT/...`, `src/docs/OctoBot/Vulns/README.md` |
| **04_integrate** | Promote per the map: repackage `octobot.tar.gz` and drop it into `labs/vulnzoo/files/usr/lib/vulnzoo-devices/`, promote cloud API + app + docs, verify the lab loads, write `integration-log.md`, clean the stage `output/` dirs. | (promotion + log) |

Lab repackaging on promotion (per the promotion map):

```sh
cd src/labs/octobot/files
tar -cvzf octobot.tar.gz opt etc usr
mv octobot.tar.gz ../../vulnzoo/files/usr/lib/vulnzoo-devices/octobot.tar.gz
```

---

## 9. Attack Scenarios (lab exercises)

Each scenario uses the arm as a safe, visible victim process and maps to one OWASP IoT item.

- **Unauthenticated remote access (`IoT:I2`).** `telnet 192.168.2.1 2000` then type `S3:5` to close the claw, or `curl` the no-auth `/api/move`.
- **Command/template injection (`IoT:I3`).** SSTI `{{7*7}}` in `/admin?msg=`, or shell metacharacters if a CGI shells out to the serial device unsanitized.
- **Replay (`IoT:I7`).** Capture a legitimate `Sx:angle` sequence with `tcpdump`, replay it later with no knowledge of the protocol.
- **Actuator denial of service (`IoT:I8`).** Rapid-fire `while true; do printf "S0:$((RANDOM%180))\n" > /dev/ttyACM0; done`, or out-of-range values, to make the servos jitter or stall.
- **Firmware / OTA tampering (`IoT:I4` / `IoT:I10`).** Upload a malicious `.hex` via `/update`, or reflash the USB-exposed UNO directly, to defeat the firmware angle clamps.
- **Segmentation bypass (`IoT:I9`).** From the flat LAN, reach the OT serial-to-Ethernet gateway with no jump host, the consequence of the deliberately unsegmented network in Section 3.
- **Protocol fuzzing (`IoT:I10`).** Feed `S9:999`, very long lines, or binary garbage at 115200 into the serial parser and watch for crashes or unexpected motion.

---

## 10. Hardening / Remediation (the "after")

The per-item toggle makes each fix teachable as a before/after. The hardening pass is the most valuable half of the lab.

| Layer | Control |
|---|---|
| Network | OT devices in their own OpenWRT firewall zone; inbound restricted to a jump host; VLANs |
| Transport | TLS on the REST API; TLS on the serial bus; MQTT over TLS |
| Authentication | JWT / mTLS on REST; MQTT credentials; HTTP auth on the CGI/HMI |
| Authorization | Allow-list valid `Sx:angle` commands; reject everything else |
| Rate limiting | Application-level throttling on serial commands |
| Updates | Signed firmware; verify origin before `avrdude` flashes |
| Logging | Every serial command to syslog / remote SIEM |
| Safety | Hardware E-stop cutting servo power; firmware min/max clamps |

---

## 11. Lab Isolation Checklist

- [ ] Dedicated / air-gapped LAN, and the Pi never touches the Internet or the home/work network.
- [ ] SD card image snapshotted for restore between sessions.
- [ ] Servos on an external supply with **common GND**, never powered from USB.
- [ ] Arm in a clear workspace (exploits move it for real), with a power cutoff within reach.
- [ ] Record which toggle is active each session so no service is left open by mistake.

---

## Related Documents

- [`bot-overview.md`](../../labs/octobot/arduino_stuff/bot-overview.md) - HU-M16 firmware, drivers, and controller analysis (Layer 3 hardware reference).
- [`Build_Guide.md`](./Build_Guide.md) - merged into this file, kept as a pointer.
- `labs/octobot/CONTEXT.md` - the Layer 2 lab contract (first Stage 01 output, not created yet).
