# BulbBee - Lab Setup and Run Guide

> Student walkthrough to build and run the bulbbee smart-light lab: the Raspberry Pi, a WS2812 RGB LED ring, SPI enablement, loading the lab, and driving the light over the control API. By the end, a command over the network changes the ring's color and scene. The lab also runs headless in simulation with no ring attached.

## What you are building

A budget WiFi smart light. A Raspberry Pi running OpenWRT hosts a lighting service that drives an addressable WS2812 RGB ring. The controller is an Android app that talks to the device over BLE (a GATT server on the Pi, `ble_light.py`, modeled on CareOtter). Control reaches the ring over three planes, all relayed to the single-owner lighting daemon: BLE GATT (the app channel), an outbound MQTT tunnel to a cloud emulator (`cloud_tunnel.py`, BULB-A3), and a Tuya-style AES-CCM LAN port on `:6668` (`local_tcp.py`, BULB-A4). A small HTTP control API on `:8082` is the secondary LAN control and diagnostics surface. This is the shape of a consumer smart light, the textbook CRA default-category product, and the intentional weaknesses a CRA assessor looks for are the shipped default degradations of the secure baselines (restored by the `secure` toggle, see the secure-mode matrix in [`README.md`](README.md)).

## Role mapping (real product -> this lab)

| Real product part | What plays it here |
|---|---|
| Smart-light MCU + LED driver | `lighting_service.py` + `ws2812.py` on the Pi |
| Addressable RGB LEDs | a WS2812 ring wired to the Pi (or the simulation frame buffer) |
| BLE control server (app channel) | `ble_light.py` on the Pi, BlueZ/D-Bus (BULB-A1), robust LE SC + Passkey pairing under `secure` (BULB-A2) |
| Vendor mobile app | Android controller over BLE (`curl` on `:8082` and `bulbctl` are the local diagnostic stand-ins) |
| Vendor cloud | `mosquitto` broker + REST API in `cloud_api/bulbbee/`, the device opens an outbound MQTT tunnel to it (`cloud_tunnel.py`, BULB-A3) |
| LAN/TCP local control | `local_tcp.py` on the Pi, AES-CCM framed commands on `:6668` (BULB-A4) |
| Per-device secrets (simulated flash) | `secret_store.py` layout + owner binding, root secret `/opt/bulbbee/.session_secret` (BULB-A5) |

## Bill of materials

- Raspberry Pi 3B+/4 flashed with the VulnZoo image (OpenWRT).
- One WS2812 / WS2812B RGB LED ring (the lab defaults to `led_count=16`, any count works, set it in `config.json`).
- 3 jumper wires (DIN, 5V, GND).
- Optional but recommended for a clean signal: a 3.3V-to-5V logic level shifter (for example a 74AHCT125) on the DIN line, and a 300-500 ohm series resistor on DIN.
- Optional: an external 5V supply for the ring if you run many LEDs at high brightness.
- Ethernet cable (direct Pi to PC).
- No extra radio needed: the Pi 3B+ onboard Bluetooth carries the BLE app control channel (BULB-A1). A BLE-capable phone or a host running a BLE central (bleak / gatttool) plays the controller.

## Part 1 - Wire the WS2812 ring

The ring has three connections: DIN (data in), 5V, and GND.

| Ring pin | Pi pin (physical) | Signal |
|---|---|---|
| DIN | pin 19 (GPIO10, SPI0 MOSI) | data |
| 5V | pin 2 or pin 4 (5V) | power |
| GND | pin 6 (GND) | ground, common with the Pi |

Two hardware realities to respect, because a WS2812 on paper and on the bench differ:

- **Logic-level margin.** The Pi's GPIO drives 3.3V, while a WS2812 powered at 5V expects a DIN high of about 0.7 x VDD, roughly 3.5V. A short lead to a small ring often works directly, but it is marginally out of spec. For a reliable signal put a level shifter on DIN (3.3V in, 5V out), or power the ring at about 4.5V (which lowers its input threshold), and keep a 300-500 ohm series resistor on DIN to protect the first LED.
- **Power budget.** Each WS2812 can draw up to about 60 mA at full white. A 16-LED ring at moderate brightness is fine off the Pi's 5V rail, but many LEDs at high brightness will exceed what the Pi can source, use an external 5V supply for the ring and tie its ground to the Pi's ground. The `brightness` cap in `config.json` also bounds the draw.

## Part 2 - Enable SPI on the Pi

The WS2812 is driven over SPI0, so `/dev/spidev0.0` must exist. If it is not already enabled, add the SPI parameter to the boot config and reboot once.

```
dtparam=spi=on
```

Add that line to `/boot/config.txt` (the RPi firmware boot config on the OpenWRT image), then reboot. After the reboot, confirm the device node:

```sh
ls -l /dev/spidev0.0
```

If `/dev/spidev0.0` is absent, the lighting service still starts and runs in simulation, only the physical ring stays dark. The `99-bulbbee-spi.sh` profile-init hook automates this step, the way the canary lab writes its CAN overlays: on the first load for the bulbbee device it writes `dtparam=spi=on` to `/boot/config.txt` and reboots once so the firmware exposes `/dev/spidev*`. The hook is idempotent and reboots only the run that actually adds the line (and only after verifying the write landed), so a read-only boot partition or a missing SPI kmod cannot turn it into a boot loop. Set `bulbbee.main.spi_reboot=0` to have the hook write the config but leave the reboot to you, or do the manual edit above if you prefer to enable SPI by hand. Enabling SPI only creates the device nodes. The shipped `config.json` already sets `use_real_hardware=true`, so once `/dev/spidev0.0` exists the driver uses the ring on the next boot (Part 5).

## Part 3 - Load the bulbbee lab

Open the Device Manager at `http://192.168.2.1:8080`, select bulbbee, and load it (or on the Pi run the `*-bulbbee-*` hook). The `45-bulbbee-light.sh` hook verifies the service files, enables and starts the `bulbbee-light` procd service, and probes the HTTP endpoint. Watch progress:

```sh
ssh root@192.168.2.1
logread | grep bulbbee
grep bulbbee /root/vulnzoo.log
pgrep -f lighting_service.py
```

## Part 4 - Verify

```sh
curl http://192.168.2.1:8082/health                                   # {"status":"ok"}
curl http://192.168.2.1:8082/state                                    # includes "simulated": true|false and "frame"
curl -X POST http://192.168.2.1:8082/scene -d '{"scene":"rainbow"}'    # 200, ring animates or the sim frame advances
curl -X POST http://192.168.2.1:8082/set   -d '{"brightness":200,"color":[10,20,30]}'
curl -X POST http://192.168.2.1:8082/scene -d '{"scene":"solid"}'      # solid at the set color
```

Or drive it with the on-device CLI `bulbctl`, a thin client of the same `:8082` surface (it never opens the SPI device, so the lighting service stays the single writer to the ring):

```sh
bulbctl color 0 255 0      # solid green
bulbctl bright 40          # brightness 0-255
bulbctl scene rainbow      # solid | rainbow | breathe | off
bulbctl off ; bulbctl on
bulbctl state              # current power/brightness/color/scene
```

On real hardware the ring visibly follows the commands. In simulation, `/state` reflects the change and `cat /tmp/bulbbee/state.json` shows the frame buffer. The service reloads its last state after a restart:

```sh
/etc/init.d/bulbbee-light restart
curl http://192.168.2.1:8082/state          # power/brightness/color/scene as before the restart
```

## Part 5 - Hardware vs simulation

| Mode | When | Behavior |
|---|---|---|
| Hardware | `use_real_hardware=true` (the shipped default) and `/dev/spidev0.0` present | drives the WS2812 ring over SPI |
| Simulation | `/dev/spidev0.0` absent (SPI off or no ring), or `use_real_hardware=false` | keeps the frame buffer in memory and in `state.json`, API unchanged |

`config.json` ships with `use_real_hardware=true`, so hardware vs simulation is decided by whether `/dev/spidev0.0` exists: with SPI enabled the ring is driven, on a bare Pi the driver degrades to simulation cleanly. The value is baked in as `true` rather than flipped at runtime because the base cold-boot re-extraction restores `config.json` from the tarball on every reboot, so a runtime flip would be overwritten (the canary lab hits the same reset). Set `use_real_hardware=false` to force simulation even with a ring attached. Every control-API exercise in the later waves works identically in simulation, only the physical light and the SPI signal need the ring.

## Part 6 - Drive it over BLE (the Android app channel)

The Android app controls the bulb over BLE (BULB-A1). The Pi runs `ble_light.py`, a dbus-fast GATT server that advertises as `BulbBee` and exposes the Lighting Control service `0xFF30` with a Control characteristic `0xFF31` (write a JSON command) and a State characteristic `0xFF32` (read/notify a JSON snapshot). It is a front-end over the `:8082` service, so a BLE write and an HTTP POST drive the same ring.

This needs a Bluetooth adapter on the Pi (`/sys/class/bluetooth/hci0`) and the `bulbbee-ble` service running. From a BLE central (a phone app such as nRF Connect, or a Linux host with `bleak`):

```sh
# scan for the peripheral
bluetoothctl --timeout 8 scan le | grep -i BulbBee

# minimal connect + write + read with bleak (controller-side, not on the device image)
python3 - <<'PY'
import asyncio, json
from bleak import BleakScanner, BleakClient
CTRL  = "0000ff31-0000-1000-8000-00805f9b34fb"
STATE = "0000ff32-0000-1000-8000-00805f9b34fb"
async def main():
    dev = await BleakScanner.find_device_by_name("BulbBee", timeout=10)
    async with BleakClient(dev) as c:
        await c.write_gatt_char(CTRL, json.dumps({"scene": "rainbow"}).encode())
        print(json.loads(await c.read_gatt_char(STATE)))
asyncio.run(main())
PY
```

On the Pi, `curl http://192.168.2.1:8082/state` reflects the BLE write, and the ring animates (hardware) or the sim frame advances. `bleak` and nRF Connect are controller-side tools, not part of the device image.

## Part 7 - Drive it over the LAN/TCP plane (`:6668`, AES-CCM)

The Tuya-style local plane, `local_tcp.py` (BULB-A4), listens on `:6668` and accepts AES-CCM framed commands, relayed to the same lighting daemon. It is enabled by the `55-bulbbee-lan.sh` hook (`bulbbee-lan` procd service). Frames are `nonce(11) || ciphertext || tag(16)` with a 2-byte big-endian length prefix, encrypted under the local key. In the shipped default the key is the static firmware constant `b"bulbbee-local-16"` (the BULB-P03 substrate), so any LAN host with the extracted key drives the ring (BULB-P06). From a LAN client with pycryptodome:

```sh
python3 - <<'PY'
import socket, struct, json, os
from Crypto.Cipher import AES
KEY = b"bulbbee-local-16"                       # static default key (secure mode derives a per-device key)
n = os.urandom(11)
c = AES.new(KEY, AES.MODE_CCM, nonce=n, mac_len=16)
ct, tag = c.encrypt_and_digest(json.dumps({"scene": "rainbow"}).encode())
f = n + ct + tag
s = socket.create_connection(("192.168.2.1", 6668))
s.sendall(struct.pack(">H", len(f)) + f)
PY
```

The ring animates (hardware) or the sim frame advances. `curl http://192.168.2.1:8082/state` reflects it, since all planes share the one lighting state.

## Part 8 - Drive it over the cloud plane (outbound MQTT tunnel)

The device never listens on the Internet. It opens an outbound MQTT tunnel (`cloud_tunnel.py`, BULB-A3) to a cloud emulator broker and relays commands published to its topic. The emulator is the `mosquitto` broker in `cloud_api/bulbbee/`, managed by `cloudctl.sh`. On the host that plays the cloud:

```sh
cd src/cloud_api/bulbbee
./cloudctl.sh start                             # API :5004 + broker :1883/:8883, prints the cloud_host IP to use
```

On the Pi, point the device at that host and enable the tunnel:

```sh
# set "cloud_host": "<that IP>" in /opt/bulbbee/config.json (bake it into the tarball for a persistent value)
/etc/init.d/bulbbee-tunnel enable && /etc/init.d/bulbbee-tunnel start
```

Then drive the bulb over the tunnel and watch its state, from the cloud host:

```sh
./cloudctl.sh pub <device_id> '{"scene":"rainbow"}'   # publishes to bulbbee/<device_id>/cmd
./cloudctl.sh sub <device_id>                         # follows bulbbee/<device_id>/state
```

The tunnel authenticates with the session token (`session_token.py`). In the default the token key is derived from the enumerable serial plus a hardcoded vendor salt (forgeable, BULB-P04), the transport is plaintext MQTT `:1883` (BULB-P02). Secure mode uses a random per-device secret and MQTT over TLS `:8883`. The REST API on `:5004` (the BULB-CLD BOLA + weak-JWT surface) is a separate inbound surface, `./cloudctl.sh` also manages it.

## Part 9 - Secure mode and the assessor run

One flag flips every plane between the shipped degraded posture and the robust one. Set `"secure": true` in `config.json` (bake it in, the cold-boot re-extraction restores the file) and every mechanism switches to its secure branch: LE SC + Passkey pairing, per-device local key, random session-token secret + TLS tunnel, enforced owner binding, `/debug` refused. The full degraded-vs-robust matrix with code locations is the "Secure mode" section of [`README.md`](README.md).

To exercise the lab as an assessor would, follow the "Assessor battery" section of [`README.md`](README.md): a single guided run (surface scan, `/debug` dump, unauthenticated LAN control, pairing MITM, secret recovery, session-token spoof, device hijack, abusive re-provisioning), each test naming the weakness (BULB-P01..P07) and the EN 303 645 / CRA requirement it fails, and whether `secure=true` refuses it. That scoreboard is the gap between the manufacturer's CRA claims and the device (the BULB-CRA gap key).

## Troubleshooting

| Symptom | Check |
|---|---|
| API does not answer on `:8082` | `pgrep -f lighting_service.py`, `logread | grep bulbbee`, the hook ran for `VULNZOO_DEVICE=bulbbee` |
| ring stays dark, `/state` shows `simulated:true` | `/dev/spidev0.0` exists (Part 2), `use_real_hardware=true` in `config.json` |
| ring flickers or shows wrong colors | logic-level margin (add a level shifter on DIN), `color_order` matches your ring (default `GRB`), lower `spi_hz` slightly, check the DIN series resistor and a solid common ground |
| only the first LEDs light | power budget, use an external 5V supply and share ground, or lower `brightness` |
| service starts then respawns | check `logread` for a Python traceback, confirm `ws2812.py` sits next to `lighting_service.py` in `/opt/bulbbee/` |
| BulbBee not visible over BLE | `/sys/class/bluetooth/hci0` present, `bulbbee-ble` running (`pgrep -f ble_light.py`), `logread | grep bulbbee-ble`, and the L1 heartbeat `/tmp/bulbbee/ble_advertising_heartbeat` is fresh |
| BLE write does nothing | the `:8082` lighting service is up (BLE is a front-end over it), check `logread` for `Control WriteValue` and a `command forward` error |

## Where the attacks go next

The bring-up and secure baselines (BULB-A0..A5) are the honest base. The intentional weaknesses are documented as two axes. The classic per-device catalogue: unauthenticated BLE onboarding and open setup AP (BULB-01), unauthenticated control surface over BLE and HTTP (BULB-02), cleartext replayable channel (BULB-03), unsigned OTA (BULB-04), plaintext secrets (BULB-05), insecure defaults / exposed `/debug` (BULB-06), scene-payload DoS (BULB-07), the cloud API BOLA + weak JWT (BULB-CLD), and the Android app findings (BULB-APP). The three-plane findings (the shipped default degradation of each secure baseline): BLE pairing MITM (BULB-P01), WiFi PSK over BLE cleartext (BULB-P02), static local key from firmware (BULB-P03), static/derivable session token (BULB-P04), owner binding app-only (BULB-P05), LAN proximity = control (BULB-P06), secure-by-default violations (BULB-P07). A `secure` toggle (BULB-SEC) neutralizes them for comparison. The consolidated overview (secure-mode matrix, the three-plane findings table, and the assessor run) is [`README.md`](README.md), the classic per-finding docs are under [`Vulns/`](Vulns/) ([`Vulns/README.md`](Vulns/README.md)), and the CRA default-category dossier is under [`CRA/`](CRA/).
