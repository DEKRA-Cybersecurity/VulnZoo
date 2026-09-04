# BulbBee - Lab Setup and Run Guide

> Student walkthrough to build and run the bulbbee smart-light lab: the Raspberry Pi, a WS2812 RGB LED ring, SPI enablement, loading the lab, and driving the light over the control API. By the end, a command over the network changes the ring's color and scene. The lab also runs headless in simulation with no ring attached.

## What you are building

A budget WiFi smart light. A Raspberry Pi running OpenWRT hosts a lighting service that drives an addressable WS2812 RGB ring. The controller is an Android app that talks to the device over BLE (a GATT server on the Pi, planned as BULB-A1, modeled on CareOtter), and a small HTTP control API on `:8082` is the secondary LAN control and diagnostics surface for power, brightness, color and named scenes. This is the shape of a consumer smart light, the textbook CRA default-category product, and later waves add the intentional weaknesses a CRA assessor would look for.

## Role mapping (real product -> this lab)

| Real product part | What plays it here |
|---|---|
| Smart-light MCU + LED driver | `lighting_service.py` + `ws2812.py` on the Pi |
| Addressable RGB LEDs | a WS2812 ring wired to the Pi (or the simulation frame buffer) |
| BLE control server (app channel) | `ble_light.py` on the Pi, BlueZ/D-Bus (planned, BULB-A1) |
| Vendor mobile app | Android controller over BLE (in Phase 0, `curl` on `:8082` is the local diagnostic stand-in) |
| Vendor cloud | deferred to a later wave (`cloud_api/bulbbee/` on `:5004`) |

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

If `/dev/spidev0.0` is absent, the lighting service still starts and runs in simulation, only the physical ring stays dark. Enabling SPI is a manual one-time step in Phase 0. A later iteration can add an overlay hook that writes this automatically on first load, the way the canary lab writes its CAN overlays.

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

On real hardware the ring visibly follows the commands. In simulation, `/state` reflects the change and `cat /tmp/bulbbee/state.json` shows the frame buffer. The service reloads its last state after a restart:

```sh
/etc/init.d/bulbbee-light restart
curl http://192.168.2.1:8082/state          # power/brightness/color/scene as before the restart
```

## Part 5 - Hardware vs simulation

| Mode | When | Behavior |
|---|---|---|
| Hardware | `use_real_hardware=true` and `/dev/spidev0.0` present | drives the WS2812 ring over SPI |
| Simulation | `use_real_hardware=false`, or the spidev node is absent | keeps the frame buffer in memory and in `state.json`, API unchanged |

Set the mode in `/opt/bulbbee/config.json`. Every control-API exercise in the later waves works identically in simulation, only the physical light and the SPI signal need the ring.

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

Phase 0 is the functional bring-up, no intentional vulnerabilities yet. The next groundwork is the BLE GATT control service (BULB-A1), the Android app's channel to the device. The vulnerability roadmap (unauthenticated BLE onboarding and open setup AP, unauthenticated control surface over BLE and HTTP, cleartext replayable BLE/HTTP channel, unsigned OTA, plaintext secrets, insecure defaults, scene-payload DoS) and the CRA default-category dossier, with their ETSI EN 303 645 and CRA Annex I mapping, live in [`Vulns/README.md`](Vulns/README.md).
