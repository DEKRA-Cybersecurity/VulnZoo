# BulbBee - Consumer Smart-Light Lab

> **Layer 3 device landing page.** The functional bring-up (BULB-A0/A1) is promoted to `src/` and certified in simulation. The intentional vulnerabilities are implemented and documented (see [`Vulns/README.md`](Vulns/README.md)): the device findings BULB-01..07, the cloud API (BULB-CLD) and the CRA default-category dossier (BULB-CRA), with a `secure` toggle (BULB-SEC) for the hardened comparison and an Android controller (BULB-APP). Device findings are verified offline, their over-the-air / on-Pi steps are recorded blocked in this environment. The vulnerabilities are intentional, do not harden them (use the `secure` toggle to compare).

BulbBee is the VulnZoo consumer smart-light lab. It reproduces a budget WiFi smart light on a Raspberry Pi running OpenWRT, driving an addressable WS2812 RGB LED ring. The controller is an Android app that talks to the device over BLE (a GATT server on the Pi, modeled on CareOtter), and a local HTTP control API on the LAN is a secondary control and diagnostics surface for setting color, brightness and scenes. It exists to fill a specific gap in the ecosystem: a product that the EU Cyber Resilience Act places in its **default category**, the roughly 90% of products with digital elements that fall in no vertical of Annex III or Annex IV and therefore inherit only the baseline. The lab is framed as the sample a tester receives for a CRA conformity assessment of a self-declared product, and the student plays the assessor.

The functional bring-up stands up the ring, the control API, and the BLE channel. The intentional weaknesses (BULB-01..07), the cloud (BULB-CLD), the Android app (BULB-APP), the CRA dossier (BULB-CRA) and the secure-mode toggle (BULB-SEC) are implemented, with their OWASP IoT / ETSI EN 303 645 / CRA Annex I mapping in [`Vulns/README.md`](Vulns/README.md).

## Quick facts

|                     |                                                                     |
| ------------------- | ------------------------------------------------------------------- |
| Domain              | Consumer IoT, smart lighting (CRA default category)                 |
| Platform            | OpenWRT v24.10.2 on Raspberry Pi 3B+/4                              |
| LED hardware        | WS2812 RGB ring (DIN, 5V, GND), driven over SPI0 MOSI (GPIO10)      |
| App control channel | BLE GATT (hci0) - the Android app's channel, modeled on CareOtter (planned, BULB-A1) |
| Local control API   | HTTP on `:8082` (`/state`, `/health`, `/set`, `/scene`, `/config`), secondary LAN/diagnostics |
| Cloud / Mobile      | Cloud deferred to a later wave (`:5004`), the BLE control app is the controller |
| Standards lens      | OWASP IoT Top 10 + ETSI EN 303 645 + CRA Annex I                    |
| Network             | `192.168.2.0/24`, Pi at `192.168.2.1`, direct Ethernet             |

## Why this lab: the CRA default category

Every other VulnZoo lab models a device type the CRA treats specially. RoutCoon is a router, which Annex III lists as an **important** product with digital elements, so it carries the heavier conformity route and the full prEN 40000-1-2 dossier under [`../RoutCoon/CRA/`](../RoutCoon/CRA/). A smart light is listed nowhere in Annex III or Annex IV, so it inherits only the baseline. That makes BulbBee the reference for the default path:

- **Conformity route**: self-assessment under **Module A (internal control)**. The manufacturer draws up the EU Declaration of Conformity and affixes the CE marking with no notified body involved, and may rely on a harmonised standard to presume conformity with the Annex I essential requirements.
- **Baseline standard**: **ETSI EN 303 645** is the natural presumption-of-conformity anchor for a consumer IoT device, so each BulbBee finding maps to an EN 303 645 provision as well as to an OWASP IoT Top 10 entry and a CRA Annex I requirement.
- **Teaching value**: the same claim-versus-device gap the RoutCoon dossier teaches, on the lighter default route, plus an explicit default-versus-important contrast against RoutCoon.

The manufacturer dossier that carries this framing is under [`CRA/`](CRA/) (target BULB-CRA, done).

## Architecture

```
+---------------------------------------------------------------+
|                 RASPBERRY PI 3B+ (OpenWRT 24.10)             |
|                                                              |
|   ble_light.py  - BLE GATT control server (app channel)      |
|     power / brightness / color / scene (+ notify)  [BULB-A1] |
|            |  shared lighting state                          |
|   lighting_service.py (/opt/bulbbee)                         |
|     - WS2812 driver (ws2812.py): SPI real, sim fallback      |
|     - scenes: solid / off / rainbow / breathe                |
|     - HTTP control API :8082 (secondary, LAN/diagnostics)    |
|     - state persisted to /tmp/bulbbee/state.json             |
|            |                                                 |
|      SPI /dev/spidev0.0 (GPIO10 = MOSI = DIN)                |
|            v                                                 |
|     [ WS2812 LED ring:  DIN . 5V . GND ]                     |
+---------------------------------------------------------------+
      ^ BLE (hci0)                    |  LAN 192.168.2.0/24
      |                               v
  Android controller app       App / assessor  ->  GET/POST :8082
```

## Control channels (BLE primary, HTTP `:8082` secondary)

The controller is the Android app, and its channel is BLE. The Pi runs a BLE GATT server (`ble_light.py`, BULB-A1, dbus-fast over BlueZ, modeled on CareOtter's `ble_server.py`) that is a front-end over the local `:8082` lighting service, so BLE and HTTP drive the same lighting state and there is only one writer to the ring. Both surfaces are unauthenticated and unencrypted in Phase 0, the properties BULB-02 and BULB-03 will document as the intentional weaknesses, not findings here.

### BLE GATT (primary, the app channel)

The bulb advertises as `BulbBee` with the Lighting Control service UUID.

| Service | UUID | Characteristic | UUID | Props | Payload |
|---------|------|----------------|------|-------|---------|
| Lighting Control | `0xFF30` | Control | `0xFF31` | write, write-without-response, read | JSON command, e.g. `{"scene":"rainbow"}` or `{"brightness":200,"color":[10,20,30]}`, the same shape as the HTTP `/set` + `/scene` API |
| Lighting Control | `0xFF30` | State | `0xFF32` | read, notify | JSON snapshot, the same as `GET /state` |

A Control write is forwarded to the `:8082` service, and a subscriber to State is notified whenever the state changes. The scan/connect/write walkthrough is in [`LAB_SETUP.md`](LAB_SETUP.md).

### HTTP `:8082` (secondary, LAN/diagnostics)

Plain HTTP, JSON in and out, the same lighting state as the BLE channel.

| Method | Path | Body | Purpose |
|--------|------|------|---------|
| GET | `/health` | - | liveness probe |
| GET | `/state` | - | power, brightness, color, scene, plus `simulated` and the current `frame` |
| GET | `/config` | - | running configuration |
| POST | `/set` | `{"power":true,"brightness":200,"color":[10,20,30]}` | set power / brightness / color |
| POST | `/scene` | `{"scene":"rainbow"}` | activate `solid`, `off`, `rainbow`, or `breathe` |

## WS2812 driving

The ring is driven from `ws2812.py` over SPI at `/dev/spidev0.0`, with GPIO10 (SPI0 MOSI) carrying the WS2812 DIN line. Each WS2812 data bit is encoded as three SPI bits at an SPI clock of about 2.4 MHz, so a `1` becomes `110` and a `0` becomes `100`, giving the roughly 1.25 microsecond WS2812 bit period. One color byte becomes three SPI bytes and one LED (24 bits, GRB) becomes nine SPI bytes, packed into a single SPI write per refresh. This uses only `fcntl.ioctl` to set the SPI clock and `os.write` to push frames, no `python3-spidev` and no `rpi_ws281x` PWM/DMA path.

When `use_real_hardware` is false in `config.json` or `/dev/spidev0.0` is absent, the driver keeps the frame buffer in memory and writes it to `state.json` instead, so the service, the API and every later target run headless with no ring attached. Calibration knobs (`led_count`, `brightness`, `gamma`, `spi_hz`, `color_order`) live in `config.json` because a real ring's timing and perceived color drift from the on-paper values and need per-unit tuning.

## Launch and verify

### 1. Package and deploy

```sh
cd src/labs/bulbbee/files
tar -czf bulbbee.tar.gz opt etc usr
mv bulbbee.tar.gz ../../vulnzoo/files/usr/lib/vulnzoo-devices/bulbbee.tar.gz
```

Load via the Device Manager UI (`http://192.168.2.1:8080`, select `bulbbee`), or over SSH by extracting the tarball and running the `*-bulbbee-*` hook. The `45-bulbbee-light.sh` hook enables and starts the `bulbbee-light` service and probes `http://127.0.0.1:8082/health`.

### 2. Hardware vs simulation

With the ring wired and SPI enabled (see [`LAB_SETUP.md`](LAB_SETUP.md)) the service drives real LEDs. On a bare Pi, or with `use_real_hardware=false`, the same service and API run in simulation, only the physical light is missing. Enabling SPI is a manual one-time step in Phase 0 (`dtparam=spi=on` in the boot config plus a reboot), the service degrades to simulation cleanly if `/dev/spidev0.0` is not present, so the lab always loads.

### 3. Drive it from the LAN

```sh
curl http://192.168.2.1:8082/health                                   # {"status":"ok"}
curl http://192.168.2.1:8082/state                                    # power/brightness/color/scene (+ simulated, frame)
curl -X POST http://192.168.2.1:8082/scene -d '{"scene":"rainbow"}'    # ring animates a rainbow (or the sim frame advances)
curl -X POST http://192.168.2.1:8082/set   -d '{"brightness":200,"color":[10,20,30]}'
```

## Roadmap

The intentional weaknesses (unauthenticated BLE onboarding and open setup AP, unauthenticated control surface over BLE and HTTP, cleartext replayable BLE/HTTP channel, unsigned OTA, plaintext secrets, insecure defaults, scene-payload DoS), their OWASP IoT / ETSI EN 303 645 / CRA Annex I mapping, the cloud API and Android app findings, the default-category CRA dossier, and the `secure` comparison toggle all live in [`Vulns/README.md`](Vulns/README.md) and [`CRA/`](CRA/).

## Documents

- [`LAB_SETUP.md`](LAB_SETUP.md) - student setup and run guide (WS2812 wiring, SPI enablement, load, verify, simulation).
- [`Vulns/README.md`](Vulns/README.md) - vulnerability roadmap and CRA / ETSI EN 303 645 mapping.
- [`../../labs/bulbbee/CONTEXT.md`](../../labs/bulbbee/CONTEXT.md) - Layer 2 lab contract.
- [`CRA/`](CRA/) - the BulbBee CRA **default-category** manufacturer dossier (Module A, self-declared DoC + Annex I mapping + assessor gap key).
- [`../RoutCoon/CRA/`](../RoutCoon/CRA/) - the important-product dossier BulbBee contrasts against.

## Status

The functional bring-up (BULB-A0/A1) is promoted and certified in simulation, on-Pi certification pending. The vulnerability catalogue is implemented: BULB-01..07 (device) and BULB-APP (mobile) are IN PROGRESS (verified offline, over-the-air / on-Pi / build steps blocked in this environment), and BULB-CRA (dossier), BULB-CLD (cloud) and BULB-SEC (secure toggle) are DONE (verified offline, no device dependency). See [`Vulns/README.md`](Vulns/README.md) for the per-finding status and `stages/05_verify/output/` for the evidence.
