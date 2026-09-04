# BulbBee - Consumer Smart-Light Lab (Layer 2)

**Stage Purpose**: Deploy a consumer WiFi smart light (WS2812 LED ring on a Raspberry Pi 3B+) as the VulnZoo reference for a **CRA default-category** product with digital elements, one that falls outside every Annex III / Annex IV vertical and therefore inherits only the baseline essential requirements and the self-assessment (Module A) conformity route.

> **Status**: implemented. The functional bring-up (BULB-A0/A1) and the device findings BULB-01..07 are in `files/` and verified offline (over-the-air / on-Pi steps blocked in the authoring environment), the cloud (BULB-CLD) and CRA dossier (BULB-CRA) and secure toggle (BULB-SEC) are DONE, and the Android app (BULB-APP) source is in `../../vulnzoo_apps/bulbbee_app/`. Development backlog and per-target status: [`../../../stages/TARGET_BULBBEE.md`](../../../stages/TARGET_BULBBEE.md). Per-finding docs: [`../../docs/BulbBee/Vulns/`](../../docs/BulbBee/).

## Why this lab

Every other VulnZoo lab models a device type the CRA treats specially: RoutCoon (router) is an Annex III **important** product, Canary is automotive, CareOtter is medical, OctoBot is industrial. BulbBee fills the gap that is 90% of the real market: a **default-category** product. A smart light is not listed in Annex III or Annex IV, so it demonstrates the CRA baseline in its purest form, and it lets the training material contrast the light default route against RoutCoon's heavier important-product route. See [`../../docs/BulbBee/CRA/`](../../docs/BulbBee/) (Wave 3) and, for the contrast, [`../../docs/RoutCoon/CRA/`](../../docs/RoutCoon/CRA/).

## Scenario

A budget WiFi smart light (BulbBee) drives an addressable RGB LED ring. The **Android controller app talks to the device over BLE**: it onboards the bulb (WiFi and cloud provisioning over a BLE GATT service, mirroring CareOtter) and then sets color, brightness and named scenes over BLE GATT characteristics. A local HTTP API on the LAN is a secondary control and diagnostics surface, and the device pairs with a cloud service for remote control and scene scheduling. The device ships the insecure defaults typical of the low-cost consumer segment, and a fictional manufacturer conformity dossier claims it meets the CRA baseline. The exercise is to test the device against the dossier and find the divergences.

## Architecture (planned)

```
+---------------------------------------------------------------+
|                 RASPBERRY PI 3B+ (OpenWRT 24.10)             |
|                                                              |
|  +------------------+   +------------------+                 |
|  | BLE GATT server  |   | Onboarding       |                 |
|  | (app channel)    |   | BLE provisioning |                 |
|  | power/bright/    |   | + open AP (fallbk)|                |
|  | color/scene +ntfy|   +------------------+                 |
|  +--------+---------+                                         |
|           |  shared lighting state                           |
|  +--------v---------+   +------------------+                 |
|  | Lighting Service |   | Update Agent     |                 |
|  | /opt/bulbbee/    |   | unsigned OTA     |                 |
|  | - WS2812 driver  |   +------------------+                 |
|  | - scenes/color   |                                        |
|  | - HTTP API :8082 |   (secondary LAN control/diagnostics)  |
|  | - MQTT client    |                                        |
|  | - sim/real toggle|                                        |
|  +--------+---------+                                         |
|           |  SPI /dev/spidev0.0 (GPIO10 = DIN)               |
|           v                                                  |
|     [ WS2812 LED ring: DIN . 5V . GND ]                      |
+---------------------------------------------------------------+
      ^ BLE (hci0)         |  LAN 192.168.2.0/24     |  MQTT (cloud, Wave 4)
      |                    v                         v
  Android app          App / attacker on LAN    cloud_api/bulbbee :5004
  (controller)         (curl :8082, diagnostics)
```

## Components (planned)

### 1. BLE GATT control server (app channel, BULB-A1)
**Purpose**: the primary control channel for the Android controller app, modeled on CareOtter's `ble_server.py` (BlueZ over D-Bus).

**Location**: `/opt/bulbbee/ble_light.py` (BULB-A1)

**Features**:
- Lighting Control GATT service `0xFF30` with a Control characteristic `0xFF31` (write a JSON command, the same shape as the HTTP `/set` + `/scene` API) and a State characteristic `0xFF32` (read/notify a JSON snapshot).
- A front-end over the local `:8082` lighting service, so BLE and HTTP drive the same lighting state and there is one writer to the ring.
- LE advertising as `BulbBee` so the app discovers the bulb, with the CareOtter-style self-healing advertising watchdog.
- Onboarding over BLE (WiFi/cloud provisioning) is the onboarding weakness and is delivered by BULB-01 (see component 3), not here.

### 2. Lighting Service (HTTP `:8082`, secondary)
**Purpose**: drive the WS2812 ring and expose a secondary local control / diagnostics surface.

**Location**: `/opt/bulbbee/lighting_service.py` (+ `config.json`)

**Features**:
- WS2812 driving over SPI (`/dev/spidev0.0`, DIN on GPIO10) when hardware is present, simulated frame buffer otherwise (`use_real_hardware` toggle, as in CareOtter).
- Color, brightness, and named scene control, HTTP REST on `:8082`.
- MQTT client for cloud control (Wave 4, local broker mock earlier).
- Calibration knobs (gamma, max brightness, LED count) left tunable, real LEDs and the 800 kHz WS2812 timing drift from the ideal and need per-ring tuning.

### 3. Onboarding (BLE provisioning + setup AP, Wave 1, BULB-01)
Primary path: an unauthenticated BLE provisioning GATT service (no bonding, LE Just Works or a hardcoded factory pairing PIN), mirroring CareOtter's WiFi-over-BLE provisioning. Fallback: an open `BulbBee-setup` WiFi AP with an unauthenticated provisioning endpoint. Intentional weakness.

### 4. Update Agent (Wave 1, BULB-04)
Pulls and applies a scene-pack / firmware update with no signature, origin, or version check. Intentional weakness.

### 5. Cloud connector (Wave 4, optional)
Thin Flask cloud at `cloud_api/bulbbee/` on `:5004` for remote control and scene sync. Deferred.

## Transports and ports

| Channel / service | Port | Protocol | Note |
|-------------------|------|----------|------|
| App control (primary) | - | BLE GATT (hci0) | Android app channel, no bonding (BULB-02/03) |
| Lighting control API (secondary) | 8082 | HTTP | local LAN control + diagnostics (BULB-02) |
| Cloud API (Wave 4) | 5004 | HTTP | remote control / scene sync |
| MQTT (cloud channel) | 1883 | MQTT | no TLS, default creds (BULB-03) |
| Onboarding | - | BLE GATT / WiFi | BLE provisioning primary, open `BulbBee-setup` AP fallback (BULB-01) |

## Intended vulnerabilities

The full catalogue, with OWASP IoT / ETSI EN 303 645 / CRA Annex I mappings and the stage breakdown, lives in [`../../../stages/TARGET_BULBBEE.md`](../../../stages/TARGET_BULBBEE.md). Summary:

| ID | Weakness | OWASP IoT | EN 303 645 |
|----|----------|-----------|------------|
| BULB-01 | Unauthenticated onboarding: BLE provisioning (primary) + open AP fallback + hardcoded pairing | I1 | 5.1 |
| BULB-02 | Unauthenticated control surface (BLE GATT no-bonding + local HTTP) | I2 | 5.6 |
| BULB-03 | Cleartext, replayable control channel (BLE no encryption, plus HTTP + MQTT) | I7 | 5.5 |
| BULB-04 | Unsigned OTA update | I4 | 5.7 |
| BULB-05 | Secrets (WiFi PSK, cloud token) readable over BLE/HTTP config, world-readable on disk | I7 | 5.4 |
| BULB-06 | Insecure default settings / debug surface | I9 | 5.6 |
| BULB-07 | Scene-payload DoS (unbounded LED count / integer overflow) | I2 | 5.9, 5.13 |

> The vulnerabilities are intentional. Do not harden them unless explicitly asked. A `secure` UCI toggle (`bulbbee.@bulbbee[0].secure=1`, target BULB-SEC) provides the hardened comparison mode.

## Inputs

| Layer | Source Path | Role |
|-------|-------------|------|
| Layer 3 | `../../docs/BulbBee/` | README, lab setup, vuln docs, CRA dossier |
| Layer 3 | `../../../stages/TARGET_BULBBEE.md` | development backlog / stage breakdown |
| Layer 4 | `files/opt/bulbbee/` | lighting service + config |
| Layer 4 | `files/etc/init.d/bulbbee-light` | OpenWRT init script |
| Layer 4 | `files/etc/config/bulbbee` | UCI config (incl. secure toggle) |
| Layer 4 | `files/usr/lib/vulnzoo-hooks/` | initialization hooks |

## Build / package

Per [`../../../_config/promotion-map.md`](../../../_config/promotion-map.md):

```bash
cd src/labs/bulbbee/files
tar -cvzf bulbbee.tar.gz opt etc usr
mv bulbbee.tar.gz ../../vulnzoo/files/usr/lib/vulnzoo-devices/bulbbee.tar.gz
```

Then add the `bulbbee` row to [`../../../shared/glossary.md`](../../../shared/glossary.md) and register it in the Device Manager.

## Verification checklist

- [ ] Lab loads from the Device Manager and `bulbbee.tar.gz` extracts cleanly
- [ ] `lighting_service` starts, `curl http://192.168.2.1:8082/state` responds
- [ ] WS2812 ring animates a scene (real hardware) or the sim frame buffer updates
- [ ] BULB-A1: the bulb advertises over BLE and a central connects and writes a control characteristic that changes the ring/sim
- [ ] BULB-01: BLE provisioning is accepted with no bonding/auth (and the open `BulbBee-setup` AP fallback)
- [ ] BULB-02: control + config-read succeed over BLE and from a second LAN host with no auth
- [ ] BULB-03: a sniffed BLE control write replays and the ring reacts
- [ ] BULB-04: an attacker-served update is applied without a signature check
- [ ] BULB-05: WiFi PSK and cloud token are readable in cleartext
- [ ] BULB-07: the crafted scene payload stops the service from serving
- [ ] Secure mode (`bulbbee.@bulbbee[0].secure=1`) neutralizes each of the above

## Dependencies

| Component | Requirement |
|-----------|-------------|
| Hardware | Raspberry Pi 3B+ (onboard BLE), WS2812 LED ring (DIN, 5V, GND) |
| OS | OpenWRT v24.10.2 |
| Python | 3.11+ with standard library |
| Bluetooth | BlueZ with D-Bus (BLE GATT server, the app control channel), as in CareOtter |
| SPI | `kmod-spi-dev` / `/dev/spidev0.0` for real-hardware LED driving |
| Network | 192.168.2.0/24 |

## References

- Development backlog: [`../../../stages/TARGET_BULBBEE.md`](../../../stages/TARGET_BULBBEE.md)
- CRA framing to reuse: [`../../docs/RoutCoon/CRA/00-CRA-Documentation-Plan.md`](../../docs/RoutCoon/CRA/00-CRA-Documentation-Plan.md)
- Template lab contract: [`../careotter/CONTEXT.md`](../careotter/CONTEXT.md), [`../canary/CONTEXT.md`](../canary/CONTEXT.md)
- Doc template: [`../../../_config/vuln-doc-template.md`](../../../_config/vuln-doc-template.md)
