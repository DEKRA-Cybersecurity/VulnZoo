---
id: BULB-02
title: "Unauthenticated control surface (BLE GATT + local HTTP)"
category: IoT
status: IN PROGRESS
severity: High
owasp: "OWASP IoT Top 10 (2018) I2 - Insecure Network Services (API2 Broken Authentication on the HTTP side)"
standard: "ETSI EN 303 645 5.6 (minimise exposed attack surfaces)"
regulation: "CRA (EU) 2024/2847 Annex I Part I - access control"
cwe: "CWE-306 (Missing Authentication for a Critical Function) / CWE-284 (Improper Access Control)"
source_docs:
  - "stages/01_spec/output/bulbbee-02-spec.md"
affected_components:
  - "labs/bulbbee/files/opt/bulbbee/lighting_service.py"
  - "labs/bulbbee/files/opt/bulbbee/ble_light.py"
verified_date: "2026-09-04"
---

## Why It Matters

BulbBee has two control surfaces and neither authenticates the caller. The BLE Lighting Control characteristic (`0xFF31`) accepts writes over an unbonded link, and the local HTTP API on `:8082` accepts control and configuration requests with no credential. Anyone within Bluetooth range, or anyone on the LAN, can set power, brightness, colour and scene, and read the device state and the running configuration. There is no owner, session, token, or paired controller.

For a light the direct impact is nuisance and, depending on where it is installed, a privacy or safety signal. The larger impact is that the unauthenticated read surface discloses the running configuration to any caller, which is the enabler for the other findings: the config carries the hardcoded provisioning PIN (BULB-01) and, once the bulb is provisioned, the stored WiFi PSK and cloud token (BULB-05). Missing authentication is what turns those into a remote, credential-free read.

## Root Cause

Neither surface checks the caller. The HTTP handler serves control and config with no `Authorization` check, token, or source restriction:

```python
# lighting_service.py
def do_POST(self):
    c = self.controller
    data = self._read_json()
    if self.path == "/set":
        c.set_state(power=data.get("power"), brightness=data.get("brightness"),
                    color=data.get("color"))      # no authentication anywhere
    elif self.path == "/scene":
        c.set_scene(data.get("scene", ""))

def do_GET(self):
    ...
    elif self.path == "/config":
        self._send(200, c.cfg)                    # whole running config to any caller
```

The BLE Control characteristic uses plain `read` / `write` flags (not the `encrypt-authenticated-write` variants) and the adapter is non-pairable, so BlueZ enforces no bonding before a central writes:

```python
# ble_light.py
class ControlChrc(ServiceInterface):
    def __init__(self):
        ...
        self.flags = ["read", "write", "write-without-response"]   # no encryption/auth flag
    @method()
    def WriteValue(self, value, options):
        command = json.loads(bytes(value).decode())   # applied with no auth
        _apply_command(command)
```

The missing control is any authentication at all: no per-device credential, no bonded link, no session on either surface.

## Steps to Reproduce

HTTP, from any host on the LAN, no credential:

```sh
curl http://192.168.2.1:8082/state
curl -X POST http://192.168.2.1:8082/set   -d '{"power":true,"brightness":255,"color":[255,0,0]}'
curl -X POST http://192.168.2.1:8082/scene -d '{"scene":"rainbow"}'
curl http://192.168.2.1:8082/config        # discloses the running config, including prov_pin
```

BLE, from any central in range, no pairing or bonding:

```python
import asyncio, json
from bleak import BleakScanner, BleakClient
CTRL  = "0000ff31-0000-1000-8000-00805f9b34fb"
STATE = "0000ff32-0000-1000-8000-00805f9b34fb"

async def main():
    dev = await BleakScanner.find_device_by_name("BulbBee", timeout=10)
    async with BleakClient(dev) as c:                 # no pairing prompt
        await c.write_gatt_char(CTRL, json.dumps({"scene": "rainbow"}).encode())
        print(json.loads(await c.read_gatt_char(STATE)))

asyncio.run(main())
```

## Expected Result

- `POST /set` and `POST /scene` change the light with no credential (confirmed via `GET /state` and the ring / sim).
- `GET /config` returns the running config to an unauthenticated caller, and it includes `prov_pin` (chain to BULB-01) and, once provisioned, the WiFi PSK and cloud token (chain to BULB-05).
- A BLE central writes `0xFF31` and reads `0xFF32` with no pairing prompt.

## How It Should Be

- Put a bearer token (or a device-bound session) on the HTTP control API, and bind it to the LAN interface only, not `0.0.0.0`.
- Require LE Secure Connections bonding on the BLE Control characteristic, using the `encrypt-authenticated-write` / `encrypt-read` flags so BlueZ refuses unbonded access.
- Never return secrets over an unauthenticated read, split the config into a public status view and an authenticated-only sensitive view.

These land behind the `secure` UCI toggle (`bulbbee.@bulbbee[0].secure=1`, target BULB-SEC) for a direct vulnerable-vs-secure comparison.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Device (HTTP) | Bearer token / device-bound session on `/set`, `/scene`, `/config` | Authenticate the caller (CWE-306) |
| Device (BLE) | LE bonding + `encrypt-authenticated-write` on `0xFF31` | Refuse unbonded control (CWE-306) |
| Device (data) | Public status view vs authenticated-only config view | Stop the no-auth config disclosure (chains BULB-01 / BULB-05) |
| Network | Bind the HTTP API to the LAN interface, not `0.0.0.0` | Reduce the exposed surface (ETSI EN 303 645 5.6) |

## Verification Checklist

- [ ] `POST /set` and `POST /scene` change the light from an unauthenticated LAN host.
- [ ] `GET /config` returns the running config (including `prov_pin`) to an unauthenticated caller.
- [ ] A BLE central writes `0xFF31` and reads `0xFF32` with no bonding.
- [ ] In `secure` mode both surfaces require authentication (HTTP token, BLE bonding) (BULB-SEC).
