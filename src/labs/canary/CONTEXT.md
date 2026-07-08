# canary - Automotive CAN / SOME-IP Lab (Layer 2)

> **Status: PHASE 0 (functional bring-up).** No intentional vulnerabilities yet. The full architecture, protocol maps, and the certification-mapped vulnerability roadmap live in the spec and, once promoted, in the Layer 3 doc at `../../docs/Canary/`. This contract does not restate them.

**Stage Purpose**: Stand up a small in-vehicle ECU subsystem on the Pi where a SOME/IP service controls one vehicle function (central locking) end to end over a real CAN bus, so that later phases can layer intentional automotive vulnerabilities on a working base.

## Scenario

The Pi hosts two ECUs on two MCP2515 + TJA1050 CAN nodes sharing one bus: a Central Gateway (CGW) on can0 that exposes the SOME/IP CentralLockingService over Ethernet and translates it to CAN, and a Body Control Module (BCM) on can1 that actuates the lock and reports status. The tester works from the PC, over Ethernet for SOME/IP and with a USB-CAN adapter on the bus for CAN (Model A). The Pi stays a clean vehicle image with no attacker tooling.

## Components

| Component | Location (`files/`) | Port / IF | Role |
|---|---|---|---|
| CGW (gateway) | `opt/canary/someip_gateway.py` | 30509/udp, can0 | SOME/IP CentralLockingService, SetLock -> LOCK_CMD (0x120), LOCK_STAT (0x121) -> LockStatus event |
| BCM (actuator) | `opt/canary/bcm_ecu.py` | can1 | listens LOCK_CMD, drives the lock indicator, transmits LOCK_STAT on change and a 500 ms heartbeat |
| UCI config | `etc/config/canary` | - | mode, use_real_hardware, bitrate, ifaces, someip_port, event target, indicator GPIO |
| CAN bring-up | `etc/init.d/canary-can` | can0/can1 or vcan0 | enabled service, runs on every boot before the ECUs: detects both MCP2515 (hardware) or falls back to vcan (sim), brings the bus up, sets `use_real_hardware`. Makes canary self-heal after a reboot |
| ECU services | `etc/init.d/canary-gateway`, `etc/init.d/canary-bcm` | - | procd services, pick the CAN iface from UCI (hardware vs sim) |
| Reference client | `tools/someip_client.py` (not packaged) | - | PC-side legitimate driver: `someip_client.py <host> lock|unlock|state` |
| Self-check | `tools/test_canary.py` (not packaged) | - | asserts the SOME/IP header and CAN frame round-trip |
| AGL head unit | `agl/` (PC-side, not packaged) | SOME/IP client | AGL in QEMU as the connected head-unit ECU, drives SetLock over SOME/IP. See `../../docs/Canary/LAB_SETUP.md` |

## Inputs

| Layer | Source | Role |
|---|---|---|
| Layer 3 | `../../docs/Canary/` (once promoted) | Architecture, protocol, frame map, vulnerability roadmap |
| Layer 3 | `../../../stages/01_spec/output/canary-spec.md` | Scope, SOME/IP and CAN maps, deploy strategy, acceptance criteria |
| Layer 4 | `files/opt/canary/` | The two ECU services |
| Layer 4 | `files/usr/lib/vulnzoo-hooks/profile-init.d/` | Init hooks (deps, services, firewall, CAN overlay) |

## Process

1. **Base-image build (one-time).** The CAN kernel packages (`kmod-can`, `kmod-can-mcp251x`, `kmod-can-raw`, `kmod-can-vcan`, `libsocketcan`, `ip-full`) are enabled in `src/labs/vulnzoo/.config`. The `spi=on` + `mcp2515-can0/can1` device-tree overlays are written to `/boot/config.txt` by the `99-canary-can-overlay.sh` hook (idempotent append, values from UCI, so the crystal and INT pins are configurable). Overlays load at boot, so the first load writes them and reboots (auto by default), and on the next boot the `canary-can` service brings the lab up in hardware mode on its own.
2. **Package the overlay.** Build `canary.tar.gz` from `files/`, excluding markdown so the Layer 3 docs do not leak into the deployed overlay.
   ```sh
   cd src/labs/canary/files
   tar -czf canary.tar.gz --exclude="*.md" opt etc usr
   mv canary.tar.gz ../../vulnzoo/files/usr/lib/vulnzoo-devices/canary.tar.gz
   ```
3. **Deploy.** Hooks run in numeric order on lab load.
4. **Hardware presence.** The `canary-can` service requires BOTH can0 and can1 for hardware mode. A single CAN node has no peer to ACK its frames and would bus-off on transmit, so one-node (or no-node) falls back to a single `vcan0` and the full SOME/IP -> CAN -> actuator chain still works in simulation. It runs on every boot, so the mode is re-evaluated after each reboot.

## Hooks (numeric order on lab load)

| Order | Hook | Purpose |
|---|---|---|
| 15 | `15-canary-python-deps.sh` | verify python3 (services are stdlib only, no runtime install) |
| 50 | `50-canary-services.sh` | enable and start `canary-can`, then `canary-gateway` and `canary-bcm` |
| 70 | `70-canary-firewall.sh` | open the SOME/IP UDP port on the LAN (vulnerable mode) |
| 99 | `99-canary-can-overlay.sh` | write the `mcp2515` overlays to `/boot/config.txt` (from UCI), then reboot so they take effect (auto by default, guarded so no boot loop) |

## Services (every boot, procd START order)

| START | Service | Purpose |
|---|---|---|
| 90 | `canary-can` | detect the CAN modules, bring the bus up (can0/can1 at 500k, or vcan0), set `use_real_hardware`. Self-heals canary after any reboot |
| 95 | `canary-gateway`, `canary-bcm` | the CGW and BCM ECU daemons, bind the interface picked from UCI |

## Outputs

| Artifact | Path / Port | Description |
|---|---|---|
| SOME/IP service | `:30509/udp` | CentralLockingService (SetLock, GetLockState, LockStatus) |
| CAN bus | can0 / can1 (or vcan0) | LOCK_CMD 0x120, LOCK_STAT 0x121 at 500 kbit/s |
| Lock state | `/tmp/canary/lock_state` | `locked` / `unlocked`, plus optional GPIO LED |
| Package | `labs/vulnzoo/files/usr/lib/vulnzoo-devices/canary.tar.gz` | Lab overlay |

## Verification checklist

- [ ] `python3 tools/test_canary.py` prints `OK` (wire formats round-trip).
- [ ] Bare Pi (no modules): vcan0 comes up, both services start, `someip_client.py <pi> lock` returns `locked`, `/tmp/canary/lock_state` says `locked`, `state` polls it back.
- [ ] Two modules: can0/can1 up at 500k, a SetLock produces LOCK_CMD 0x120 on the bus (candump on the PC adapter), the BCM emits LOCK_STAT 0x121, and the client reflects the change.
- [ ] LOCK_STAT heartbeat visible at about 2 Hz.
- [ ] Single-module hardware: preflight logs the one-node error and falls back to vcan, no bus-off.
- [ ] No intentional vulnerabilities exist yet.

## Dependencies

| Component | Requirement |
|---|---|
| Hardware | Raspberry Pi 3B+/4, 2x MCP2515 + TJA1050 on SPI0 CE0/CE1 with separate INT GPIOs, 120 ohm at the two bus ends, PC USB-CAN adapter for the tester |
| OS | OpenWRT v24.10.2, target `bcm27xx` |
| Kernel | `kmod-can`, `kmod-can-mcp251x`, `kmod-can-raw`, `kmod-can-vcan`, `libsocketcan`, `ip-full` for `ip link ... type can` |
| Python | 3.x standard library only (AF_CAN raw sockets, UDP), no pip packages |
| Network | `192.168.2.0/24`, Pi at `192.168.2.1`, direct Ethernet |

## References

- Spec / single source of truth (pipeline): [`../../../stages/01_spec/output/canary-spec.md`](../../../stages/01_spec/output/canary-spec.md)
- Layer 3 doc (once promoted): `../../docs/Canary/`
