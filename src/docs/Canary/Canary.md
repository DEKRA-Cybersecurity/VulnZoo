# Canary - Automotive CAN / SOME-IP Lab

> **Layer 3 device landing page.** Phase 0 (functional bring-up) is verified on the Pi in simulation. The first vulnerability chain, a 2015 Jeep Cherokee reconstruction (`AUTO-01/05/02`, remote-to-CAN), is implemented, documented, and verified on the Pi in simulation (see [`Vulns/Automotive/AUTO-Jeep-Kill-Chain.md`](Vulns/Automotive/AUTO-Jeep-Kill-Chain.md)). Hardware mode (the two physical CAN modules) and the AGL head-unit node are brought up per [`LAB_SETUP.md`](LAB_SETUP.md). Further findings are a documented roadmap (see [`Vulns/README.md`](Vulns/README.md)). The vulnerabilities are intentional.

Canary is the VulnZoo automotive lab. It reproduces a small in-vehicle ECU subsystem on a Raspberry Pi running OpenWRT, driven by two real MCP2515 + TJA1050 CAN nodes, with a modern service-oriented control interface (SOME/IP over Automotive Ethernet) in front of a classic CAN bus. The lab is framed as the sample that a tester at a certification body (a TIC company such as DEKRA) receives for a UNECE R155 and ISO/SAE 21434 assessment, a representative subsystem with an external service interface and an internal CAN bus. The student plays the assessor.

Phase 0 stands up the functional environment only. A single vehicle function, central locking, is controlled end to end through a SOME/IP service that translates to CAN frames and drives an actuator. Attacks and the certification-mapped vulnerabilities come in later phases.

## Quick facts

|                       |                                                                         |
| --------------------- | ----------------------------------------------------------------------- |
| Domain                | Automotive, in-vehicle E/E (ICS-adjacent)                               |
| Platform              | OpenWRT v24.10.2 on Raspberry Pi 3B+/4, target `bcm27xx`                |
| CAN nodes             | 2x MCP2515 + TJA1050 on SPI0 (CE0 -> can0 CGW, CE1 -> can1 BCM)         |
| CAN                   | classic CAN, 500 kbit/s, single bus shared by both nodes                |
| Service layer         | SOME/IP over UDP, CentralLockingService on `:30509`                     |
| Controlled function   | Central locking (single component in phase 0)                          |
| Test model            | Model A: tester on the PC, Ethernet for SOME/IP plus a USB-CAN adapter on the bus |
| Head unit             | AGL (Automotive Grade Linux) in QEMU on the PC, SOME/IP client of the CGW |
| Cloud / Mobile        | Deferred to later phases                                                |
| Network               | `192.168.2.0/24`, Pi at `192.168.2.1`, direct Ethernet                  |

## Test / attacker model (Model A)

Attacks and tests originate from the PC, never from a shell on the Pi. The Pi is the vehicle and stays a clean ECU image with no attacker tooling baked in (`canutils` is deliberately left out of the base image). The tester reaches the vehicle exactly as a bench tester reaches a real car, over Ethernet for the SOME/IP service layer, and over the CAN bus with the PC's own USB-CAN adapter clipped to CAN_H and CAN_L. Because the tester brings the CAN interface, both Pi modules are vehicle nodes.

## Architecture

```
  PC tester (192.168.2.2)
   |  Ethernet -> SOME/IP SetLock / GetLockState ---------.
   |  USB-CAN  -> candump / cansend --------------.        |
   v                                              v        v
  ==== CAN BUS  (CAN_H / CAN_L, 120 ohm at the two ends) ====
          |                              |
       can0 (SPI CE0)                 can1 (SPI CE1)
       CGW - Central Gateway          BCM - Body Control Module
       hosts the SOME/IP service,     listens LOCK_CMD, drives the
       SetLock -> tx LOCK_CMD,        lock indicator, tx LOCK_STAT
       rx LOCK_STAT -> event          (on change + periodic heartbeat)
          \________ both processes on the Raspberry Pi ________/
```

Legitimate control flow: the PC calls SetLock over SOME/IP UDP, the CGW transmits LOCK_CMD (CAN 0x120), the BCM receives it, updates the lock state, drives the indicator, transmits LOCK_STAT (CAN 0x121), and the CGW returns the SetLock response and (if a static event target is configured) the LockStatus notification. The tester on the PC USB-CAN sees LOCK_CMD and LOCK_STAT on the bus.

### Head unit (AGL)

The connected head-unit / telematics ECU is AGL (Automotive Grade Linux) running in QEMU on the PC. It is the rich Linux world that fronts the internal CAN domain, and it drives the lock by sending the same SOME/IP SetLock to the CGW, reproducing the remote-to-CAN kill chain across the two worlds. AGL is a PC-side node under [`../../labs/canary/agl/`](../../labs/canary/agl/), not part of the OpenWRT overlay. The full end-to-end topology (Pi, CAN modules, USB-CAN adapter, AGL) and the student walkthrough are in [`LAB_SETUP.md`](LAB_SETUP.md).

## Protocol reference

### SOME/IP CentralLockingService

Transport is UDP over eth0 at `192.168.2.1:30509`. Phase 0 uses a static endpoint with no Service Discovery. The service is hand-rolled on the Python standard library, the SOME/IP header is a fixed 16-byte layout.

| Item | Value |
|------|-------|
| Service ID | 0x1401 |
| Instance ID | 0x0001 |
| Protocol / Interface version | 0x01 / 0x01 |

| Kind | Name | ID | Request | Response / notify |
|------|------|----|---------|-------------------|
| Method | SetLock | 0x0001 | 1 byte: 0x00 unlock, 0x01 lock | 1 byte resulting state (RESPONSE 0x80) |
| Method | GetLockState | 0x0002 | empty | 1 byte current state |
| Event | LockStatus | 0x8001 | - | 1 byte state (NOTIFICATION 0x02), static target, full pub/sub in the SD phase |

SetLock is authenticated in the current phase: the request payload is the head-unit token followed by the lock byte (`token || 0x01`), and a tokenless or wrong-token SetLock is rejected with a SOME/IP error. The response echoes the request's Request ID so SOME/IP tooling can correlate it. The exposed management service (`0x1402 UpdateFirmware`) and the post-reflash `RelayFrame` (`0x0003`) are the Jeep-chain attack surface, documented in [`Vulns/Automotive/AUTO-Jeep-Kill-Chain.md`](Vulns/Automotive/AUTO-Jeep-Kill-Chain.md).

### CAN frame map (classic CAN, 11-bit IDs, 500 kbit/s)

| Name | CAN ID | Dir | DLC | Bytes | Meaning |
|------|--------|-----|-----|-------|---------|
| LOCK_CMD | 0x120 | CGW -> BCM | 1 | b0: 0x00 unlock / 0x01 lock | lock command from the gateway |
| LOCK_STAT | 0x121 | BCM -> bus | 1 | b0: 0x00 unlocked / 0x01 locked | actual lock state, on change and as a 500 ms heartbeat |

## Launch and verify

### 1. Package and deploy

```sh
cd src/labs/canary/files
tar -czf canary.tar.gz --exclude="*.md" opt etc usr
mv canary.tar.gz ../../vulnzoo/files/usr/lib/vulnzoo-devices/canary.tar.gz
```

Load via the Device Manager UI (`http://192.168.2.1:8080`, select `canary`), or manually over SSH by extracting the tarball and running the `*-canary-*` hooks in order. Hooks run `15` verify python3, `50` enable and start the `canary-can`, `canary-gateway` and `canary-bcm` services, `70` open the SOME/IP port on the LAN, and `99` write the `mcp2515` overlays to `/boot/config.txt` and reboot. The enabled `canary-can` service detects the modules and brings the bus up on every boot (hardware if both present, else vcan sim).

The CAN kernel support (`kmod-can`, `kmod-can-mcp251x`, `kmod-can-raw`, `kmod-can-vcan`, `libsocketcan`, `ip-full`) is baked into the base image. The `spi=on` plus `mcp2515-can0/can1` device-tree overlays are written to `/boot/config.txt` by the `99-canary-can-overlay.sh` hook (values from UCI). On the first load it writes them and the Pi reboots automatically, then the `canary-can` service brings the lab up in hardware mode on boot. See [`LAB_SETUP.md`](LAB_SETUP.md) Part 2.

### 2. Hardware vs simulation

With both modules attached the lab brings up can0 and can1 at 500 kbit/s. On a bare Pi it falls back to a single `vcan0` and the full SOME/IP to CAN to actuator chain still works, only the tester's physical bus tap needs the real modules. A single module is refused for hardware mode, since a lone CAN controller has no peer to ACK its frames and would go bus-off on transmit.

### 3. Drive it from the PC

```sh
python3 tools/someip_client.py 192.168.2.1 lock AGL-HEADUNIT-7c2f    # -> locked
python3 tools/someip_client.py 192.168.2.1 state                     # -> locked
python3 tools/someip_client.py 192.168.2.1 unlock AGL-HEADUNIT-7c2f  # -> unlocked
candump can0                                          # LOCK_CMD 0x120 and LOCK_STAT 0x121 on the PC USB-CAN
```

`tools/someip_client.py` is the PC-side reference client and is not part of the deployed vehicle image.

## Certification framing and roadmap

Findings carry a dual mapping, the way a TIC assessment report is structured, UNECE R155 Annex 5 threat categories and ISO/SAE 21434 process work products for the in-vehicle and update surfaces, and OWASP API, Mobile and IoT for the cloud, app and telematics surfaces added later. The vulnerability roadmap and the mapping live in [`Vulns/README.md`](Vulns/README.md). The first chain (`AUTO-01/05/02`, the Jeep reconstruction) is implemented, the rest of the catalog is a roadmap.

## Documents

- [`LAB_SETUP.md`](LAB_SETUP.md) - end-to-end student setup and run guide (Pi, CAN wiring, AGL in QEMU, USB-CAN adapter).
- [`Vulns/README.md`](Vulns/README.md) - vulnerability roadmap and certification mapping.
- [`../../labs/canary/agl/README.md`](../../labs/canary/agl/README.md) - AGL head-unit node (QEMU launch and SOME/IP interop).
- [`../../labs/canary/CONTEXT.md`](../../labs/canary/CONTEXT.md) - Layer 2 lab contract.

## Status

Phase 0 promoted to `src/labs/canary/` and verified on the Pi in simulation (the SOME/IP to CAN to BCM chain, SetLock and GetLockState). The first vulnerability chain (`AUTO-01/05/02`, the Jeep reconstruction) is implemented, documented, and verified on the Pi in simulation (DONE). The SOME/IP header, CAN frame packers, and the chain gateway logic are unit-checked (`tools/test_canary.py`). Hardware mode with the two MCP2515 modules and the AGL head-unit node are brought up per [`LAB_SETUP.md`](LAB_SETUP.md). The remaining roadmap is PENDING.
