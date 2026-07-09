# Canary - Lab Setup and Run Guide

> Student walkthrough to build and run the canary automotive lab end to end: the Raspberry Pi in-vehicle domain, the two physical CAN modules, the AGL head-unit in QEMU, and the tester's USB-CAN adapter. By the end, a command from the AGL head unit locks and unlocks the "car" over a real CAN bus.

## What you are building

A modern car has two worlds, and this lab reproduces both plus the gateway between them.

- The rich, connected world: a Linux head unit / telematics ECU. Here it is AGL running in QEMU on your PC.
- The deeply embedded world: small real-time ECUs on a CAN bus. Here the Raspberry Pi hosts two of them and the bus.

The simulated vehicle function is central locking. The head unit asks to lock or unlock, the request crosses SOME/IP to the gateway, the gateway turns it into a CAN frame, and a body ECU actuates the lock. This is the same shape as the classic remote-to-CAN attack chain a UNECE R155 / ISO-SAE 21434 assessment looks for.

## Architecture and topology

```
                          PC / tester (192.168.2.2)
   +--------------------------------------------------------------+
   |  QEMU: AGL head unit  --(SOME/IP UDP, via user-mode NAT)--.   |
   |  USB-CAN adapter ------------------------------------.    |   |
   |  eth0 ----------------------------------------.      |    |   |
   +-----------------------------------------------|------|----|---+
                                                   |      |    |
                    direct Ethernet cable          |      |    | SOME/IP to
                                                   |      |    | 192.168.2.1:30509
             Raspberry Pi (192.168.2.1, OpenWrt)   |      |    |
   +-----------------------------------------------|------|----v---+
   |  CGW (Central Gateway) ---- can0 (SPI CE0) ---+      |        |
   |  BCM (Body Control Mod) --- can1 (SPI CE1) ---+      |        |
   +-----------------------------------------------|------|--------+
                                                   |      |
                 ==== CAN bus (CAN_H / CAN_L on the breadboard) ====
                        can0 ----- can1 ----- USB-CAN adapter
```

Legitimate flow: AGL sends SOME/IP `SetLock` -> CGW transmits `LOCK_CMD` (CAN `0x120`) -> BCM actuates the lock and transmits `LOCK_STAT` (CAN `0x121`) -> CGW returns the result to AGL. The tester watches `0x120` / `0x121` on the bus with the USB-CAN adapter.

## Role mapping (real car -> this lab)

| Real car component | What plays it here |
|---|---|
| Head unit / telematics (IVI) | AGL in QEMU on the PC |
| Central gateway ECU | CGW process on the Pi (`can0`) |
| Body control ECU (locks, lights) | BCM process on the Pi (`can1`) |
| Internal CAN bus | the two MCP2515 + TJA1050 modules, wired together |
| Tester diagnostic gear (OBD) | USB-CAN adapter on the PC |

## Bill of materials

- Raspberry Pi 3B+/4 flashed with the VulnZoo image (OpenWrt, CAN support baked in).
- 2x MCP2515 + TJA1050 CAN modules (8 MHz crystal).
- 1 breadboard and jumper wires.
- 1 USB-CAN adapter for the PC (PEAK, Kvaser, a USB-SLCAN, or a third MCP2515-USB).
- Ethernet cable (direct Pi to PC).
- PC with QEMU and KVM, and the AGL demo image `agl-demo-platform-qemux86-64.vmdk`, downloaded from the VulnZoo GitHub Releases (see Part 4).

## Part 1 - Wire the CAN hardware

Power the modules at 3.3V, not 5V. At 5V the module outputs would push 5V into the Pi's 3.3V GPIO and can damage it. On the breadboard use one rail for 3.3V and one for GND, and one free row per signal (signals must not share a row).

Raspberry Pi header to breadboard:

| Signal      | Pi pin (GPIO)   | Breadboard | Goes to               |
| ----------- | --------------- | ---------- | --------------------- |
| 3.3V        | pin 1           | `+` rail   | VCC of both modules   |
| GND         | pin 6           | `-` rail   | GND of both modules   |
| SCLK        | pin 23 (GPIO11) | row A      | `SCK` of both modules |
| MOSI        | pin 19 (GPIO10) | row B      | `SI` of both modules  |
| MISO        | pin 21 (GPIO9)  | row C      | `SO` of both modules  |
| CE0         | pin 24 (GPIO8)  | row D      | `CS` of module 1      |
| INT (mod 1) | pin 22 (GPIO25) | row E      | `INT` of module 1     |
| CE1         | pin 26 (GPIO7)  | row F      | `CS` of module 2      |
| INT (mod 2) | pin 18 (GPIO24) | row G      | `INT` of module 2     |

Note the naming: the module pin `SI` is its SPI input and goes to the Pi MOSI, `SO` is its output and goes to MISO.

- Module 1 becomes `can0` (the CGW). Module 2 becomes `can1` (the BCM).
- CAN bus: `CAN_H` of module 1 to `CAN_H` of module 2, and `CAN_L` to `CAN_L`. Use two more breadboard rows (one for `CAN_H`, one for `CAN_L`). The screw terminal or the `J3` pins carry `CAN_H`/`CAN_L`, the board marks them `H` and `L`.
- Termination: bridge the `J1` jumper on both modules to enable each module's onboard 120 ohm resistor (two ends, 60 ohm total, correct). Only two terminations total: with a third node like the USB-CAN adapter, leave its termination off.

Where the USB-CAN adapter connects: its `CAN_H` goes to the `CAN_H` row and its `CAN_L` to the `CAN_L` row, so it sits on the same bus as the two modules. Leave the adapter's own 120 ohm termination OFF, the two modules already provide it.

![[canary_hardware.jpg|700]]

## Part 2 - Enable CAN on the Pi (automatic, one reboot)

The CAN kernel drivers are already in the image. What is missing is the device-tree overlay that makes the kernel probe the two MCP2515 chips. The lab handles it for you: when you load canary (Part 3), the `99-canary-can-overlay.sh` hook appends `spi=on` and the two `mcp2515` overlays to `/boot/config.txt` (crystal and INT pins from UCI, defaults `oscillator=8000000`, `cgw_int=25`, `bcm_int=24`, which match the wiring in Part 1) and then reboots the Pi.

Overlays are read by the firmware at boot, so one reboot is unavoidable, but it is automatic. On that reboot the `canary-can` service detects the two modules and brings the lab up in hardware mode on its own, with no second load. So the whole sequence is: load canary once, wait for the automatic reboot, done.

To change the defaults, set them in UCI before the first load: `canary.main.oscillator` (use `16000000` for a 16 MHz crystal), and `cgw_int` / `bcm_int` (the INT GPIOs). To disable the automatic reboot and reboot by hand instead, set `canary.main.can_overlay_reboot=0`. After the reboot, `ls /sys/class/net | grep can` shows `can0` and `can1`.

Equivalent boot-config lines if you prefer to prepare it by hand or bake it into the image:

```
dtparam=spi=on
dtoverlay=mcp2515-can0,oscillator=8000000,interrupt=25
dtoverlay=mcp2515-can1,oscillator=8000000,interrupt=24
```

## Part 3 - Load the canary lab on the Pi

Open the Device Manager at `http://192.168.2.1:8080`, select canary, and load it (or on the Pi run the `*-canary-*` hooks in order). On the very first load the `99` hook writes the CAN overlays and the Pi reboots automatically (Part 2). When it comes back, the `canary-can` service detects `can0` and `can1` and the lab is in hardware mode. Later loads do not reboot, the overlays are already there.

Verify (after the automatic reboot):

```sh
ssh root@192.168.2.1
cat /tmp/canary/mode                          # expect 'hardware' (source of truth, not the UCI file)
ip -br link show | grep -E 'can0|can1'        # both UP, 500k
ps w | grep -E 'someip_gateway|bcm_ecu'       # both services running
ss -lnup | grep 30509                         # SOME/IP listening
cat /tmp/canary/lock_state                    # unlocked
```

If only one module is detected the `canary-can` service falls back to simulation to avoid a bus-off (a lone CAN node has no peer to ACK its frames). Check `logread` and `/root/vulnzoo.log` for the `mcp251x` probe result, and that both modules answer on SPI (a failed probe logs `MCP251x didn't enter in conf mode` / `err=110`). Note: `/etc/config/canary`'s `use_real_hardware` is reverted to `0` by the base re-extraction, so `/tmp/canary/mode` is the value to trust.

## Part 4 - Bring up AGL in QEMU

The AGL demo image is distributed on the VulnZoo GitHub Releases page (it is too large for the repo). Download `agl-demo-platform-qemux86-64.vmdk` from https://github.com/DEKRA-Cybersecurity/VulnZoo/releases (if you get the compressed `.vmdk.xz`, decompress it once with `unxz`).

Then on the PC, point `AGL_IMG` at the downloaded image and launch it (`AGL_IMG` has no default):

```sh
cd src/labs/canary/agl
AGL_IMG=/path/to/agl-demo-platform-qemux86-64.vmdk ./run-agl-qemu.sh
```

Log in per the AGL QuickStart (linked in `agl/README.md`). The VM uses QEMU user-mode NAT, so from inside AGL you can already reach the Pi at `192.168.2.1`, and the guest SSH is forwarded to `localhost:2222` on the PC.

## Part 5 - Lock the car from the head unit

The head unit's central-locking control lives on AGL under `agl/`. Copy it into the guest and operate it, this is the legitimate control an occupant uses and its traffic is what the attack later sniffs. `SetLock` is authenticated, the control holds the token (`AGL-HEADUNIT-7c2f` by default, `canary.main.setlock_token`).

```sh
# on the PC, copy the head-unit control into the AGL guest
scp -P 2222 -r src/labs/canary/agl/carctl src/labs/canary/agl/lock-ui root@localhost:/tmp/

# Level 1 (CLI): operate the lock from the AGL console
ssh -p 2222 root@localhost 'python3 /tmp/carctl lock'      # -> locked
ssh -p 2222 root@localhost 'python3 /tmp/carctl state'     # -> locked
ssh -p 2222 root@localhost 'python3 /tmp/carctl unlock'    # -> unlocked

# Level 2 (IVI screen): serve the web control on AGL, then open it in the IVI browser
ssh -p 2222 root@localhost 'python3 /tmp/lock-ui/server.py &'
#   then open http://<agl-ip>:8088/ in the IVI browser and press Lock / Unlock
```

Watch it on the wire from the PC with the USB-CAN adapter (assuming it comes up as `can0` on your PC, at 500 kbit/s):

```sh
sudo ip link set can0 type can bitrate 500000 && sudo ip link set can0 up
candump can0
# lock  -> 120#01  then 121#01
# unlock-> 120#00  then 121#00   plus a 121 heartbeat about twice a second
```

On the Pi, `cat /tmp/canary/lock_state` follows the commands. That is the full chain: head unit (AGL) -> SOME/IP -> gateway (Pi CGW) -> CAN -> body ECU (Pi BCM) actuates the lock.

The advanced, more realistic path replaces the python client with a vsomeip application on AGL using `agl/vsomeip.json`. See `agl/README.md`.

## Part 6 - What is being simulated

The vehicle function is central locking. The "actuator" is represented on the Pi by `/tmp/canary/lock_state` (`locked` / `unlocked`) and, if `indicator_gpio` is set in `/etc/config/canary`, a GPIO LED. The BCM re-broadcasts `LOCK_STAT` (`0x121`) about twice a second as a heartbeat, the way a real status signal behaves, so the bus is never silent.

## Troubleshooting

| Symptom | Check |
|---|---|
| `can0`/`can1` do not appear | `config.txt` overlays added and the Pi rebooted, both modules powered at 3.3V, INT wiring matches `interrupt=25`/`24` |
| lab stays in simulation | preflight needs both modules, `uci get canary.main.use_real_hardware` and re-load the lab |
| SetLock from AGL times out | the PC can reach `192.168.2.1` (direct Ethernet up), the CGW is listening (`ss -lnup | grep 30509` on the Pi) |
| no frames on the PC candump | USB-CAN on the same `CAN_H`/`CAN_L` rows, adapter at 500k, `J1` termination on both modules, adapter termination off |
| bus errors / no communication | crystal really is 8 MHz, both `J1` bridged (and only those two, not the adapter), `CAN_H`/`CAN_L` not swapped |

## Where the attacks go next

Phase 0 is the functional bring-up, no intentional vulnerabilities yet. The vulnerability roadmap (SOME/IP without authentication, CAN injection and replay, UDS diagnostics, unsigned OTA, and the AGL head-unit surface) with its R155 / ISO-SAE 21434 mapping lives in [`Vulns/README.md`](Vulns/README.md).
