# canary AGL head-unit node

AGL (Automotive Grade Linux) plays the connected head-unit / telematics ECU in the canary lab: the "rich" Linux world that fronts the internal CAN domain. It runs on the tester PC as a QEMU VM and issues SOME/IP calls that the Pi's Central Gateway (CGW) translates to CAN, driving the Body Control Module (BCM) that actuates the central lock.

This folder is a PC-side component, not part of the OpenWRT lab overlay (it is never packaged into `canary.tar.gz`), the same way octobot keeps its cloud and app separate.

## Files

- `run-agl-qemu.sh` - launches the AGL demo image in QEMU with KVM and user-mode NAT so the guest reaches the Pi at `192.168.2.1`. SSH into the guest is forwarded to `localhost:2222`.
- `vsomeip.json` - vsomeip config for the realistic SOME/IP path (static route to the canary `CentralLockingService` at `192.168.2.1:30509`, Service `0x1401`).
- `carctl` - Level 1: the vehicle's central-locking control as a CLI on the head unit. `carctl lock|unlock|state` sends the authenticated SOME/IP `SetLock` to the CGW. Holds the token (`CANARY_TOKEN`, default `AGL-HEADUNIT-7c2f`), gateway via `CANARY_GW` (default `192.168.2.1`).
- `lock-ui/` - Level 2: the same control as an IVI screen (`index.html` + `server.py`). The browser cannot send UDP, so `server.py` serves the page and bridges a button press to the `SetLock`.

## Get the AGL image

The AGL demo image is large, so it is distributed on the VulnZoo GitHub Releases page, not in the repo. Download it before running:

1. Get `agl-demo-platform-qemux86-64.vmdk` (or the compressed `.vmdk.xz`) from https://github.com/DEKRA-Cybersecurity/VulnZoo/releases.
2. If you downloaded the `.xz`, decompress it once: `unxz agl-demo-platform-qemux86-64.vmdk.xz`.
3. Note its path for `AGL_IMG` below.

## Run

`AGL_IMG` has no default, point it at the image you downloaded:

```sh
AGL_IMG=/path/to/agl-demo-platform-qemux86-64.vmdk ./run-agl-qemu.sh
```

Log in per the AGL QuickStart (https://docs.automotivelinux.org/en/trout/#01_Getting_Started/01_Quickstart/01_Using_Ready_Made_Images/). Canonical boot flags for your image live there, the script is a working starting point.

Graphics gotcha: this AGL demo image is old (kernel 4.8-yocto) and its Weston will start on either of two display backends, a DRM GPU (`/dev/dri`) or a plain framebuffer (`/dev/fb0`, VESA), so the video device just has to give it one. Two confirmed working setups:

- **VirtualBox** with the default **VMSVGA** controller: it exposes a VESA `/dev/fb0` that Weston's fbdev backend uses, no DRM needed. This is a fully working path for this image.
- **QEMU** with `-vga cirrus` (what this script uses): `cirrus` is the image's only DRM driver, so it gives `/dev/dri` and Weston's drm backend.

virtio-gpu / virtio-vga give neither in this image and stay black (`VGA_MODE=virtio` is only for newer AGL images). If the HMI is black, check `ssh -p 2222 root@localhost 'systemctl is-active weston; ls /dev/fb0 /dev/dri'` and reboot the guest, Weston sometimes fails its first start before it settles on a backend. SSH on `localhost:2222` works regardless, so a black HMI never blocks the lab, you can drive the lock over SSH.

## The central-locking control (the head unit's legitimate function)

This is what an occupant uses to lock the car, and its SOME/IP traffic is what a gray-box attacker sniffs to recover the token (the AUTO-02 replay path). It runs on AGL and holds the head unit's token. Copy it into the guest:

```sh
scp -P 2222 -r carctl lock-ui root@localhost:/tmp/
```

Level 1 (CLI): operate the lock from the AGL console.

```sh
ssh -p 2222 root@localhost 'python3 /tmp/carctl lock'      # -> locked
ssh -p 2222 root@localhost 'python3 /tmp/carctl state'     # -> locked / unlocked
```

Level 2 (IVI screen): serve the web control on AGL and open it in the IVI browser.

```sh
ssh -p 2222 root@localhost 'python3 /tmp/lock-ui/server.py &'   # http://<agl-ip>:8088/
# press Lock / Unlock on the IVI screen, each press is one authenticated SetLock on the wire
```

Requires `python3` on the AGL guest (the demo image ships it). Level 3, the fully realistic path, is a packaged AGL HTML5 app on the home screen (see `Documentation/creating_html5_apps_for_agl.pdf` in the AGL Virtual ECU) with a vsomeip binding, using `vsomeip.json` to exercise AGL's real SOME/IP stack. That is the upgrade once Level 1/2 work.

`../tools/someip_client.py` remains the PC-side generic client, used for tests and to replay a sniffed token.

Full end-to-end walkthrough for students: [`../../../docs/Canary/LAB_SETUP.md`](../../../docs/Canary/LAB_SETUP.md).
