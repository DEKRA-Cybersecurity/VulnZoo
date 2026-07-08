# canary AGL head-unit node

AGL (Automotive Grade Linux) plays the connected head-unit / telematics ECU in the canary lab: the "rich" Linux world that fronts the internal CAN domain. It runs on the tester PC as a QEMU VM and issues SOME/IP calls that the Pi's Central Gateway (CGW) translates to CAN, driving the Body Control Module (BCM) that actuates the central lock.

This folder is a PC-side component, not part of the OpenWRT lab overlay (it is never packaged into `canary.tar.gz`), the same way octobot keeps its cloud and app separate.

## Files

- `run-agl-qemu.sh` - launches the AGL demo image in QEMU with KVM and user-mode NAT so the guest reaches the Pi at `192.168.2.1`. SSH into the guest is forwarded to `localhost:2222`.
- `vsomeip.json` - vsomeip config for the realistic SOME/IP path (static route to the canary `CentralLockingService` at `192.168.2.1:30509`, Service `0x1401`, no Service Discovery).

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

Log in per the AGL QuickStart (https://docs.automotivelinux.org/en/trout/#01_Getting_Started/01_Quickstart/01_Using_Ready_Made_Images/). Canonical boot flags for your image live there, the script is a working starting point, adjust the display flags if the compositor does not come up.

## Driving the lock from AGL

Two paths, both send a SOME/IP `SetLock` to the CGW.

- MVP (reproducible, no build): copy the lab's reference client into the guest and run it.
  ```sh
  scp -P 2222 ../tools/someip_client.py root@localhost:/tmp/
  ssh -p 2222 root@localhost 'python3 /tmp/someip_client.py 192.168.2.1 lock'
  ```
- Realistic (advanced): build a small vsomeip client on AGL that requests Service `0x1401` and calls method `0x0001` (SetLock), pointing `VSOMEIP_CONFIGURATION` at `vsomeip.json`. This exercises AGL's real SOME/IP stack. It is heavier to set up and is the upgrade path once the MVP works.

Full end-to-end walkthrough for students: [`../../../docs/Canary/LAB_SETUP.md`](../../../docs/Canary/LAB_SETUP.md).
