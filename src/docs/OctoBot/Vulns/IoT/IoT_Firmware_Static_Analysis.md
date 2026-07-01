---
id: IoT:I10-FW
title: "Firmware Static Analysis — SD-Card Binwalk Extraction"
category: IoT
status: IN PROGRESS
severity: Medium
owasp: "IoT I10 — Lack of Physical Hardening / IoT I1 — Weak, Guessable, or Hardcoded Passwords"
cwe: "CWE-1263 (Physical Access Issues) / CWE-798 (Use of Hard-coded Credentials)"
source_docs:
  - "src/docs/OctoBot/OPENWRT_INTEGRATION.md §3, §4, §7"
  - "src/docs/OctoBot/Vulns/IoT/IoT1_Weak_Guessable_Hardcoded_Passwords.md"
  - "src/docs/OctoBot/Vulns/IoT/IoT2_Insecure_Network_Services.md"
  - "src/docs/OctoBot/Vulns/IoT/IoT4_Lack_of_Secure_Update_Mechanism.md"
  - "src/docs/OctoBot/Vulns/IoT/IoT7_Insecure_Data_Transfer_and_Storage.md"
  - "src/docs/OctoBot/Vulns/IoT/IoT9_Insecure_Default_Settings.md"
affected_components:
  - "labs/octobot/firmware_analysis/extractions/"
  - "labs/octobot/files/opt/octobot/firmware/robot_arm.hex"
verified_date: "2026-06-19"

> **Scope note:** The source overlay tarball at `labs/vulnzoo/files/usr/lib/vulnzoo-devices/octobot.tar.gz` is the VulnZoo packaging artifact used to populate the live Pi. It is intentionally **out of scope** for this firmware-analysis procedure; the analysis targets the firmware image(s) obtained from the running device.
---

# IoT:I10-FW — Firmware Static Analysis: SD-Card Binwalk Extraction

> **Status:** IN PROGRESS  
> **Source docs:** `OPENWRT_INTEGRATION.md`, `IoT:I1`, `IoT:I2`, `IoT:I4`, `IoT:I7`, `IoT:I9`  
> **OWASP:** IoT I10 (Physical Hardening) / IoT I1 (Hardcoded Passwords)  
> **CWE:** CWE-1263 / CWE-798  
> **Severity:** Medium

---

## Why It Matters

The OctoBot Pi is an OpenWRT gateway. Its SD card contains the base firmware, the runtime overlay, and the Arduino `.hex` image. Because the overlay is dropped onto the base image at lab-load time, an attacker who gains physical access (or any shell on the Pi) can dump the card, run `binwalk`, and recover the entire vulnerable surface offline: default passwords, hardcoded API keys, the actuator password, the MQTT broker configuration, and the firewall rules. This turns a network compromise or a brief physical encounter into a complete static teardown of the device.

---

## What the firmware contains

| Layer | On-disk location | Contents |
|-------|------------------|----------|
| Boot partition | `/dev/mmcblk0p1` | Raspberry Pi boot firmware, kernel, device trees |
| Root partition | `/dev/mmcblk0p2` | OpenWRT Squashfs rootfs + F2FS overlay |
| Lab overlay | deployed onto `/overlay` at lab-load time (pulled live from the running Pi) | OctoBot services, UCI config, hooks, firewall rules |
| Arduino firmware | `/opt/octobot/firmware/robot_arm.hex` | Compiled ATmega328P image flashed by `avrdude` |

> The VulnZoo source tarball (`octobot.tar.gz`) is a build/packaging artifact and is **out of scope** for this analysis. The procedure uses only images and files extracted from the running device.
> In spite of this, in case you can't get access to the Pi you can use `easyuser` (user without credentials), so you can use the commands bellow to get all data needed for firmware analysis.

---

## Acquisition

### Full SD card dump

```bash
ssh root@192.168.2.1 'dd if=/dev/mmcblk0 bs=4M | gzip -c' > octobot_sdcard.img.gz
```

The card is ~30 GB, but most of it is empty; gzip compresses it to a few hundred megabytes.

### Targeted partitions

If only the boot/root partitions are needed:

```bash
ssh root@192.168.2.1 'dd if=/dev/mmcblk0p1 bs=4M | gzip -c' > octobot_p1_boot.img.gz
ssh root@192.168.2.1 'dd if=/dev/mmcblk0p2 bs=4M count=512 | gzip -c' > octobot_p2_first2gb.img.gz
```

The first 128 MB of `mmcblk0p2` already contain the Squashfs rootfs.

### Live overlay snapshot

The dynamically deployed OctoBot files can also be pulled directly from a running lab:

```bash
ssh root@192.168.2.1 'tar -czf - /opt/octobot /etc/init.d/octobot-* /etc/config/octobot /etc/config/firewall /root/vulnzoo.log' > live_overlay.tar.gz
```

---

## Extraction with binwalk

### Boot partition

```bash
gunzip -c octobot_p1_boot.img.gz > octobot_p1_boot.img
binwalk -e -M octobot_p1_boot.img
```

Binwalk identifies the Linux kernel ARM64 image, Broadcom bootcode, and device-tree blobs. This is the standard Raspberry Pi boot chain, not OctoBot-specific, but it confirms the exact kernel and boot configuration.

### Root partition

```bash
gunzip -c octobot_p2_first128mb.img.gz > octobot_p2_first128mb.img
binwalk -e -M octobot_p2_first128mb.img
```

Expected signature:

```text
0             0x0             Squashfs filesystem, little endian, version 4.0, compression:xz, size: 47678596 bytes, 5510 inodes, blocksize: 262144 bytes, created: 2025-09-19 21:19:38
```

The extracted `squashfs-root/` is the read-only OpenWRT base image.

### Arduino firmware

The shipped `.hex` is Intel HEX. Convert it to raw binary before analysis:

```bash
python3 -c '
import sys
with open("robot_arm.hex") as f:
    data = {}
    for line in f:
        line = line.strip()
        if not line or line[0] != ":": continue
        bytecount = int(line[1:3], 16)
        address = int(line[3:7], 16)
        rectype = int(line[7:9], 16)
        payload = bytes.fromhex(line[9:9+bytecount*2])
        if rectype == 0:
            for i, b in enumerate(payload):
                data[address + i] = b
out = bytearray(max(data) + 1)
for addr, b in data.items():
    out[addr] = b
open("robot_arm.bin", "wb").write(out)
'

strings robot_arm.bin | grep -iE "pass|octo|version|auth|servo"
```

Expected output:

```text
OCTOBOT_FW_VERSION:v1.0.0
PASS:
OctoSuperBot2026
ERR AUTH
```

---

## Findings mapped to IoT vulnerabilities

| Finding | Evidence in extraction | Maps to |
|---------|------------------------|---------|
| Blank root password in `/etc/shadow` (`root:::0:99999:7:::`) | `binwalk_p2/.../squashfs-root/etc/shadow` | `IoT:I1`, `IoT:I9` |
| Dropbear allows root password auth (`RootPasswordAuth 'on'`) | `binwalk_p2/.../squashfs-root/etc/config/dropbear` | `IoT:I9` |
| Default `rpcd`/`uhttpd` password `openwrt` | `binwalk_p2/.../squashfs-root/etc/config/rpcd`, `etc/config/uhttpd` | `IoT:I1`, `IoT:I9` |
| `mosquitto-nossl` baked into base image | `binwalk_p2/.../squashfs-root/usr/lib/opkg/status` | `IoT:I2`, `IoT:I7` |
| Mosquitto default config leaves `allow_anonymous` implicitly true | `binwalk_p2/.../squashfs-root/etc/mosquitto/mosquitto.conf` (all auth lines commented out, `use_uci 0`) | `IoT:I2` |
| Hardcoded API key `octobot-industrial-2020` | live overlay `etc/config/octobot` + `opt/octobot/octobot_gateway.py` | `IoT:I1`, `IoT:I7` |
| Default admin credentials `admin/admin` | live overlay `etc/config/octobot` | `IoT:I1`, `IoT:I9` |
| Hardcoded actuator password `OctoSuperBot2026` | `robot_arm.hex` → binary strings | `IoT:I1` |
| Firmware version marker `OCTOBOT_FW_VERSION:v1.0.0` | `robot_arm.hex` → binary strings | `IoT:I4` |
| All services bind `0.0.0.0` | live overlay `opt/octobot/*.py` | `IoT:I2`, `IoT:I9` |
| Firewall opens `:2000`, `:502`, `:1883`, `:8090` to LAN | live overlay `etc/config/firewall` | `IoT:I9` |
| VulnZoo device manager exposes device IP and API port in UCI | `binwalk_p2/.../squashfs-root/etc/config/vulnzoo` | `IoT:I6`, `IoT:I7` |

---

## Steps to Reproduce

```bash
# 1. Dump the SD card from the Pi
ssh root@192.168.2.1 'dd if=/dev/mmcblk0 bs=4M | gzip -c' > octobot_sdcard.img.gz

# 2. Decompress a sample of the root partition
gunzip -c octobot_sdcard.img.gz | dd of=octobot_p2_sample.img bs=1M count=128

# 3. Extract filesystems
binwalk -e -M octobot_p2_sample.img

# 4. Search the extracted rootfs for default credentials
cd _octobot_p2_sample.img.extracted/squashfs-root
cat etc/shadow                              # blank root password
cat etc/config/dropbear                     # RootPasswordAuth on
cat etc/config/rpcd                         # password 'openwrt'
grep -R "allow_anonymous" etc/mosquitto/    # implicitly true

# 5. Pull and inspect the live OctoBot overlay
ssh root@192.168.2.1 'tar -czf - /opt/octobot /etc/config/octobot /etc/config/firewall' > live_overlay.tar.gz
tar -xzf live_overlay.tar.gz
grep -E "api_key|admin_pass" etc/config/octobot
grep -E "dest_port '1883|dest_port '2000|dest_port '502|dest_port '8090" etc/config/firewall

# 6. Recover secrets from the Arduino firmware
python3 -c '
import sys
with open("opt/octobot/firmware/robot_arm.hex") as f:
    data = {}
    for line in f:
        line = line.strip()
        if not line or line[0] != ":": continue
        bc = int(line[1:3], 16)
        addr = int(line[3:7], 16)
        rt = int(line[7:9], 16)
        pl = bytes.fromhex(line[9:9+bc*2])
        if rt == 0:
            for i, b in enumerate(pl):
                data[addr+i] = b
out = bytearray(max(data)+1)
for a, b in data.items(): out[a] = b
open("robot_arm.bin", "wb").write(out)
'
strings robot_arm.bin | grep -iE "OCTOBOT_FW_VERSION|OctoSuperBot|PASS:|ERR AUTH"
```

---

## How It Should Be

- **Physical hardening:** Restrict physical access; encrypt the overlay partition or store secrets in a TPM/Secure Element.
- **No default credentials:** Force a unique password on first boot; store only salted hashes.
- **No cleartext secrets in firmware:** Derive per-device keys; do not embed passwords in the Arduino image.
- **Secure MQTT:** Use `mosquitto-ssl` with authentication and ACLs, not `mosquitto-nossl` with anonymous access.
- **Minimal attack surface:** Bind services to the management interface and keep OT ports off the LAN by default.

---

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Physical | Tamper-evident case, encrypted overlay | Prevent offline SD-card teardown |
| Provisioning | First-boot unique password + hash storage | Eliminate blank/default credentials |
| Firmware | Per-device key derivation, no static secrets | Survive `.hex` extraction |
| MQTT | `mosquitto-ssl` + auth + ACLs | Stop anonymous plaintext control |
| Network | Bind to mgmt interface, deny-by-default firewall | Shrink reachable surface |

---

## Verification Checklist

- [ ] `dd` of `/dev/mmcblk0` produces a valid image
- [ ] `binwalk` extracts a Squashfs rootfs from `mmcblk0p2`
- [ ] `etc/shadow` shows a blank root password
- [ ] `etc/config/dropbear` has `RootPasswordAuth 'on'`
- [ ] `etc/config/rpcd` / `etc/config/uhttpd` contain default password `openwrt`
- [ ] `usr/lib/opkg/status` lists `mosquitto-nossl`
- [ ] `etc/mosquitto/mosquitto.conf` leaves authentication disabled by default
- [ ] Live overlay `etc/config/octobot` exposes `api_key`, `admin_user`, `admin_pass`
- [ ] `robot_arm.hex` converted to binary yields `OctoSuperBot2026` and `OCTOBOT_FW_VERSION:v1.0.0`
- [ ] Firewall rules in live overlay accept OT ports from the LAN

---

## Related Vulnerabilities

- [IoT:I1 — Weak, Guessable, or Hardcoded Passwords](IoT1_Weak_Guessable_Hardcoded_Passwords.md)
- [IoT:I2 — Insecure Network Services](IoT2_Insecure_Network_Services.md)
- [IoT:I4 — Lack of Secure Update Mechanism](IoT4_Lack_of_Secure_Update_Mechanism.md)
- [IoT:I7 — Insecure Data Transfer and Storage](IoT7_Insecure_Data_Transfer_and_Storage.md)
- [IoT:I9 — Insecure Default Settings](IoT9_Insecure_Default_Settings.md)
- [IoT:I10 — Lack of Physical Hardening](IoT10_Lack_of_Physical_Hardening.md)
