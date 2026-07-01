---
id: IoT:I7
title: "Insecure Data Transfer and Storage"
category: IoT
status: IN PROGRESS
severity: High
owasp: "IoT I7 - Insecure Data Transfer and Storage"
cwe: "CWE-319 (Cleartext Transmission of Sensitive Information) / CWE-312 (Cleartext Storage of Sensitive Information)"
source_docs:
  - "src/docs/OctoBot/OPENWRT_INTEGRATION.md §5, §7 (IoT:I7)"
  - "stages/01_spec/output/octobot-spec.md"
  - "stages/02_implement/output/manifest.md"
affected_components:
  - "labs/octobot/files/opt/octobot/octobot_gateway.py"
  - "labs/octobot/files/opt/octobot/robot_mqtt_bridge.py"
  - "labs/octobot/files/etc/config/octobot"
verified_date: ""
---

## Why It Matters

Nothing in OctoBot is encrypted. Commands cross the network in cleartext over HTTP, MQTT, Modbus, and the raw serial bus, and credentials sit in cleartext in the UCI config. An attacker on the LAN captures commands and the API key with a passive sniff, and anyone who reads the overlay recovers the stored secrets. Confidentiality and integrity of the control channel are absent end to end.

## Root Cause

Transit is cleartext on every channel. The gateway serves plain HTTP:

```python
# labs/octobot/files/opt/octobot/octobot_gateway.py
app.run(host='0.0.0.0', port=HTTP_PORT)     # [IoT:I9] all interfaces, [IoT:I7] plain HTTP
```

The MQTT bridge connects without TLS, and the serial bus forwards in cleartext. At rest, the API key and admin password are stored verbatim in the UCI config:

```
# labs/octobot/files/etc/config/octobot
	option api_key 'octobot-industrial-2020'
	option admin_pass 'admin'
```

Firmware static analysis proves the problem is baked in. Binwalk extraction of `/dev/mmcblk0p2` shows `Package: mosquitto-nossl` in the base image, and the extracted broker config (`/etc/mosquitto/mosquitto.conf`) ships with TLS disabled by default. The same extraction also recovers `/etc/config/vulnzoo`, which stores the device control-plane IP and API port in cleartext. See [IoT:I10-FW — Firmware Static Analysis](IoT_Firmware_Static_Analysis.md).

## Steps to Reproduce

```bash
# Passive capture of cleartext commands and secrets on the LAN
sudo tcpdump -i any -A 'tcp port 8090 or tcp port 2000 or tcp port 502 or tcp port 1883'
# Move the arm from any path; the command (and on HTTP, request details) appear in cleartext.

# Cleartext storage
uci show octobot | grep -E 'api_key|admin_pass'

# Firmware static analysis: confirm no-TLS broker is baked into the base image
ssh root@192.168.2.1 'dd if=/dev/mmcblk0p2 bs=4M count=32 2>/dev/null' > p2_sample.img
binwalk -e -M p2_sample.img
grep -E "^Package: mosquitto-nossl" _p2_sample.img.extracted/squashfs-root/usr/lib/opkg/status
# -> Package: mosquitto-nossl
grep -E "^#.*tls|listener.*8883|^port" _p2_sample.img.extracted/squashfs-root/etc/mosquitto/mosquitto.conf | head
# No TLS listener configured; default plaintext port 1883 is used.
# Cleartext device/network metadata in base UCI config:
cat _p2_sample.img.extracted/squashfs-root/etc/config/vulnzoo
# -> option control_plane_ip '192.168.2.1'
# -> option device_ip '192.168.2.100'
# -> option api_port '8080'
```

## Expected Result

Captured traffic shows command payloads in cleartext on all four channels, and `uci show octobot` reveals the API key and admin password unencrypted.

## How It Should Be

Encrypt every channel (TLS for HTTP/MQTT, stunnel for Modbus, an authenticated encrypted bus) and stop storing cleartext secrets. Keep only salted hashes or references to a secret store, never the raw values, in config.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Transport | TLS on HTTP/MQTT, stunnel on Modbus | End cleartext on the wire |
| Storage | Salted hashes / secret store | No cleartext secrets at rest |
| Bus | Authenticated encrypted serial channel | Protect the control path |

## Verification Checklist

- [ ] `tcpdump` reveals cleartext commands on `:8090` / `:2000` / `:502` / `:1883`
- [ ] `uci show octobot` exposes `api_key` and `admin_pass` in cleartext
- [ ] Binwalk extraction of `mmcblk0p2` shows `Package: mosquitto-nossl` in the base image
- [ ] Extracted `/etc/mosquitto/mosquitto.conf` has no TLS listener on `:8883`
- [ ] Extracted `/etc/config/vulnzoo` exposes control-plane and device IP in cleartext
