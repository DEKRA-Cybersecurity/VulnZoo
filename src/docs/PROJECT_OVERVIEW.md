# VulnZoo Project Overview

**VulnZoo** — An open-source ecosystem of vulnerable IoT devices for cybersecurity training in embedded, medical, industrial and automotive environments.

## Tech Stack

| Component | Technology |
|-----------|------------|
| **Firmware Platform** | OpenWRT v24.10.2 (Linux-based for embedded) |
| **Base Hardware** | Raspberry Pi 3B/3B+/4 |
| **Backend Services** | Python (Flask/FastAPI), Lua (LUCI/OpenWRT) |
| **Frontend** | HTML/JavaScript (Device Manager), Lua/LUCI (Router) |
| **Mobile** | Android/iOS companion apps (Flutter) |
| **Cloud API** | Docker containers (Python/FastAPI) |
| **Database** | SQLite (local), optionally external APIs |
| **Communication** | BLE (BlueZ/bleak), HTTP/REST, MQTT, CAN bus |

## Network Configuration

- **Raspberry Pi:** 192.168.2.1 (fixed)
- **User PC:** 192.168.2.x (DHCP or static)
- **Connection:** Direct Ethernet cable
- **Cloud API:** Docker on user PC (192.168.2.x:5000)

## Service Ports

| Lab | Service | Port | Protocol |
|-----|---------|------|----------|
| vulnzoo | Device Manager | 8080 | HTTP |
| routcoon | LUCI Admin | 80 | HTTP |
| owlcam | RTSP Stream | 8554 | RTSP |
| owlcam | Camera API | 5000 | HTTP |
| careotter | Sensor API | 8081 | HTTP |
| careotter | BLE GATT | - | Bluetooth LE |
| octobot | Gateway HMI / REST | 8090 | HTTP |
| octobot | ser2net serial bridge | 2000 | TCP |
| octobot | Modbus/TCP | 502 | TCP |
| octobot | Cloud API (PC) | 5003 | HTTP |
| canary | SOME/IP CentralLockingService | 30509 | UDP |
| canary | CAN bus (can0/can1) | - | CAN |
| cloud_api | C2 Server | 5000 | HTTP |
| cloud_api | MQTT Broker | 1883 | MQTT |

## Troubleshooting

### SSH host key changes after `firstboot`

After running `firstboot` (or a factory reset) on the Pi and rebooting, the next `ssh root@192.168.2.1` fails with `REMOTE HOST IDENTIFICATION HAS CHANGED` and refuses to connect. This is expected behaviour, not a man-in-the-middle attack.

**Cause.** `firstboot` erases the OpenWRT overlay (`/overlay`). On OpenWRT `/etc` is an overlay mounted over the read-only Squashfs, and the dropbear SSH host keys live in `/etc/dropbear/` inside that overlay. The reset wipes them, so on the next boot dropbear generates brand new host keys. The new fingerprint no longer matches the one your client pinned in `~/.ssh/known_hosts`, and with strict host-key checking the client refuses the connection. Because the VulnZoo image does not ship persistent host keys, this repeats on every reset.

**Option A (client side, recommended for frequent resets).** Tell your SSH client not to pin the lab host. Add to `~/.ssh/config`:

```
Host 192.168.2.1
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
```

The client then accepts the Pi's current key without saving or comparing it, so the warning never appears again. As a one-off you can instead drop the stale entry with `ssh-keygen -R 192.168.2.1` after each reset.

**Option B (image side, stable fingerprint for everyone).** Bake fixed dropbear host keys into the base image at `src/labs/vulnzoo/files/etc/dropbear/` (`dropbear_ed25519_host_key` and `dropbear_rsa_host_key`). Living in the read-only Squashfs they survive `firstboot`, so dropbear reuses them instead of regenerating and the fingerprint stays constant across resets. The trade-off is that every deployed Pi then shares the same host key, which is acceptable for a lab image but is a real key committed to the repository.

## Regulatory Context

VulnZoo aligns with:
- EU Cyber Resilience Act (CRA)
- NIS2 Directive
- RED DA
- US Cyber Trust Mark
- IEC 62443 (Industrial security)
- ISO/SAE 21434 (Automotive)
- ETSI EN 303 645 (IoT security)

## Important Notes

- **Purpose:** Educational and research only. Do not use on real systems without authorization.
- **Vulnerabilities:** Intentionally introduced for training. Each lab has documented attack chains.
- **Hardware support:** Optional (sensors, servo motors, CAN modules) but labs work without them.
- **Target:** OWASP donation candidate for neutral governance.

## Model Workspace Protocol

This project follows the **Model Workspace Protocol (MWP)** for agent context management:

| Layer | File | Purpose |
|-------|------|---------|
| Layer 0 | `AGENTS.md` | Global identity + routing table |
| Layer 1 | `CLAUDE.md` / `KIMI.md` | Per-agent entry points (thin routers → `AGENTS.md`) |
| Layer 2 | `<component>/CONTEXT.md`, `labs/<device>/CONTEXT.md` | Stage-specific contracts |
| Layer 3 | `docs/` | Reference documentation |

Layer 0/1 files live at the `src/` root. See [`../MWP_README.md`](../MWP_README.md) (condensed) or [`../../MWP.md`](../../MWP.md) (full paper) for MWP details.
