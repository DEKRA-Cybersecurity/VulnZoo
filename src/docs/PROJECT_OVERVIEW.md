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
| cloud_api | C2 Server | 5000 | HTTP |
| cloud_api | MQTT Broker | 1883 | MQTT |

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
