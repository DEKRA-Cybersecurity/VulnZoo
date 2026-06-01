# Labs - Laboratory Build & Deployment Stage (Layer 2)

> **⚠️ LAYER 2 STAGE CONTRACT**
> 
> This document defines the laboratory build and deployment workflow for the VulnZoo platform.
> 
> **Navigation:** Read this file when building, modifying, or deploying VulnZoo laboratories.
> 
> **Parent Context:** [../AGENTS.md](../AGENTS.md) (Layer 0) → [../CLAUDE.md](../CLAUDE.md)/[../KIMI.md](../KIMI.md) (Layer 1) → **this file** (Layer 2)

> **⚠️ NOTE FOR AI AGENTS — MWP context tree:**
> 
> Before doing any analysis or development on the labs, walk the markdown tree
> following the links from the root:
> 
> ```
> CLAUDE.md (Layer 1, Claude entry)
>   └─→ AGENTS.md (Layer 0, global identity + routing table)
>         └─→ MWP_README.md (layer methodology)
>               └─→ labs/CONTEXT.md (this file, build & deploy)
>                     └─→ labs/<device>/CONTEXT.md (lab-specific contract)
>                           └─→ docs/<device>/ (reference documentation)
> ```
> 
> The entry point for Claude is always `CLAUDE.md`. Do not assume paths or behaviors
> without having read the full chain for the lab you are going to modify.

---

## Stage Purpose

Build and deploy vulnerable IoT device simulations (labs) for cybersecurity training. This stage handles:
- Compiling OpenWRT base images with Device Manager
- Packaging individual lab overlays as compressed archives
- Deploying labs to Raspberry Pi through real-time filesystem transformation

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     BUILD PHASE (Host PC)                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  labs/vulnzoo/files/          ← Base OpenWRT overlay (always)   │
│  ├── usr/lib/vulnzoo-hooks/     Hook framework                  │
│  ├── www/                       Device Manager Web UI           │
│  └── usr/lib/vulnzoo-devices/   ← Lab packages (.tar.gz)        │
│       ├── careotter.tar.gz      Medical device lab              │
│       ├── routcoon.tar.gz       Router lab                      │
│       ├── owlcam.tar.gz         Camera lab                      │
│       └── ...                                                   │
│                                                                  │
│  releases/build.sh              OpenWRT compilation script      │
│  └── Produces: openwrt-vulnzoo.img.gz                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                               ↓
                    Flash to Raspberry Pi
                               ↓
┌─────────────────────────────────────────────────────────────────┐
│                  RUNTIME PHASE (Raspberry Pi)                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. BASE SYSTEM (always present)                                │
│     - Device Manager (port 8080)                                │
│     - Hook framework (/usr/lib/vulnzoo-hooks/)                  │
│     - Lab storage (/usr/lib/vulnzoo-devices/)                   │
│                                                                  │
│  2. LAB TRANSFORMATION (on-demand)                              │
│     User selects "careotter" → Extract careotter.tar.gz         │
│                                  ↓                              │
│     Root filesystem overwritten in real-time:                   │
│     - /opt/medical-sensor/        Service files                 │
│     - /etc/config/                UCI configurations            │
│     - /etc/init.d/                Service init scripts          │
│     - /usr/lib/vulnzoo-hooks/     Lab-specific hooks            │
│                                                                  │
│     Result: Pi "transforms" into CareOtter medical device       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Inputs

| Layer | Source Path | Role/Description |
|-------|-------------|------------------|
| **Layer 3** | `../docs/` | Architecture diagrams, vulnerability specs |
| **Layer 3** | `../releases/build.sh` | OpenWRT image builder |
| **Layer 4** | `vulnzoo/files/` | Base OpenWRT overlay (Device Manager) |
| **Layer 4** | `<device>/files/` | Lab-specific file overlays |
| **Layer 4** | `<device>/hooks/` | Lab initialization scripts |

## Process

### 1. Build Base Image (One-time)

```bash
cd ../releases
./build.sh vulnzoo

# This:
# 1. Takes labs/vulnzoo/files/ as base overlay
# 2. Compiles OpenWRT with packages
# 3. Produces: openwrt-vulnzoo-<target>.img.gz
```

**Key files in base overlay:**
```
 labs/vulnzoo/files/
 ├── etc/
 │   ├── config/vulnzoo           # UCI: tracks current lab
 │   └── init.d/vulnzoo           # Init: Device Manager service
 ├── usr/
 │   ├── lib/vulnzoo-hooks/       # Hook execution framework
 │   │   └── profile-init.d/      # Hook scripts (##-name.sh)
 │   └── lib/vulnzoo-devices/     # Lab packages (.tar.gz)
 └── www/vulnzoo                  # Web UI (Device Manager)
```

### 2. Package Individual Labs

Each lab is packaged as a `.tar.gz` archive following this three-step workflow:

**Step 1 — Edit the lab's source files**

All changes are made inside `labs/<device>/files/`. This folder is the overlay
tree that is extracted onto the Raspberry Pi's root filesystem at deploy time.

```
labs/careotter/files/
├── etc/            ← UCI configs, init.d, logrotate
├── opt/            ← Python services, C binaries
└── usr/            ← initialization hooks
```

> **Important:** `labs/<device>/files/` may also contain a leftover `careotter.tar.gz`
> from previous builds. This file must NOT be included in the package.

**Step 2 — Generate the tar.gz from the overlay subdirectories**

```bash
cd labs/careotter/files
tar -cvzf careotter.tar.gz opt etc usr
# The resulting tar.gz contains only the overlay directories (not itself)
```

**Step 3 — Move the package to vulnzoo's devices directory**

```bash
mv labs/careotter/files/careotter.tar.gz \
   labs/vulnzoo/files/usr/lib/vulnzoo-devices/careotter.tar.gz
```

The file in `labs/vulnzoo/files/usr/lib/vulnzoo-devices/` is the one bundled into
the compiled OpenWRT image and the one the Device Manager extracts at runtime.

**Lab package structure:**
```
careotter.tar.gz
├── opt/careotter/               # C binary of the admin service (careservice)
├── opt/medical-sensor/          # Python services
│   ├── sensor_service.py
│   ├── ble_server.py
│   └── simulator.py
├── etc/config/                  # UCI configuration
├── etc/init.d/                  # OpenWRT init scripts
├── etc/logrotate.d/             # logrotate configuration
└── usr/lib/vulnzoo-hooks/profile-init.d/
    ├── 40-i2c.sh
    ├── 50-medical-sensor.sh
    ├── 55-ble-server.sh
    └── ...
```

### 3. Deploy Lab (Runtime Transformation)

When user selects lab via Device Manager (port 8080):

```bash
# 1. Extract lab package
tar -xzf /usr/lib/vulnzoo-devices/careotter.tar.gz -C /

# 2. Update UCI state
uci set vulnzoo.state.current_device=careotter
uci commit vulnzoo

# 3. Execute hooks in order
for hook in /usr/lib/vulnzoo-hooks/profile-init.d/##-*.sh; do
    $hook
done

# Result: Raspberry Pi now functions as CareOtter device
```

### 4. Switch Between Labs

```bash
# Reset to base
/etc/init.d/vulnzoo reset

# Load new lab (automatic via web UI)
# or manually:
tar -xzf /usr/lib/vulnzoo-devices/routcoon.tar.gz -C /
/etc/init.d/vulnzoo reload
```

## Outputs

| Artifact | Path | Description |
|----------|------|-------------|
| Base Image | `releases/*.img.gz` | Flashable OpenWRT + Device Manager |
| Lab Packages | `labs/vulnzoo/files/usr/lib/vulnzoo-devices/*.tar.gz` | Compressed lab overlays |
| Active Lab | Raspberry Pi root fs | Real-time transformed system |
| Logs | `/root/vulnzoo.log` | Device switching history |

## Lab Directory Structure

```
labs/
├── CONTEXT.md                    # This file (Stage Contract)
├── vulnzoo/                      # Base system (Device Manager)
│   ├── files/                    # Base overlay
│   └── hooks/                    # Base hooks
├── careotter/                    # Medical device lab
│   ├── CONTEXT.md                # Lab-specific stage contract
│   └── files/                    # Lab overlay
├── routcoon/                     # Router lab
│   ├── CONTEXT.md
│   └── files/
└── owlcam/                       # Camera lab
    ├── CONTEXT.md
    └── files/
```

## Key Conventions

| Element | Convention | Example |
|---------|------------|---------|
| **Lab folder** | lowercase | `careotter/` |
| **Package name** | `<labname>.tar.gz` | `careotter.tar.gz` |
| **Hooks** | `##-descriptive-name.sh` | `50-medical-sensor.sh` |
| **Init scripts** | `/etc/init.d/<name>` | `/etc/init.d/medical-sensor` |
| **UCI configs** | `/etc/config/<name>` | `/etc/config/careotter` |

## Hook Execution Order

Hooks run sequentially during lab transformation:

| Order | Hook | Purpose |
|-------|------|---------|
| 05 | `5-preflight.sh` | System checks |
| 10 | `10-database.sh` | Database setup |
| 15 | `15-python-deps.sh` | Python packages |
| 20 | `20-bluetooth.sh` | BLE adapter config |
| 30 | `30-security-policy.sh` | Security rules |
| 40 | `40-i2c.sh` | I2C bus setup |
| 50 | `50-medical-sensor.sh` | Start sensor service |
| 55 | `55-ble-server.sh` | Start BLE GATT |
| 60 | `60-cron.sh` | Log rotation |

## Verification

### Build Phase Checklist
- [ ] Base overlay in `vulnzoo/files/` is complete
- [ ] Lab packages (`.tar.gz`) exist in `vulnzoo/files/usr/lib/vulnzoo-devices/`
- [ ] Each lab has valid `CONTEXT.md`
- [ ] OpenWRT image compiles without errors
- [ ] Image boots on Raspberry Pi

### Runtime Phase Checklist
- [ ] Device Manager accessible on port 8080
- [ ] Lab selection works via web UI
- [ ] Lab package extracts without errors
- [ ] Hooks execute in correct order
- [ ] Services start and respond on expected ports
- [ ] Log file `/root/vulnzoo.log` shows success

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| Lab won't load | Corrupt `.tar.gz` | Repackage: `make package` in lab folder |
| Hooks don't run | Wrong permissions | `chmod +x /usr/lib/vulnzoo-hooks/profile-init.d/*.sh` |
| Services fail | Missing dependencies | Check `15-python-deps.sh` output |
| UCI error | Config syntax | Validate with `uci show` |
| Can't switch labs | Previous lab remnants | Run `/etc/init.d/vulnzoo reset` |

## References

- Layer 0: [../AGENTS.md](../AGENTS.md) - Global identity and task routing
- Layer 1: [../KIMI.md](../KIMI.md) or [../CLAUDE.md](../CLAUDE.md) - Agent-specific routing
- MWP Guide: [../MWP_README.md](../MWP_README.md) - Methodology documentation
- Lab specifics: `labs/<device>/CONTEXT.md` - Individual lab contracts
