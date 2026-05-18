# VulnZoo - Device Manager (Layer 2)

**Stage Purpose**: Deploy the base system and device manager for switching between IoT lab environments.

## Inputs

| Layer | Source Path | Role/Description |
|-------|-------------|------------------|
| **Layer 3** | `../../docs/` | System architecture, hook system docs |
| **Layer 4** | `files/www/` | Web interface (HTML/JS) |
| **Layer 4** | `files/usr/lib/vulnzoo-hooks/` | Hook framework |
| **Layer 4** | `files/etc/config/vulnzoo` | UCI device tracking |
| **Layer 4** | `files/etc/init.d/vulnzoo` | Device manager service |

## Process

### 1. Analyze Requirements
- Web interface for lab selection
- Hook-based initialization system
- Device switching capability
- Base system for other labs

### 2. Apply Constraints
- Web interface on port 8080
- Hook directory: `/usr/lib/vulnzoo-hooks/profile-init.d/`
- UCI config tracks loaded device
- Labs deployed as .tar.gz overlays

### 3. Transform (Deployment Steps)
1. Install base web interface files
2. Set up hook framework directories
3. Create UCI config structure
4. Enable vulnzoo service (init.d)
5. Configure uhttpd for port 8080

### 4. Refine
- Verify web interface accessible
- Test device switching workflow
- Validate hook execution order

## Outputs

| Artifact | Path | Description |
|----------|------|-------------|
| Web UI | `:8080` | Device manager interface |
| Hooks | `/usr/lib/vulnzoo-hooks/` | Init framework |
| Config | `/etc/config/vulnzoo` | Device state |
| Service | `/etc/init.d/vulnzoo` | Manager daemon |

## Verification

- [ ] Manager loads at `http://192.168.2.1:8080`
- [ ] Device selection works
- [ ] Hook execution runs in order
- [ ] Lab switching functions correctly

## Architecture

```
User → Web UI (:8080) → Device Selection
                              ↓
                     Extract lab.tar.gz
                              ↓
                    Run hooks (05-99)
                              ↓
                       Lab Active
```

## Dependencies

- Platform: OpenWRT v24.10.2
- Web: uhttpd
- Backend: Shell scripts + UCI
- Requires: Other lab packages in `/releases/`
