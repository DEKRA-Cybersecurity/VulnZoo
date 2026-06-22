---
id: IoT:I9
title: "Insecure Default Settings"
category: IoT
status: IN PROGRESS
severity: High
owasp: "IoT I9 - Insecure Default Settings"
cwe: "CWE-1188 (Insecure Default Initialization of Resource) / CWE-16 (Configuration)"
source_docs:
  - "src/docs/OctoBot/OPENWRT_INTEGRATION.md §3, §7 (IoT:I9)"
  - "stages/01_spec/output/octobot-spec.md"
  - "stages/02_implement/output/manifest.md"
affected_components:
  - "labs/octobot/files/usr/lib/vulnzoo-hooks/profile-init.d/70-octobot-firewall.sh"
  - "labs/octobot/files/opt/octobot/octobot_gateway.py"
  - "labs/octobot/files/etc/config/octobot"
verified_date: ""
---

## Why It Matters

OctoBot ships in its most exposed state by default. The firewall is permissive, every service binds all interfaces, the operator account is `admin/admin`, and the config defaults to `mode 'vulnerable'`. A unit deployed as-is is fully open on the LAN with no operator action, which is exactly how many real devices arrive and are never re-configured.

## Root Cause

The firewall hook opens every OT port to the LAN by default:

```sh
# labs/octobot/files/usr/lib/vulnzoo-hooks/profile-init.d/70-octobot-firewall.sh
# [IoT:I9] all OT ports reachable from the flat LAN, no segmentation.
add_rule gateway   "$(uci -q get octobot.main.http_port)"
add_rule serialbus "$(uci -q get octobot.main.bus_port)"
add_rule modbus    "$(uci -q get octobot.main.modbus_port)"
add_rule mqtt 1883
```

Services bind `0.0.0.0`, and the shipped config defaults to the vulnerable mode with default credentials:

```
# labs/octobot/files/etc/config/octobot
	option mode 'vulnerable'
	option admin_user 'admin'
	option admin_pass 'admin'
```

The base image also retains default LuCI/AP settings, which compound the exposure.

## Steps to Reproduce

```bash
# Default mode + permissive firewall
uci get octobot.main.mode                 # -> vulnerable
uci show firewall | grep octobot          # -> ACCEPT rules for 8090/2000/502/1883 from lan
ss -tlnp | grep -E '8090|2000|502'        # -> bound on 0.0.0.0

# Default credentials work out of the box
curl -s -X POST http://192.168.2.1:8090/login -d 'user=admin&pass=admin'   # -> {"ok": true}
```

## Expected Result

Out of the box the firewall accepts all OT ports from the LAN, services listen on all interfaces, `mode` is `vulnerable`, and `admin/admin` authenticates.

## How It Should Be

Ship secure-by-default: deny-by-default firewall, services bound to the management interface only, forced credential change on first boot, and `mode` defaulting to `secure`. Any exposure should be an explicit opt-in, not the shipped state.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Firewall | Deny-by-default, allow via jump host | No blanket LAN exposure |
| Bind | Management interface only | Shrink the listen surface |
| Defaults | `mode=secure`, forced password set | Secure out of the box |

## Verification Checklist

- [ ] `uci get octobot.main.mode` is `vulnerable` by default
- [ ] Firewall accepts all OT ports from the LAN by default
- [ ] Services bind `0.0.0.0`
- [ ] `admin/admin` works with no prior configuration
