---
id: IoT:I1
title: "Weak, Guessable, or Hardcoded Passwords"
category: IoT
status: IN PROGRESS
severity: High
owasp: "IoT I1 - Weak, Guessable, or Hardcoded Passwords"
cwe: "CWE-798 (Use of Hard-coded Credentials) / CWE-1392 (Use of Default Credentials)"
source_docs:
  - "src/docs/OctoBot/OPENWRT_INTEGRATION.md §7 (IoT:I1)"
  - "stages/01_spec/output/octobot-spec.md"
  - "stages/02_implement/output/manifest.md"
affected_components:
  - "labs/octobot/files/opt/octobot/octobot_gateway.py"
  - "labs/octobot/files/etc/config/octobot"
verified_date: ""
---

## Why It Matters

The OctoBot HMI gateway is the operator entry point to a physical robot arm. It ships with the credential `admin/admin` and a hardcoded API key baked into the gateway source. Anyone who reaches the gateway, or who reads the lab overlay, owns the operator interface with no guessing. The key is identical on every deployment, cannot be rotated from the interface, and is duplicated in the UCI config in cleartext, so a single disclosure compromises the whole fleet and grants the ability to move real hardware.

## Root Cause

```python
# labs/octobot/files/opt/octobot/octobot_gateway.py
USERS   = {'admin': 'admin'}                  # [IoT:I1] default credentials
API_KEY = 'octobot-industrial-2020'           # [IoT:I1] hardcoded key, never rotated
```

The same values are duplicated in cleartext in the UCI config:

```
# labs/octobot/files/etc/config/octobot
	option api_key 'octobot-industrial-2020'
	option admin_user 'admin'
	option admin_pass 'admin'
```

There is no per-device derivation, no hashing, and no rotation path. The credential is a compile-time constant in plain Python, recoverable with `cat`, `strings`, or by reading the extracted overlay.

## Steps to Reproduce

```bash
# 1. Default credentials accepted
curl -s -X POST http://192.168.2.1:8090/login -d 'user=admin&pass=admin'
# -> {"ok": true}

# 2. Hardcoded key recoverable from the shipped overlay
grep -n "API_KEY" /opt/octobot/octobot_gateway.py
uci show octobot | grep -E 'api_key|admin_pass'
```

## Expected Result

`/login` returns `{"ok": true}` for `admin/admin`, and the API key plus admin password appear in plaintext in both the gateway script and `uci show octobot`.

## How It Should Be

Remove default credentials and force a first-boot password set. Derive any device secret at runtime from a hardware-bound value (eFuse / serial) via a KDF so no static key is shipped, and store only a salted hash, never a cleartext password, in config.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Provisioning | First-boot forced password change | Eliminate `admin/admin` |
| Firmware | Derive key from hardware secret (HKDF) | No static key in the image |
| Config | Store salted hash, never cleartext | Survive overlay disclosure |
| Auth | Per-device unique credentials | Contain a single leak to one unit |

## Verification Checklist

- [ ] `POST /login user=admin&pass=admin` returns `{"ok": true}`
- [ ] `API_KEY` is readable in `octobot_gateway.py`
- [ ] `uci show octobot` exposes `api_key` and `admin_pass` in cleartext
