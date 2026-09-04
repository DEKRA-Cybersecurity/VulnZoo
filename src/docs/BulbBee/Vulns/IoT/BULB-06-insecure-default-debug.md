---
id: BULB-06
title: "Insecure default settings / exposed debug surface"
category: IoT
status: IN PROGRESS
severity: Medium
owasp: "OWASP IoT Top 10 (2018) I9 - Insecure Default Settings"
standard: "ETSI EN 303 645 5.6 (minimise exposed attack surfaces)"
regulation: "CRA (EU) 2024/2847 Annex I Part I - secure by default"
cwe: "CWE-1188 (Insecure Default Initialization) / CWE-489 (Active Debug Code)"
source_docs:
  - "stages/01_spec/output/bulbbee-06-spec.md"
affected_components:
  - "labs/bulbbee/files/opt/bulbbee/lighting_service.py"
  - "labs/bulbbee/files/opt/bulbbee/config.json"
verified_date: "2026-09-04"
---

## Why It Matters

The bulb ships with a diagnostic endpoint enabled by default. `GET /debug` returns a rich dump to any unauthenticated caller: the running config (including `prov_pin`), the provisioning state (including the WiFi PSK and cloud token), the current lighting state, and a slice of the process environment. The weakness is the insecure default, `debug` is `true` out of the box, so a surface that should never exist on a production unit is live on every device. It also collapses BULB-02 (unauthenticated read) and BULB-05 (secret storage) into a single one-request dump of everything sensitive the device holds.

## Root Cause

The debug surface is gated by a config flag that defaults on:

```python
# config.json
"debug": true

# lighting_service.py
elif self.path == "/debug":
    if not c.cfg.get("debug", True):        # defaults ON, ships enabled
        self._send(404, {"error": "not found"})
    else:
        prov = _read_provisioning()          # wifi_psk, pair_token
        self._send(200, {"config": c.cfg,    # prov_pin
                         "provisioning": prov,
                         "state": c.get_state(),
                         "env": {...}})
```

The missing control is a secure default: debug surfaces must be off unless explicitly enabled for development, and never expose secrets.

## Steps to Reproduce

```sh
curl http://192.168.2.1:8082/debug     # unauthenticated, shipped enabled
# -> {"config": {... "prov_pin":"8080" ...},
#     "provisioning": {"wifi_psk":"...", "pair_token":"..."},
#     "state": {...}, "env": {...}}
```

## Expected Result

`GET /debug` returns the full diagnostic dump, including `prov_pin` and the provisioning secrets, with no authentication, because `debug` ships `true`.

## How It Should Be

- Default `debug` to off, and require an explicit, authenticated opt-in to enable it.
- Never include secrets (PSK, token, PIN) in any diagnostic output.
- Remove the debug surface from production images entirely (build-time flag).

These land behind the `secure` UCI toggle (BULB-SEC), which ships `debug=false`.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Device (default) | `debug` off by default | Secure default (CWE-1188) |
| Device (debug) | No secrets in diagnostic output | Contain the disclosure |
| Build | Strip the debug surface from production images | Remove active debug code (CWE-489) |

## Verification Checklist

- [ ] `GET /debug` returns the diagnostic dump (config + secrets) with the shipped default.
- [ ] With `debug=false` the endpoint is disabled (404).
- [ ] In `secure` mode `debug` defaults off (BULB-SEC).
