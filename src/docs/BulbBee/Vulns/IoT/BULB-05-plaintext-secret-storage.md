---
id: BULB-05
title: "Secrets in world-readable plaintext config (WiFi PSK, cloud token)"
category: IoT
status: IN PROGRESS
severity: Medium
owasp: "OWASP IoT Top 10 (2018) I7 - Insecure Data Transfer and Storage"
standard: "ETSI EN 303 645 5.4 (securely store sensitive security parameters)"
regulation: "CRA (EU) 2024/2847 Annex I Part I - protect stored data"
cwe: "CWE-312 (Cleartext Storage of Sensitive Information) / CWE-256 (Plaintext Storage of a Password)"
source_docs:
  - "stages/01_spec/output/bulbbee-05-spec.md"
affected_components:
  - "labs/bulbbee/files/opt/bulbbee/ble_light.py"
  - "labs/bulbbee/files/opt/bulbbee/config.json"
verified_date: "2026-09-04"
---

## Why It Matters

The security-sensitive parameters the bulb holds are stored in cleartext with no protection. The home WiFi PSK and the cloud pairing token land in `/tmp/bulbbee/provisioning.json` in plaintext, written by the BULB-01 provisioning path, and the hardcoded provisioning PIN sits in `/opt/bulbbee/config.json`. None are encrypted and none carry a restrictive file mode, so any local process reads them, and they are returned over the unauthenticated read surfaces (the BLE Config characteristic and `GET /config`, BULB-02). An attacker who reaches the device, over the onboarding weakness (BULB-01), the unauthenticated read (BULB-02), or an SSH foothold from the unsigned update (BULB-04), walks away with the home network credentials.

## Root Cause

The provisioning state is persisted as plain JSON with no encryption and no restrictive mode:

```python
# ble_light.py
def _save_prov_state():
    with open(PROV_STATE_FILE, "w") as f:                 # /tmp/bulbbee/provisioning.json
        json.dump({k: _prov_state[k] for k in
                   ("wifi_ssid", "wifi_psk", "cloud_url", "pair_token")}, f)  # cleartext
```

and the WiFi PSK is returned over the BLE Config read:

```python
def _prov_read() -> dict:
    ...
    return {"wifi_ssid": ..., "wifi_psk": _prov_state["wifi_psk"], "cloud_url": ...}  # cleartext
```

`config.json` additionally stores `prov_pin` in cleartext and is returned whole by `GET /config`.

## Steps to Reproduce

```sh
# on the device (or via any local process, SSH foothold, etc.)
cat /tmp/bulbbee/provisioning.json     # {"wifi_ssid":"home","wifi_psk":"<cleartext>","pair_token":"<cleartext>",...}
cat /opt/bulbbee/config.json           # prov_pin in cleartext

# remotely, over the unauthenticated reads (BULB-02)
curl http://192.168.2.1:8082/config    # discloses prov_pin
# and the BLE Config characteristic 0xFF42 returns wifi_psk in cleartext after the weak PIN gate
```

## Expected Result

The WiFi PSK and cloud token are readable in cleartext both on disk (world-readable file) and over the unauthenticated read surfaces.

## How It Should Be

- Store secrets encrypted at rest (a device-bound key), or write-only so they are never read back.
- Set a restrictive file mode (`0600`, owned by the service user) on any secret file.
- Never return secrets over a read API, and split the config into a public status view and an authenticated sensitive view (BULB-02 fix).

These land behind the `secure` UCI toggle (BULB-SEC).

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Device (storage) | Encrypt secrets at rest with a device-bound key, or keep them write-only | Cleartext-at-rest removed (CWE-312 / CWE-256) |
| Device (fs) | `0600` mode on secret files | No world-readable secret |
| Device (API) | Do not return secrets over any read | Close the disclosure (chains BULB-02) |

## Verification Checklist

- [ ] `provisioning.json` contains the PSK and token in cleartext after provisioning.
- [ ] The secret file is world-readable (default mode, no restrictive chmod).
- [ ] The BLE Config read returns the PSK in cleartext.
- [ ] In `secure` mode secrets are encrypted / not returned and the file is `0600` (BULB-SEC).
