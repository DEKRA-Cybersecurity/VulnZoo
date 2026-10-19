---
id: BULB-06
title: "Insecure default settings / exposed debug surface"
category: IoT
status: DONE
severity: Medium
owasp: "OWASP IoT Top 10 (2018) I9 - Insecure Default Settings"
standard: "ETSI EN 303 645 5.6 (minimise exposed attack surfaces)"
regulation: "CRA (EU) 2024/2847 Annex I Part I - secure by default"
cwe: "CWE-1188 (Insecure Default Initialization) / CWE-489 (Active Debug Code)"
affected_components:
  - "labs/bulbbee/files/opt/bulbbee/lighting_service.py"
  - "labs/bulbbee/files/opt/bulbbee/config.json"
verified_date: "2026-10-19"
---

## Why It Matters

The bulb ships with a diagnostic endpoint enabled by default (`debug` is `true` out of the box), gated only by a discoverable diagnostic key. `GET /debug?diag=bulbbee-diag` answers any unauthenticated caller with device reconnaissance: the device serial (`device_id`), the firmware version, the MQTT command topic (`bulbbee/<serial>/cmd`) and uptime. The `diag` key is not a secret, it is a static string baked into the firmware (`lighting_service.py`), so it is recovered by reversing the image, not by guessing a credential. Without it the endpoint returns `404`, identical to an unknown path, so it no longer shows up in a naive path scan, which is the raised recon bar. No secrets cross it, the sensitive config (`prov_pin`), the WiFi PSK and the pairing token sit behind a device-bound session (`/config`, BULB-02/BULB-05), not here. The weakness is the insecure default, a production unit should not ship a live diagnostic surface keyed by one hardcoded string, and once that string is read from the firmware the endpoint hands an attacker the serial that seeds the per-device PIN derivation (BULB-01) and the topic that drives the cloud arm (BULB-CLD).

## Chain role

In the chained model (see [CHAINS.md](../CHAINS.md)) this finding is the reconnaissance link, recut to yield no secrets and gated behind a discoverable diag key.

- Yields: reconnaissance only, the device serial, the MQTT device id and command topic, and the firmware version.
- Consumes: network reachability, plus the firmware-baked `diag` key to open the HTTP path. The serial is also readable pre-auth over BLE (`0xFF41`, BULB-01), so the chain does not depend on this HTTP path, the key gate only adds a reversing step to the HTTP avenue.
- Unlocks: BULB-01 (serial for PIN derivation), BULB-CLD (topic), BULB-04 (version for a targeted payload).

## Root Cause

The debug surface ships enabled and is gated by a static, firmware-baked diag key:

```python
# config.json
"debug": true                      # ships enabled

# lighting_service.py
elif path == "/debug":
    diag = parse_qs(parts.query).get("diag", [""])[0]
    if not c.cfg.get("debug", True) or self._secure() \
       or diag != c.cfg.get("diag_key", "bulbbee-diag"):   # static key, baked in firmware
        self._send(404, {"error": "not found"})
    else:
        dev = self._device_id()                            # recon only, no secrets
        self._send(200, {"device_id": dev,
                         "version": c.cfg.get("fw_version", "bulbbee-1.0"),
                         "cmd_topic": "bulbbee/%s/cmd" % dev,
                         "uptime": int(time.time() - _START_TIME)})
```

The `diag` key raises the discovery bar but is not a control, it is one static string compiled into every unit, so firmware reversing recovers it once and it works on the whole fleet. The missing control is a secure default: diagnostic surfaces must be off unless explicitly enabled for development, and even then must not expose device identifiers that seed the rest of the chain.

## Steps to Reproduce

Default build: `/debug` is unauthenticated and shipped enabled, but it is gated by a discoverable diag key and returns reconnaissance only (serial, command topic, firmware version), no secrets. It is the one independent chain link, feeding the serial to BULB-01 and the command topic to the cloud arm. See [CHAINS.md](../CHAINS.md).

Direct hit, once the path and the `diag` key are known:

```sh
curl 'http://192.168.2.1:8082/debug?diag=bulbbee-diag'   # unauthenticated, key-gated
# -> {"device_id":"<serial>","version":"bulbbee-1.0",
#     "cmd_topic":"bulbbee/<serial>/cmd","uptime":<seconds>}

curl -s http://192.168.2.1:8082/debug                    # no key -> hidden
# -> {"error":"not found"}   (HTTP 404)
```

### Active endpoint discovery (fuzzing)

An assessor first fuzzes the path with a classic CLI fuzzer and a common web-content wordlist. The service answers `404 {"error":"not found"}` on an unknown path and `200` on a real one, so a status-code filter isolates the live routes cleanly.

ffuf, match on the 200 responses:

```sh
ffuf -u http://192.168.2.1:8082/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200 -t 40
# live GET routes: health, state, config
```

gobuster, whose default already hides the 404s so the hits are the live routes:

```sh
gobuster dir -u http://192.168.2.1:8082 \
  -w /usr/share/wordlists/dirb/common.txt --no-error
```

wfuzz, match on 200 (or `--hc 404` to hide the misses):

```sh
wfuzz -z file,/usr/share/seclists/Discovery/Web-Content/common.txt \
  --sc 200 http://192.168.2.1:8082/FUZZ
```

A GET fuzz surfaces `health`, `state` and `config`. `/debug` does not appear: without the `diag` key it answers `404`, identical to an unknown path, which is the raised recon bar (target BULB-06 hardening). A param fuzz against a guessed `/debug` (`-u .../debug?FUZZ=1`) also stays dark, because the gate checks the key's value, not the mere presence of a parameter. The control routes (`/set`, `/scene`, `/update`) are POST-only and answer `404` to a GET probe, so they stay hidden under a GET wordlist scan too (they are covered under BULB-02).

### Recovering the diag key (firmware reversing)

The `diag` key is one static string baked into the firmware, not a per-device secret, so it is recovered once from the lab image (the same firmware access the BULB-APP reversing track assumes) and then works on every unit:

```sh
# from the extracted device filesystem / tarball
grep -ern 'diag' opt/bulbbee/lighting_service.py
strings opt/bulbbee/lighting_service.py | grep -i diag
# -> diag != c.cfg.get("diag_key", "bulbbee-diag")
```

With the key in hand, the direct `curl` above returns the reconnaissance JSON.

### Recon payload

Past the gate the response is the reconnaissance-only JSON (`device_id`, firmware `version`, the MQTT `cmd_topic` and `uptime`), with no authentication, because `debug` ships `true` and the key is baked in the clear. No config, secrets or environment are included, those sit behind a device-bound session (`/config`, BULB-02/BULB-05). The captures below are from the pre-hardening baseline (a bare `GET /debug`), the payload is identical, only the request now carries the `diag` key.

![[bulb-06-fuzzing_http_service.png]]

![[bulb-06-curling-debug.png]]

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

- [x] Gate verified in-process (`python3 lighting_service.py --selfcheck`): `/debug` 404s with no key and with a wrong key, returns recon-only JSON with `?diag=bulbbee-diag`, and 404s in secure mode even with the key.
- [x] On hardware: `GET /debug?diag=bulbbee-diag` returns the recon-only JSON (`device_id`, `version`, `cmd_topic`, `uptime`), no secrets.
- [x] On hardware: `GET /debug` without the key returns 404.
- [ ] With `debug=false` the endpoint is disabled (404).
- [ ] In `secure` mode `debug` defaults off (BULB-SEC).
