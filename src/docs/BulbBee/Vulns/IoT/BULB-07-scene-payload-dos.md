---
id: BULB-07
title: "Scene-payload denial of service (unbounded LED count)"
category: IoT
status: IN PROGRESS
severity: Medium
owasp: "OWASP IoT Top 10 (2018) I2 - Insecure Network Services"
standard: "ETSI EN 303 645 5.9 (resilient to outages), 5.13 (validate input data)"
regulation: "CRA (EU) 2024/2847 Annex I Part I(3)(k) - resilience to denial of service"
cwe: "CWE-400 (Uncontrolled Resource Consumption) / CWE-1284 (Improper Validation of Specified Quantity in Input) / CWE-190 (Integer Overflow or Wraparound)"
source_docs:
  - "stages/01_spec/output/bulbbee-07-spec.md"
affected_components:
  - "labs/bulbbee/files/opt/bulbbee/lighting_service.py"
verified_date: "2026-09-04"
---

## Why It Matters

A crafted scene payload with an unbounded LED count makes the lighting service allocate a frame buffer proportional to an attacker-supplied number, with no upper bound. A large enough count exhausts memory and hangs or kills the service, so the light stops responding. It is reachable unauthenticated over the same control surface as BULB-02, and it is the CRA resilience-to-denial-of-service essential requirement made concrete on the WS2812 buffer.

## Root Cause

The `custom` scene builds a list of `count` pixels from the request with no bound check:

```python
# lighting_service.py
if name == "custom":
    count = int(payload.get("count", self.led_count))   # no upper bound (CWE-1284 / CWE-190)
    color = tuple(payload.get("color") or self.state["color"])
    self.dev.show([color] * count)                      # allocates N tuples -> CWE-400
```

The driver later truncates to `led_count`, but the oversized list is already built in the request-handling thread, so the memory is consumed before truncation. There is no validation that `count` is within a sane range.

## Steps to Reproduce

```sh
# a moderate count shows the allocation is proportional and unbounded-by-design
curl -X POST http://192.168.2.1:8082/scene -d '{"scene":"custom","count":2000000,"color":[255,0,0]}'

# the denial of service: a huge count exhausts memory and hangs / kills the service
curl -X POST http://192.168.2.1:8082/scene -d '{"scene":"custom","count":1000000000}'
# -> the service stops responding (do not run against a shared host)
```

## Expected Result

`POST /scene` with a `custom` scene and a large `count` is accepted with no bound check, and a sufficiently large `count` exhausts memory and stops the service. Normal scenes are unaffected.

## How It Should Be

- Clamp `count` to `led_count` (or a small hard maximum) and reject oversized inputs with a 400.
- Validate all quantities from the network before allocating.

These land behind the `secure` UCI toggle (BULB-SEC).

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Device (parser) | Clamp `count` to a sane maximum, reject oversize | Bounded allocation (CWE-1284 / CWE-400) |
| Device (input) | Validate all network-supplied quantities | Input validation (ETSI EN 303 645 5.13) |

## Verification Checklist

- [ ] `POST /scene {"scene":"custom","count":N}` is accepted with no bound check on `N`.
- [ ] No quantity validation exists in the path (inspection).
- [ ] Normal scenes (`solid`, `rainbow`) still work.
- [ ] In `secure` mode `count` is clamped and oversize payloads are rejected (BULB-SEC).
