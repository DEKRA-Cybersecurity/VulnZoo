---
id: IoT:I8
title: "Lack of Device Management"
category: IoT
status: IN PROGRESS
severity: Medium
owasp: "IoT I8 - Lack of Device Management"
cwe: "CWE-778 (Insufficient Logging) / CWE-770 (Allocation of Resources Without Limits or Throttling)"
source_docs:
  - "src/docs/OctoBot/OPENWRT_INTEGRATION.md §7 (IoT:I8)"
  - "stages/01_spec/output/octobot-spec.md"
  - "stages/02_implement/output/manifest.md"
affected_components:
  - "labs/octobot/files/opt/octobot/octobot_gateway.py"
verified_date: ""
---

## Why It Matters

The gateway has no operational management controls: no rate limiting, no lockout, no alerting, and no way to revoke access. An attacker can hammer the actuator as fast as the network allows, and nothing throttles, blocks, or raises an alarm. For an actuator this is also a safety issue, since unbounded command rates drive servos continuously and can overheat or wear the mechanism.

## Root Cause

The movement endpoint has no throttle, counter, or lockout. Every request is serviced and forwarded:

```python
# labs/octobot/files/opt/octobot/octobot_gateway.py
@app.route('/api/move')                     # [IoT:I3] no auth, [IoT:I8] no rate limit
def move():
    ...
    bus_send(f'S{servo}:{angle}')
```

There is no per-client counter, no `429` path, no anomaly alert, and no access-revocation mechanism anywhere in the gateway. The only record is the append-only operator log (see IoT:I6), which is not monitored.

## Steps to Reproduce

```bash
# Flood the actuator; observe no throttle, no lockout, no alert
for i in $(seq 1 2000); do
  curl -s "http://192.168.2.1:8090/api/move?servo=0&angle=$((RANDOM%180))" >/dev/null
done
# All requests succeed. No rate-limit response, no block, no alert is raised.
```

## Expected Result

Thousands of rapid commands all succeed with no throttling, no lockout, and no alert, and there is no mechanism to revoke the attacker's access.

## How It Should Be

Add per-client rate limiting and lockout on abuse, emit alerts on anomalous command rates to a monitored sink, and provide an access-revocation path (rotate/disable credentials, block a source). Bound the actuator command rate in the gateway as a safety control.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Rate limit | Per-client throttle + lockout | Stop flooding |
| Monitoring | Alert on anomalous rates to a SIEM | Detect abuse |
| Lifecycle | Credential rotation / revocation | Cut off a compromised client |

## Verification Checklist

- [ ] A flood of `/api/move` requests is never throttled or blocked
- [ ] No alert is raised on the command burst
- [ ] No access-revocation mechanism exists
