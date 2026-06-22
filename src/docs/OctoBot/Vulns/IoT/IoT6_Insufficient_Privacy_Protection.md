---
id: IoT:I6
title: "Insufficient Privacy Protection"
category: IoT
status: IN PROGRESS
severity: Medium
owasp: "IoT I6 - Insufficient Privacy Protection"
cwe: "CWE-359 (Exposure of Private Information) / CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"
source_docs:
  - "src/docs/OctoBot/OPENWRT_INTEGRATION.md §5, §7 (IoT:I6)"
  - "stages/01_spec/output/octobot-spec.md"
  - "stages/02_implement/output/manifest.md"
affected_components:
  - "labs/octobot/files/opt/octobot/octobot_gateway.py"
  - "labs/octobot/files/opt/octobot/serial_bus.py"
verified_date: ""
---

## Why It Matters

The gateway keeps an operator activity log (who issued which command, from which IP, and when) and serves it over an unauthenticated endpoint. In an operational setting this leaks the plant's activity pattern, the source addresses of operators, and the exact command history, which supports reconnaissance and operator profiling, all without a credential.

## Root Cause

The serial bus writes every command to a cleartext log:

```python
# labs/octobot/files/opt/octobot/serial_bus.py
with open(LOG_PATH, 'a') as f:                 # [IoT:I6] cleartext operator log
    f.write(f'{ts} {client} {cmd}\n')
```

The gateway then serves that log with no authentication:

```python
# labs/octobot/files/opt/octobot/octobot_gateway.py
@app.route('/logs')                         # [IoT:I6] operator history, no auth
def logs():
    body = open(LOG_PATH).read() if os.path.exists(LOG_PATH) else 'no logs'
    return body, 200, {'Content-Type': 'text/plain'}
```

## Steps to Reproduce

```bash
# A direct bus command logs the real client IP; then read the history with no credential
printf 'S3:0\n' | nc 192.168.2.1 2000
curl -s http://192.168.2.1:8090/logs
# -> 2026-06-18T12:15:40 192.168.2.50 S3:0
#    ... full command history with timestamps
# Note: commands relayed via the gateway / Modbus / MQTT log as 127.0.0.1, since
# those services are the bus client; only direct :2000 clients log a real remote IP.
```

## Expected Result

`GET /logs` returns the full command history with timestamps and no authentication, including the real source IP for any host that connected directly to the serial bus.

## How It Should Be

Restrict the log endpoint to authenticated administrators, minimize what is recorded (avoid storing source IPs longer than needed), and apply a retention policy. Treat operator activity as sensitive and protect it at rest and in transit.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Auth | Admin-only access to `/logs` | No anonymous history read |
| Minimization | Record only what is needed, with retention | Reduce exposure |
| Transport | TLS for the management plane | Protect logs in transit |

## Verification Checklist

- [ ] `GET /logs` returns the command history with no auth
- [ ] Entries include timestamp and command (and the real source IP for direct-bus clients)
