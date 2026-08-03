---
id: IoT:I5
title: "Use of Insecure or Outdated Components"
category: IoT
status: DONE
severity: Medium
owasp: "IoT I5 - Use of Insecure or Outdated Components"
cwe: "CWE-1104 (Use of Unmaintained Third-Party Components) / CWE-1035 (Using Components with Known Vulnerabilities)"
source_docs:
  - "src/docs/OctoBot/OPENWRT_INTEGRATION.md §7 (IoT:I5)"
  - "stages/01_spec/output/octobot-spec.md"
  - "stages/02_implement/output/manifest.md"
affected_components:
  - "labs/octobot/files/opt/octobot/octobot_gateway.py"
  - "labs/octobot/files/usr/lib/vulnzoo-hooks/profile-init.d/15-octobot-python-deps.sh"
verified_date: "2026-08-03"
---

## Why It Matters

An IoT field gateway often runs a frozen software stack for years: an old web server, an outdated library, a stale framework. Each carries published CVEs an attacker can look up from a version banner. OctoBot ships exactly that. The Pi gateway runs its Flask app on the Werkzeug development server, which advertises its own version in the HTTP `Server` header, and the shipped Flask and Werkzeug packages are both years out of date with known CVEs. Reading the banner and mapping it to a CVE database is a one-request reconnaissance step.

## Shipped versions (live-confirmed)

The OpenWRT feed baked into the image ships outdated Python web packages, and `octobot_gateway.py` runs them via `app.run()` (the Werkzeug dev server). Confirmed on the running Pi:

| Component | Shipped version | Released | Current at time of writing |
|-----------|-----------------|----------|-----------------------------|
| Werkzeug | 2.3.6 | June 2023 | 3.x |
| Flask | 2.0.2 | October 2021 | 3.x |
| Python | 3.11.13 | current | - |

The Docker cloud API is separate and pins `flask==3.0.0`, so this finding is specific to the on-Pi gateway, not the cloud.

## Root Cause

The gateway starts the Werkzeug development server, which sets a version-disclosing `Server` header on every response:

```python
# labs/octobot/files/opt/octobot/octobot_gateway.py
if __name__ == '__main__':
    # [IoT:I9] binds all interfaces, [IoT:I7] plain HTTP, no TLS
    app.run(host='0.0.0.0', port=HTTP_PORT)
```

The `15-octobot-python-deps.sh` hook only verifies that `flask` imports, it never checks or updates the version, so whatever the feed provides (here Flask 2.0.2 / Werkzeug 2.3.6) is what runs. There is no SBOM and no advisory tracking.

## Steps to Reproduce

```bash
# 1. Fingerprint the gateway version from the Server header (no auth needed).
curl -sI http://192.168.2.1:8090/admin | grep -i '^Server:'
# -> Server: Werkzeug/2.3.6 Python/3.11.13

# 2. Confirm the Flask version from the overlay / opkg (the banner shows Werkzeug only).
ssh root@192.168.2.1 'opkg list-installed | grep python3-flask'
# -> python3-flask - 2.0.2-r6
ssh root@192.168.2.1 'python3 -c "import flask; print(flask.__version__)"'
# -> 2.0.2

# 3. Map each version to a published CVE.
#  Werkzeug 2.3.6  -> CVE-2023-46136  (multipart/form-data DoS, affects <= 2.3.7)
#  Flask   2.0.2   -> CVE-2023-30861  (cached session-cookie disclosure, affects < 2.2.5)
```

### CVE-2023-46136 — Werkzeug multipart DoS (reachable)

Werkzeug 2.3.6 is vulnerable to a denial of service in its multipart form parser (CVSS 3.1 base 7.5). A crafted `multipart/form-data` body forces the parser into pathological CPU use. The gateway's `/update` route parses multipart input (`request.files['firmware'].save(...)`) with no authentication, so a single crafted upload against `http://192.168.2.1:8090/update` reaches the vulnerable code path and can stall the gateway. Not run here (a DoS against the live gateway is disruptive), but the version and the reachable multipart sink are both confirmed.

### CVE-2023-30861 — Flask cached-session disclosure (version-present, topology-limited)

Flask 2.0.2 is below the 2.2.5 fix for CVE-2023-30861, where a caching proxy in front of the app can serve one client's session cookie to another. The shipped version is affected, but exploitation needs a caching proxy in front of the gateway and Flask session usage, neither of which the simple `octobot_gateway.py` deployment has. It is recorded as a real outdated-component exposure rather than a working chain in this topology.

## Expected Result

`curl -I` against the gateway returns `Server: Werkzeug/2.3.6 Python/3.11.13`, the overlay confirms Flask 2.0.2, and both versions map to published CVEs (CVE-2023-46136 reachable via the unauthenticated multipart `/update` route, CVE-2023-30861 present but topology-limited).

## How It Should Be

Do not run the Werkzeug development server in a deployed device, and never expose its version banner. Track a software bill of materials, monitor advisories for every shipped component, and pin to current patched releases (Flask 3.x / Werkzeug 3.x here) rather than whatever the feed happens to carry. Suppress or genericize the `Server` header.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| SBOM | Inventory every component + version | Know the attack surface |
| Patch | Track advisories, update on release | Close known CVEs |
| Build | Pin to current patched versions | Avoid shipping stale code |
| Server | Production WSGI server, no version banner | Remove the fingerprint and the dev-server exposure |

## Verification Checklist

- [ ] `curl -sI http://192.168.2.1:8090/admin` returns `Server: Werkzeug/2.3.6 Python/3.11.13`
- [ ] `opkg list-installed | grep python3-flask` reports `2.0.2`
- [ ] Werkzeug 2.3.6 maps to CVE-2023-46136 and the unauthenticated multipart `/update` route reaches the parser
- [ ] Flask 2.0.2 maps to CVE-2023-30861 (present, topology-limited in this deployment)

## Related Vulnerabilities

- [IoT:I4 — Lack of Secure Update Mechanism](IoT4_Lack_of_Secure_Update_Mechanism.md): the same unauthenticated `/update` multipart route is the reachable sink for the Werkzeug parser DoS.
- [IoT:I3 — Insecure Ecosystem Interfaces](IoT3_Insecure_Ecosystem_Interfaces.md): the dev server that banners its version is the same gateway that carries the SSTI root RCE.
