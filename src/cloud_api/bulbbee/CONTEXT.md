# BulbBee Cloud API (Layer 2)

**Stage Purpose**: a thin remote-control backend for BulbBee (target BULB-CLD, Wave 4), Flask on port `5004`, with two intentional API vulnerabilities.

## Scenario

The BulbBee cloud lets the app control bulbs remotely and sync scenes. It seeds two users (alice owns bulb-1, bob owns bulb-2) and exposes per-bulb control plus an admin view.

## Intended vulnerabilities

| ID | Weakness | OWASP |
|----|----------|-------|
| API1 (BOLA) | `/api/bulb/<id>/state` authorizes by "valid token", never by bulb ownership, so any user controls any bulb | API1:2023 |
| API2 (Broken Auth) | `decode_token` accepts the `none` algorithm (keyless forge) and a weak hardcoded HS256 secret (`bulbbee-secret`) | API2:2023 |

> The vulnerabilities are intentional. Documented in [`../../docs/BulbBee/Vulns/API/`](../../docs/BulbBee/).

## Ports

| Service | Port | Protocol |
|---------|------|----------|
| Cloud API | 5004 | HTTP |

## Build / run

```bash
cd src/cloud_api/bulbbee
docker compose up --build      # serves the API on :5004
```

## Verification checklist

- [ ] `POST /api/login {"user":"alice"}` returns an HS256 token
- [ ] BOLA: alice's token controls bob's `bulb-2` via `POST /api/bulb/bulb-2/state`
- [ ] API2: a forged `alg:none` `role:admin` token reaches `GET /api/admin/bulbs`
- [ ] a wrong-secret HS256 token is rejected (only the weak secret / none work)

## References

- Finding doc: [`../../docs/BulbBee/Vulns/API/BULB-CLD-cloud-api-bola-weak-jwt.md`](../../docs/BulbBee/)
- Lab: [`../../labs/bulbbee/CONTEXT.md`](../../labs/bulbbee/CONTEXT.md)
