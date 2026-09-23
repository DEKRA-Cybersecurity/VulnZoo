# BulbBee Cloud API (Layer 2)

**Stage Purpose**: the remote-control backend for BulbBee (target BULB-CLD, Wave 4), Flask on port `5004`, split into a `services/` layer over a SQLAlchemy (SQLite) database, with intentional API vulnerabilities.

## Scenario

The BulbBee cloud lets the app control bulbs remotely and sync scenes. It seeds two users (alice owns bulb-1, bob owns bulb-2) and exposes per-bulb control plus an admin view.

## Intended vulnerabilities

| ID | Weakness | OWASP |
|----|----------|-------|
| API1 (BOLA) | `/api/bulb/<id>/state` authorizes by "valid token", never by bulb ownership, so any user controls any bulb | API1:2023 |
| API2 (Broken Auth) | `decode_token` accepts the `none` algorithm (keyless forge) and a weak hardcoded HS256 secret (`bulbbee-secret`) | API2:2023 |

> BULB-R1: `/api/bulb/<id>/state` and the new `/api/bulb/<id>/scene` relay the command to the device's MQTT `cmd` topic (`bulbbee/<device_id>/cmd`, where the tunnel is subscribed), so the API1 BOLA is a real remote hijack of the physical bulb, not a dict edit. Transport is plaintext `:1883` by default, TLS `:8883` and ownership-checked only when `BULBBEE_SECURE=1`.

> BULB-R2: `POST /api/register` binds an account to a device (`device_id` + binding token), and control resolves `bulb_id -> device_id` through that binding. The owner is recorded but, by default, never enforced (BULB-P05 lifted to the cloud), so any authenticated caller can claim any device (takeover by registration). `BULBBEE_SECURE=1` refuses a cross-owner re-bind (409) and enforces `owner == caller`.

> BULB-R3: a background subscriber to `bulbbee/+/state` reflects each device's reported state (published by the tunnel after every apply) into the store through the R2 binding, so `GET /api/bulb/<id>/state` returns live device state, not the seed. No new weakness, the uplink is unauthenticated at the anonymous broker like the rest of the plaintext plane.

> BULB-R6: `/api/login` gains a password (ignored by default = API2, verified in secure), `/api/claim` issues a single-use TTL claim token, and a `bulbbee/+/register` activation binds `device -> user` via the claim (default binds on any named claim with no proof, secure is single-use + write-once). `/api/mybulbs` lists the caller's own bulbs.

> The vulnerabilities are intentional. Documented in [`../../docs/BulbBee/Vulns/API/`](../../docs/BulbBee/).

## Structure

The API is split into a `services/` layer over a SQLAlchemy (SQLite) database (replacing the earlier in-process dicts), served by gunicorn (`wsgi:app`, workers 1 so the MQTT subscriber runs once):

- `config.py` - env-driven config (`JWT_SECRET`, `BULBBEE_SECURE`, broker, `CLAIM_TTL`, `DB_PATH`).
- `services/database_service.py` - SQLAlchemy models (`User` / `Bulb` / `Claim` / `Event`) + persistence + the seed (users alice/bob/admin, bulbs bulb-1/bulb-2), plus `log_event` (a timestamped `events` row + a stdout line: the server's temporal event log). DB at `DB_PATH` (default `/app/data/bulbbee.db`), persisted on the `bulbbee_data` volume.
- `services/auth_service.py` - login + JWT decode (API2: `alg:none` / weak secret / password ignored by default).
- `services/claim_service.py` - claim tokens (single-use + TTL in secure).
- `services/bulb_service.py` - control (BOLA), binding (register + activation), state uplink.
- `services/relay_service.py` - MQTT publish (relay) + the state/activation subscriber.
- `app.py` - thin Flask routes wiring the services; `init_app()` seeds the DB and starts the subscriber.

## Ports

| Service | Port | Protocol |
|---------|------|----------|
| Cloud API | 5004 | HTTP |

## Build / run

The stack is two services: the Flask REST API (`bulbbee-cloud`, `:5004`) and the MQTT broker the device tunnel connects to (`bulbbee-broker`, `:1883`/`:8883`, BULB-A3).

```bash
cd src/cloud_api/bulbbee
./cloudctl.sh start            # build + up -d (API :5004 + broker :1883/:8883), prints the cloud_host hint
./cloudctl.sh pub <id> '{"scene":"rainbow"}'   # drive the bulb over the tunnel
./cloudctl.sh stop | restart | reset | status | logs [service]
# or raw:
docker compose up --build      # serves the API on :5004 and the broker on :1883/:8883
```

## Verification checklist

- [ ] `POST /api/login {"user":"alice"}` returns an HS256 token
- [ ] BOLA: alice's token controls bob's `bulb-2` via `POST /api/bulb/bulb-2/state`
- [ ] API2: a forged `alg:none` `role:admin` token reaches `GET /api/admin/bulbs`
- [ ] a wrong-secret HS256 token is rejected (only the weak secret / none work)
- [ ] BULB-R1: a `POST /api/bulb/bulb-2/state` publishes the command to `bulbbee/bee-0002/cmd` (observe with `cloudctl.sh sub 'bulbbee/bee-0002/cmd'` or `mosquitto_sub`), and `/scene` publishes `{"scene":...}`
- [ ] BULB-R2: `POST /api/register {"device_id":"bee-0009"}` returns a `bulb_id` bound to the caller, control resolves it to `bulbbee/bee-0009/cmd`, and a cross-owner re-bind returns 409 under `BULBBEE_SECURE=1`
- [ ] BULB-R3: a state publish on `bulbbee/bee-0002/state` is reflected in `GET /api/bulb/bulb-2/state` (live device state, not the seed)
- [ ] Event log: every route and each appreciable event is recorded in the `events` table (timestamped) + stdout; `GET /api/admin/events` returns the log (reachable with a forged `alg:none` admin token, API2 data exposure of the activity trail)

## References

- Finding doc: [`../../docs/BulbBee/Vulns/API/BULB-CLD-cloud-api-bola-weak-jwt.md`](../../docs/BulbBee/)
- Lab: [`../../labs/bulbbee/CONTEXT.md`](../../labs/bulbbee/CONTEXT.md)
