#!/usr/bin/env python3
"""BulbBee cloud API (BULB-CLD), thin remote-control backend.

Intentional vulnerabilities:
  API1 (BOLA): the per-bulb control endpoints authorize by "is there a valid
       token", never by bulb ownership, so any authenticated user controls any
       user's bulb.
  API2 (Broken Authentication): decode_token accepts the `none` algorithm
       (keyless forge) and otherwise verifies with a weak hardcoded HS256 secret.
"""

import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

# VULNERABILITY (API2): weak, hardcoded signing secret.
JWT_SECRET = "bulbbee-secret"

# Seeded model: alice owns bulb-1, bob owns bulb-2.
USERS = {"alice": {"role": "user"}, "bob": {"role": "user"}, "admin": {"role": "admin"}}
BULBS = {
    "bulb-1": {"owner": "alice", "power": False, "color": [0, 0, 0]},
    "bulb-2": {"owner": "bob", "power": False, "color": [0, 0, 0]},
}


def decode_token(token):
    """VULNERABILITY (API2): honour the token header's alg, including `none`
    (keyless), otherwise verify with the weak hardcoded secret."""
    header = jwt.get_unverified_header(token)
    if header.get("alg") == "none":
        return jwt.decode(token, options={"verify_signature": False}, algorithms=["none"])
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])


def _auth():
    """Return the token claims, or None. Only checks the token is decodable,
    never who owns the target object (that is the BOLA)."""
    h = request.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        return None
    try:
        return decode_token(h[7:])
    except Exception:
        return None


@app.post("/api/login")
def login():
    user = (request.get_json(silent=True) or {}).get("user", "")
    if user not in USERS:
        return jsonify({"error": "unknown user"}), 404
    token = jwt.encode({"sub": user, "role": USERS[user]["role"]}, JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token})


@app.get("/api/bulb/<bulb_id>/state")
def get_state(bulb_id):
    claims = _auth()
    if claims is None:
        return jsonify({"error": "unauthorized"}), 401
    b = BULBS.get(bulb_id)
    if not b:
        return jsonify({"error": "not found"}), 404
    # VULNERABILITY (API1 / BOLA): no check that claims["sub"] owns bulb_id.
    return jsonify(b)


@app.post("/api/bulb/<bulb_id>/state")
def set_state(bulb_id):
    claims = _auth()
    if claims is None:
        return jsonify({"error": "unauthorized"}), 401
    b = BULBS.get(bulb_id)
    if not b:
        return jsonify({"error": "not found"}), 404
    # VULNERABILITY (API1 / BOLA): any authenticated user controls any bulb.
    data = request.get_json(silent=True) or {}
    for k in ("power", "color"):
        if k in data:
            b[k] = data[k]
    return jsonify(b)


@app.get("/api/admin/bulbs")
def admin_bulbs():
    claims = _auth()
    if claims is None or claims.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403
    # reachable by forging an alg:none role=admin token (API2)
    return jsonify(BULBS)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5004)
