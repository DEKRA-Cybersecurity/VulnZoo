#!/usr/bin/env python3
"""app.py - BulbBee cloud API (BULB-CLD), thin Flask over the services layer.

The logic lives in services/ (database, auth, claims, bulbs, relay). This file
only wires HTTP routes to them. Every route logs a line before returning and each
appreciable event is recorded, so the server keeps a temporal event log (in the
`events` table plus stdout, via db.log_event).

Intentional vulnerabilities (unchanged, documented per service):
  API1 (BOLA)  - per-bulb control never checks ownership by default (bulb_service).
  API2 (auth)  - `alg:none` / weak secret / password ignored (auth_service).
  BULB-R1/R2/R3/R6 - relay, binding, state uplink, claim-token activation.

Set BULBBEE_SECURE=1 to enable the robust branches.
"""

from flask import Flask, request, jsonify

from config import Config
from services.database_service import DatabaseService
from services.auth_service import AuthService
from services.claim_service import ClaimService
from services.relay_service import RelayService
from services.bulb_service import BulbService

app = Flask(__name__)
cfg = Config

db = DatabaseService(cfg.DB_URL)
relay = RelayService(cfg)
claims = ClaimService(db, cfg)
auth = AuthService(db, cfg)
bulbs = BulbService(db, relay, claims, cfg)


def init_app():
    """Startup logic run once per process (seed the DB, start the subscriber)."""
    db.seed()
    relay.start_subscriber(on_state=bulbs.ingest_state, on_register=bulbs.bind_from_activation)
    db.log_event("boot", "cloud API up (secure=%s)" % cfg.SECURE)


def _ev(kind, message):
    """One log line, persisted to the events table and stdout."""
    db.log_event(kind, message)


def _claims():
    return auth.claims(request.headers.get("Authorization", ""))


@app.post("/api/login")
def login():
    body = request.get_json(silent=True) or {}
    user = body.get("user", "")
    token, err = auth.login(user, body.get("password", ""))
    if err == "unknown":
        _ev("login", "unknown user=%s" % user)
        return jsonify({"error": "unknown user"}), 404
    if err == "bad":
        _ev("login", "bad-credentials user=%s" % user)
        return jsonify({"error": "bad credentials"}), 401
    _ev("login", "user=%s ok" % user)
    return jsonify({"token": token})


@app.post("/api/claim")
def claim():
    c = _claims()
    if c is None:
        _ev("claim", "unauthorized")
        return jsonify({"error": "unauthorized"}), 401
    tok = claims.issue(c["sub"])
    _ev("claim", "issued for %s" % c["sub"])
    return jsonify({"claim_token": tok, "expires_in": cfg.CLAIM_TTL})


@app.post("/api/register")
def register():
    c = _claims()
    if c is None:
        _ev("register", "unauthorized")
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    device_id = data.get("device_id")
    if not device_id:
        _ev("register", "missing device_id by=%s" % c["sub"])
        return jsonify({"error": "device_id required"}), 400
    bulb_id, code = bulbs.register(c["sub"], device_id,
                                   bulb_id=data.get("bulb_id"),
                                   token=data.get("binding_token", ""))
    if code == 409:
        _ev("register", "device=%s refused (owned by another) by=%s" % (device_id, c["sub"]))
        return jsonify({"error": "device already registered to another account"}), 409
    _ev("register", "device=%s owner=%s (%s)" % (device_id, c["sub"], bulb_id))
    return jsonify({"bulb_id": bulb_id, "device_id": device_id, "owner": c["sub"]})


@app.get("/api/mybulbs")
def my_bulbs():
    c = _claims()
    if c is None:
        _ev("mybulbs", "unauthorized")
        return jsonify({"error": "unauthorized"}), 401
    mine = bulbs.mybulbs(c["sub"])
    _ev("mybulbs", "%s n=%d" % (c["sub"], len(mine)))
    return jsonify(mine)


@app.get("/api/bulb/<bulb_id>/state")
def get_state(bulb_id):
    c = _claims()
    if c is None:
        _ev("get_state", "unauthorized bulb=%s" % bulb_id)
        return jsonify({"error": "unauthorized"}), 401
    b = bulbs.get_bulb(bulb_id)
    if not b:
        _ev("get_state", "not-found bulb=%s by=%s" % (bulb_id, c["sub"]))
        return jsonify({"error": "not found"}), 404
    # VULNERABILITY (API1 / BOLA): no ownership check.
    _ev("get_state", "bulb=%s by=%s" % (bulb_id, c["sub"]))
    return jsonify(b)


@app.post("/api/bulb/<bulb_id>/state")
def set_state(bulb_id):
    c = _claims()
    if c is None:
        _ev("control", "unauthorized bulb=%s" % bulb_id)
        return jsonify({"error": "unauthorized"}), 401
    if bulbs.get_bulb(bulb_id) is None:
        _ev("control", "not-found bulb=%s by=%s" % (bulb_id, c["sub"]))
        return jsonify({"error": "not found"}), 404
    if cfg.SECURE and not bulbs.owns(c["sub"], bulb_id):
        _ev("control", "forbidden bulb=%s by=%s" % (bulb_id, c["sub"]))
        return jsonify({"error": "forbidden"}), 403
    out = bulbs.set_state(bulb_id, request.get_json(silent=True) or {})
    _ev("control", "bulb=%s by=%s relayed=%s" % (bulb_id, c["sub"], out.get("relayed")))
    return jsonify(out)


@app.post("/api/bulb/<bulb_id>/scene")
def set_scene(bulb_id):
    c = _claims()
    if c is None:
        _ev("scene", "unauthorized bulb=%s" % bulb_id)
        return jsonify({"error": "unauthorized"}), 401
    if bulbs.get_bulb(bulb_id) is None:
        _ev("scene", "not-found bulb=%s by=%s" % (bulb_id, c["sub"]))
        return jsonify({"error": "not found"}), 404
    if cfg.SECURE and not bulbs.owns(c["sub"], bulb_id):
        _ev("scene", "forbidden bulb=%s by=%s" % (bulb_id, c["sub"]))
        return jsonify({"error": "forbidden"}), 403
    scene = (request.get_json(silent=True) or {}).get("scene")
    if not scene:
        _ev("scene", "missing scene bulb=%s by=%s" % (bulb_id, c["sub"]))
        return jsonify({"error": "scene required"}), 400
    relayed = bulbs.set_scene(bulb_id, scene)
    _ev("scene", "bulb=%s scene=%s by=%s relayed=%s" % (bulb_id, scene, c["sub"], relayed))
    return jsonify({"bulb": bulb_id, "scene": scene, "relayed": relayed})


@app.get("/api/admin/bulbs")
def admin_bulbs():
    c = _claims()
    if c is None or c.get("role") != "admin":
        _ev("admin", "bulbs forbidden by=%s" % (c.get("sub") if c else None))
        return jsonify({"error": "forbidden"}), 403
    # reachable by forging an alg:none role=admin token (API2)
    _ev("admin", "bulbs listed by=%s" % c.get("sub"))
    return jsonify(bulbs.all_bulbs())


@app.get("/api/admin/events")
def admin_events():
    """The server event log. Admin-gated, so a forged alg:none admin token reads
    the whole activity log (API2, data exposure of the event trail)."""
    c = _claims()
    if c is None or c.get("role") != "admin":
        _ev("admin", "events forbidden by=%s" % (c.get("sub") if c else None))
        return jsonify({"error": "forbidden"}), 403
    _ev("admin", "events read by=%s" % c.get("sub"))
    return jsonify({"events": db.recent_events(int(request.args.get("limit", 100)))})


def _selfcheck():
    class _CapRelay:
        def __init__(self):
            self.sent = []

        def publish(self, dev, cmd):
            if cmd:
                self.sent.append((dev, cmd))
                return True
            return False

    tdb = DatabaseService("sqlite://")
    tdb.seed()
    cap = _CapRelay()
    tclaims = ClaimService(tdb, Config)
    tbulbs = BulbService(tdb, cap, tclaims, Config)
    tauth = AuthService(tdb, Config)

    assert tbulbs.relay_payload({"power": True, "brightness": 10, "color": [1, 2, 3], "x": 9}) == \
        {"power": True, "brightness": 10, "color": [1, 2, 3]}
    assert tdb.bulb_for_device("bee-0001") == "bulb-1"
    assert tdb.bulb_for_device("nope") is None

    out = tbulbs.set_state("bulb-2", {"power": True, "color": [9, 9, 9]})
    assert out is not None and cap.sent[-1] == ("bee-0002", {"power": True, "color": [9, 9, 9]}), cap.sent
    bid, code = tbulbs.register("alice", "bee-9999")
    assert code == 200 and tdb.get_bulb(bid)["owner"] == "alice" and tdb.get_bulb(bid)["device_id"] == "bee-9999"
    assert tbulbs.ingest_state("bee-0002", {"power": True, "brightness": 200, "scene": "solid", "color": [1, 2, 3]}) == "bulb-2"
    st = tdb.get_bulb("bulb-2")
    assert st["brightness"] == 200 and st["scene"] == "solid"

    t1 = tclaims.issue("alice")
    assert tclaims.redeem(t1) == "alice"
    assert tclaims.redeem(t1) is None          # single-use
    assert tclaims.redeem("nope") is None
    t2 = tclaims.issue("alice")
    b6 = tbulbs.bind_from_activation("bee-777", {"device_id": "bee-777", "claim_token": t2})
    assert b6 is not None and tdb.get_bulb(b6)["owner"] == "alice"

    tok, err = tauth.login("alice", "wrong")    # default ignores the password (API2)
    assert tok is not None and err is None
    mine = tbulbs.mybulbs("alice")
    assert "bulb-1" in mine and "bulb-2" not in mine
    assert tauth.claims("Bearer " + tok)["sub"] == "alice"

    # event log: the appreciable events above were recorded
    tdb.log_event("selfcheck", "done")
    evs = tdb.recent_events()
    assert any(e["kind"] == "bind" for e in evs) and any(e["kind"] == "state" for e in evs), evs
    assert evs[-1]["message"] == "done"          # ordered oldest -> newest
    print("app services+eventlog selfcheck OK")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--selfcheck":
        _selfcheck()
    else:
        init_app()
        app.run(host="0.0.0.0", port=cfg.PORT)
