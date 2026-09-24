"""bulb_service.py - bulb control + account-device binding for the BulbBee cloud.

Intentional vulnerabilities (unchanged by the service split):
  API1 (BOLA): control never checks ownership in the default posture, so any
       authenticated user drives any bulb (and the relay makes it physical).
  BULB-P05: /api/register binds by "a valid token", no proof of possession.
  BULB-R6: activation binds on any named claim by default; secure requires a
       valid, unused, unexpired claim and is write-once.
"""


class BulbService:
    def __init__(self, db, relay, claims, config):
        self.db = db
        self.relay = relay
        self.claims = claims
        self.cfg = config

    # ── lookups ──────────────────────────────────────────────────────────────

    def get_bulb(self, bulb_id):
        return self.db.get_bulb(bulb_id)

    def mybulbs(self, owner):
        return self.db.bulbs_by_owner(owner)

    def all_bulbs(self):
        return self.db.all_bulbs()

    def owns(self, sub, bulb_id):
        b = self.db.get_bulb(bulb_id)
        return b is not None and b["owner"] == sub

    def relay_payload(self, data):
        return {k: data[k] for k in self.cfg.LIGHT_KEYS if k in data}

    # ── control (BULB-R1 relay through the BULB-R2 binding) ──────────────────

    def set_state(self, bulb_id, data):
        b = self.db.get_bulb(bulb_id)
        if b is None:
            return None
        self.db.update_bulb(bulb_id, {k: data[k] for k in ("power", "color") if k in data})
        relayed = self.relay.publish(b["device_id"], self.relay_payload(data))
        out = self.db.get_bulb(bulb_id)
        out["relayed"] = relayed
        return out

    def set_scene(self, bulb_id, scene):
        b = self.db.get_bulb(bulb_id)
        if b is None:
            return None
        return self.relay.publish(b["device_id"], {"scene": scene})

    # ── registration (BULB-R2, app-driven) ──────────────────────────────────

    def register(self, owner, device_id, bulb_id=None, token=""):
        """Bind a device to the caller. Returns (bulb_id, http_code)."""
        prior = self.db.bulb_for_device(device_id)
        if self.cfg.SECURE and prior is not None and self.db.get_bulb(prior)["owner"] != owner:
            return None, 409
        # VULNERABILITY (BULB-P05): default records the owner with no possession proof.
        bid = self.db.bind(device_id, owner, token, bulb_id=(bulb_id or prior))
        return bid, 200

    # ── activation binding (BULB-R6) ─────────────────────────────────────────

    def bind_from_activation(self, device_id, msg):
        """Bind a device from its activation message {device_id, token, claim_token}.
        Returns the bulb_id, or None."""
        device_id = msg.get("device_id") or device_id
        claim = msg.get("claim_token", "")
        token = msg.get("token", "")
        if self.cfg.SECURE:
            owner = self.claims.redeem(claim)              # single-use + TTL
            if owner is None:
                self.db.log_event("bind", "activation device=%s rejected (no valid claim)" % device_id)
                return None
            prior = self.db.bulb_for_device(device_id)
            if prior is not None and self.db.get_bulb(prior)["owner"] != owner:
                self.db.log_event("bind", "activation device=%s rejected (owned by another)" % device_id)
                return None                                # write-once
        else:
            owner = self.claims.peek_user(claim)           # default: no proof
            if owner is None:
                self.db.log_event("bind", "activation device=%s rejected (unknown claim)" % device_id)
                return None
        bulb_id = self.db.bind(device_id, owner, token)
        self.db.touch_device(device_id)     # BULB-U3: the device just announced itself -> live
        self.db.log_event("bind", "activation device=%s -> owner=%s (%s)" % (device_id, owner, bulb_id))
        return bulb_id

    # ── state uplink (BULB-R3) ───────────────────────────────────────────────

    def ingest_state(self, device_id, state):
        bid = self.db.bulb_for_device(device_id)
        if bid is None:
            self.db.log_event("state", "ignored device=%s (unregistered)" % device_id)
            return None
        self.db.update_bulb(bid, {k: state[k] for k in self.cfg.LIGHT_KEYS if k in state})
        self.db.touch_device(device_id)     # BULB-U3: mark the device live
        self.db.log_event("state", "device=%s -> %s updated" % (device_id, bid))
        return bid
