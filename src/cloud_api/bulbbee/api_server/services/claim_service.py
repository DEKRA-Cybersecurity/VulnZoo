"""claim_service.py - single-use, TTL claim tokens for device binding (BULB-R6).

The app gets a claim after signing in and hands it to the bulb over BLE; the bulb
presents it on activation so the cloud binds the device to the user. Single-use +
TTL is only enforced on the secure path, the default reuses/ignores it.
"""

import secrets
import time


class ClaimService:
    def __init__(self, db, config):
        self.db = db
        self.cfg = config

    def issue(self, user):
        tok = secrets.token_hex(8)
        self.db.add_claim(tok, user, time.time() + self.cfg.CLAIM_TTL)
        return tok

    def redeem(self, token):
        """Secure path: return the user and consume the claim, or None when it is
        unknown, already used, or expired (single-use)."""
        c = self.db.get_claim(token)
        if not c or c["used"] or c["exp"] < time.time():
            return None
        self.db.mark_claim_used(token)
        return c["user"]

    def peek_user(self, token):
        """Default (vulnerable) path: the claim's named user, ignoring used / TTL."""
        c = self.db.get_claim(token)
        return c["user"] if c else None
