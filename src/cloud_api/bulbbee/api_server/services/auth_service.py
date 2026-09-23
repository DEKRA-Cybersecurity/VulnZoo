"""auth_service.py - login + token decoding for the BulbBee cloud API.

Intentional vulnerabilities (unchanged by the service split):
  API2 (Broken Authentication): decode_token honours the `none` algorithm
       (keyless forge) and otherwise verifies with the weak hardcoded secret;
       login ignores the password in the default posture.
"""

import jwt


class AuthService:
    def __init__(self, db, config):
        self.db = db
        self.cfg = config

    def decode_token(self, token):
        """VULNERABILITY (API2): honour the header alg, including `none`."""
        header = jwt.get_unverified_header(token)
        if header.get("alg") == "none":
            return jwt.decode(token, options={"verify_signature": False}, algorithms=["none"])
        return jwt.decode(token, self.cfg.JWT_SECRET, algorithms=[self.cfg.JWT_ALGORITHM])

    def claims(self, auth_header):
        """The token claims from an Authorization header, or None. Only checks the
        token decodes, never object ownership (that is the BOLA)."""
        if not auth_header.startswith("Bearer "):
            return None
        try:
            return self.decode_token(auth_header[7:])
        except Exception:
            return None

    def login(self, user, password):
        """Return (jwt, None) on success, (None, reason) otherwise. The default
        ignores the password (API2), secure verifies it (BULB-R6)."""
        u = self.db.get_user(user)
        if u is None:
            return None, "unknown"
        if self.cfg.SECURE and password != u["password"]:
            return None, "bad"
        token = jwt.encode({"sub": user, "role": u["role"]},
                           self.cfg.JWT_SECRET, algorithm=self.cfg.JWT_ALGORITHM)
        return token, None
