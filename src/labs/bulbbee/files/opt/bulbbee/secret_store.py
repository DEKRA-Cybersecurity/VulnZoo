#!/usr/bin/env python3
"""BulbBee secret store (BULB-A5), a simulated flash region on the rootfs.

Defines where every device secret lives and its intended protection. One stored
root secret (the per-device secret) is the single source of truth: the session
token (BULB-A3) and the LAN/TCP local key (BULB-A4) derive from it in secure
mode, so there is no redundant key file. The one net-new stored secret is the
owner binding.

Owner binding (vuln-consistent):
  secure  (secure=true) : write-once, and the device enforces it (check_owner
                          requires a match).
  default (secure=false): the device does not enforce (check_owner returns True),
                          binding lives only in the app (the BULB-05 substrate).

Stdlib only. Non-invasive: importing/using this does not change the default
control path.
"""
import json
import os
import time

STORE_DIR = os.environ.get("BULBBEE_SECRETS_DIR", "/opt/bulbbee/secrets")
OWNER_FILE = os.path.join(STORE_DIR, "owner.json")

# Every device secret, its rootfs location and intended protection. The Phase-4
# findings and the eval point at these entries.
LAYOUT = {
    "session_secret": {"path": "/opt/bulbbee/.session_secret", "mode": 0o600,
                       "purpose": "root per-device secret; token + local key derive from it"},
    "local_key":      {"path": "(derived from session_secret)", "mode": 0o600,
                       "purpose": "AES-CCM LAN/TCP key (BULB-A4); not stored separately"},
    "provisioning":   {"path": "/tmp/bulbbee/provisioning.json", "mode": 0o600,
                       "purpose": "WiFi PSK + pair token cache (BULB-02/05 read it)"},
    "owner_binding":  {"path": OWNER_FILE, "mode": 0o600,
                       "purpose": "account the device is bound to (BULB-05 enforces/omits)"},
}


def ensure_store():
    try:
        os.makedirs(STORE_DIR, mode=0o700, exist_ok=True)
        os.chmod(STORE_DIR, 0o700)
    except OSError:
        pass


def owner():
    """The bound owner id, or None."""
    try:
        with open(OWNER_FILE) as f:
            return json.load(f).get("owner")
    except (OSError, ValueError):
        return None


def bind_owner(owner_id):
    """Write-once bind. If already bound, keep the existing owner (returns it)."""
    existing = owner()
    if existing is not None:
        return existing
    ensure_store()
    try:
        fd = os.open(OWNER_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"owner": owner_id, "bound_at": int(time.time())}, f)
    except FileExistsError:
        return owner()          # raced; keep whoever won
    except OSError:
        pass
    return owner_id


def check_owner(claim_owner, secure):
    """Robust (secure): the claim must equal the bound owner (an unbound device
    accepts the first claimant). Default (vulnerable): always True, the device
    does not enforce owner binding (the BULB-05 substrate)."""
    if not secure:
        return True
    bound = owner()
    return bound is None or claim_owner == bound


def _selfcheck():
    import tempfile
    global STORE_DIR, OWNER_FILE
    d = tempfile.mkdtemp()
    STORE_DIR = os.path.join(d, "secrets")
    OWNER_FILE = os.path.join(STORE_DIR, "owner.json")
    # 4. ensure_store creates the dir 0700
    ensure_store()
    assert oct(os.stat(STORE_DIR).st_mode & 0o777) == oct(0o700)
    # 2. write-once binding
    assert bind_owner("alice") == "alice"
    assert owner() == "alice"
    assert bind_owner("mallory") == "alice"     # second bind ignored
    assert owner() == "alice"
    # 3. enforcement secure vs default
    assert check_owner("mallory", secure=True) is False
    assert check_owner("alice", secure=True) is True
    assert check_owner("mallory", secure=False) is True     # BULB-05 substrate
    # 1. layout modes restrictive
    for name, e in LAYOUT.items():
        assert e["mode"] in (0o600,), name
    print("secret_store selfcheck OK")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--selfcheck":
        _selfcheck()
    else:
        ensure_store()
        print(json.dumps({"owner": owner(), "layout": {k: v["path"] for k, v in LAYOUT.items()}}))
