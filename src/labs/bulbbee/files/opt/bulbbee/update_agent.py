#!/usr/bin/env python3
"""BulbBee update agent (BULB-04).

VULNERABILITY: applies an over-the-air update with NO signature, origin, or
version check, so an attacker-served payload runs on the device (as the service
user, root on OpenWRT). Stdlib only. Triggered unauthenticated over the :8082
/update endpoint (chains BULB-02).
"""

import os
import sys
import hmac
import hashlib
import subprocess
import urllib.request

UPDATE_DIR = "/tmp/bulbbee"
_SIG_PREFIX = b"# BULBBEE-SIGNED: "


def _download(url, timeout=15):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()


def _verify_signature(data, key):
    """Secure-mode check (BULB-SEC): the payload must start with a signature line
    `# BULBBEE-SIGNED: <hex hmac-sha256 of the remaining bytes>`."""
    try:
        first, rest = data.split(b"\n", 1)
    except ValueError:
        return False
    if not first.startswith(_SIG_PREFIX):
        return False
    sig = first[len(_SIG_PREFIX):].strip()
    expect = hmac.new(key.encode(), rest, hashlib.sha256).hexdigest().encode()
    return hmac.compare_digest(sig, expect)


def apply_update(url, secure=False, key=""):
    """Fetch and apply an update. In the default (vulnerable) mode there is no
    signature verification, no origin/allowlist, no version check, the served
    bytes are executed as-is (BULB-04). In secure mode (BULB-SEC) the payload
    must carry a valid HMAC signature line or it is rejected."""
    data = _download(url)                       # attacker-controlled URL, no allowlist
    if secure and not _verify_signature(data, key):
        raise ValueError("update rejected: missing or invalid signature")
    os.makedirs(UPDATE_DIR, exist_ok=True)
    path = os.path.join(UPDATE_DIR, "update.sh")
    with open(path, "wb") as f:
        f.write(data)                           # no signature check in the default mode
    os.chmod(path, 0o755)
    subprocess.run(["sh", path], timeout=30, check=False)   # runs whatever was served
    return path


def _demo():
    # ponytail: prove an unsigned payload is fetched and executed, no verification
    import http.server, threading, tempfile
    marker = os.path.join(tempfile.gettempdir(), "bulbbee_update_marker")
    if os.path.exists(marker):
        os.remove(marker)
    payload = ("#!/bin/sh\ntouch %s\n" % marker).encode()

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(payload)

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    apply_update("http://127.0.0.1:%d/firmware.sh" % port)
    srv.shutdown()
    assert os.path.exists(marker), "unsigned payload was not executed"
    os.remove(marker)
    print("update_agent self-check OK (unsigned payload fetched + executed)")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selfcheck":
        _demo()
    elif len(sys.argv) > 1:
        print(apply_update(sys.argv[1]))
