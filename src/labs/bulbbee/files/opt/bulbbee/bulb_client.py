#!/usr/bin/env python3
"""Shared control-daemon client (BULB-A1).

The lighting service (lighting_service.py) is the single owner of the ring
state on :8082. Each plane (BLE today, LAN/TCP in BULB-A4, cloud tunnel in
BULB-A3) translates its own wire format into a lighting command dict and
applies it here, so no plane opens /dev/spidev0.0. Stdlib only.

A command dict may carry any of: power (bool), brightness (0-255),
color ([r,g,b]), scene (str). It is split into the daemon's /set (state
fields) and /scene (named scene) calls, /set first.
"""
import json
import urllib.request

SET_KEYS = ("power", "brightness", "color")


def plan_calls(command):
    """Split a command dict into ordered (path, body) daemon calls. Pure."""
    calls = []
    setk = {k: command[k] for k in SET_KEYS if k in command}
    if setk:
        calls.append(("/set", setk))
    if "scene" in command:
        calls.append(("/scene", {"scene": command["scene"]}))
    return calls


class BulbClient:
    def __init__(self, port=8082, host="127.0.0.1", timeout=2):
        self.base = "http://%s:%d" % (host, port)
        self.timeout = timeout

    def _post(self, path, body):
        req = urllib.request.Request(
            self.base + path, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return r.read()

    def apply(self, command):
        for path, body in plan_calls(command):
            self._post(path, body)

    def state(self):
        with urllib.request.urlopen(self.base + "/state", timeout=self.timeout) as r:
            return json.loads(r.read().decode())


def _selfcheck():
    assert plan_calls({"scene": "rainbow"}) == [("/scene", {"scene": "rainbow"})]
    assert plan_calls({"power": True, "brightness": 200, "color": [1, 2, 3]}) == [
        ("/set", {"power": True, "brightness": 200, "color": [1, 2, 3]})]
    combined = plan_calls({"color": [1, 2, 3], "scene": "solid"})
    assert [p for p, _ in combined] == ["/set", "/scene"], combined
    assert plan_calls({}) == []
    print("bulb_client selfcheck OK")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--selfcheck":
        _selfcheck()
    else:
        print(json.dumps(BulbClient().state()))
