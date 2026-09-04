#!/usr/bin/env python3
"""BulbBee lighting service: WS2812 ring control over a local HTTP API (:8082).

Honest functional bring-up (BULB-A0). Stdlib only. No authentication is added
here on purpose, that surface is what BULB-02 documents as the intentional
weakness. This service does not add the open AP, the unsigned updater, or the
plaintext-secret behavior, those are BULB-01/04/05.
"""

import os
import json
import time
import threading
import colorsys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ws2812 import WS2812

CONFIG_PATH = os.environ.get("BULBBEE_CONFIG", "/opt/bulbbee/config.json")

DEFAULTS = {
    "use_real_hardware": False,
    "led_count": 16,
    "brightness": 128,
    "gamma": 2.2,
    "spi_hz": 2_400_000,
    "color_order": "GRB",
    "http_port": 8082,
    "refresh_hz": 30,
    "spi_device": "/dev/spidev0.0",
    "state_file": "/tmp/bulbbee/state.json",
}

ANIMATED = ("rainbow", "breathe")


def _log(msg):
    print("[bulbbee] %s" % msg, flush=True)


def _load_config():
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_PATH) as f:
            cfg.update(json.load(f))
    except (OSError, ValueError) as e:
        _log("config: using defaults (%s)" % e)
    return cfg


class Controller:
    def __init__(self, cfg):
        self.cfg = cfg
        self.led_count = int(cfg["led_count"])
        self.dev = WS2812(cfg, _log)
        self.lock = threading.Lock()
        self.state = {
            "power": True,
            "brightness": int(cfg["brightness"]),
            "color": [255, 160, 60],
            "scene": "solid",
        }
        self._load_state()
        self._phase = 0.0
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)

    # ---- persistence -------------------------------------------------
    def _state_path(self):
        return self.cfg["state_file"]

    def _load_state(self):
        try:
            with open(self._state_path()) as f:
                saved = json.load(f)
            self.state.update({k: saved[k] for k in self.state if k in saved})
            _log("state: restored from %s" % self._state_path())
        except (OSError, ValueError):
            pass

    def _save_state(self):
        try:
            os.makedirs(os.path.dirname(self._state_path()), exist_ok=True)
            tmp = self._state_path() + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self._snapshot(), f)
            os.replace(tmp, self._state_path())
        except OSError as e:
            _log("state: save failed (%s)" % e)

    def _snapshot(self):
        s = dict(self.state)
        s["simulated"] = self.dev.simulated
        s["frame"] = self.dev.frame
        return s

    # ---- public API --------------------------------------------------
    def start(self):
        self._t.start()

    def stop(self):
        self._stop.set()
        self._t.join(timeout=2)
        self.dev.clear()
        self.dev.close()

    def get_state(self):
        with self.lock:
            return self._snapshot()

    def set_state(self, power=None, brightness=None, color=None):
        with self.lock:
            if power is not None:
                self.state["power"] = bool(power)
            if brightness is not None:
                self.state["brightness"] = max(0, min(255, int(brightness)))
                self.dev.brightness = self.state["brightness"]
            if color is not None:
                self.state["color"] = [max(0, min(255, int(c))) for c in color][:3]
            self._save_state()
        self._render_once()

    def set_scene(self, name):
        if name not in ("solid", "off") and name not in ANIMATED:
            raise ValueError("unknown scene: %s" % name)
        with self.lock:
            self.state["scene"] = name
            self._save_state()
        self._render_once()

    # ---- rendering ---------------------------------------------------
    def _render_once(self):
        with self.lock:
            scene = self.state["scene"]
            on = self.state["power"]
            color = tuple(self.state["color"])
        if not on or scene == "off":
            self.dev.show([(0, 0, 0)] * self.led_count)
        elif scene == "solid":
            self.dev.show([color] * self.led_count)
        # animated scenes are advanced by the background loop

    def _run(self):
        _log("animation loop started (%d LEDs, %s)" %
             (self.led_count, "sim" if self.dev.simulated else "hw"))
        period = 1.0 / max(1, int(self.cfg["refresh_hz"]))
        self._render_once()
        while not self._stop.is_set():
            with self.lock:
                scene = self.state["scene"]
                on = self.state["power"]
                color = tuple(self.state["color"])
            if on and scene in ANIMATED:
                self._phase = (self._phase + 0.01) % 1.0
                if scene == "rainbow":
                    self.dev.show(self._rainbow(self._phase))
                elif scene == "breathe":
                    self.dev.show(self._breathe(color, self._phase))
            time.sleep(period)

    def _rainbow(self, phase):
        out = []
        for i in range(self.led_count):
            h = (phase + i / self.led_count) % 1.0
            r, g, b = colorsys.hsv_to_rgb(h, 1.0, 1.0)
            out.append((int(r * 255), int(g * 255), int(b * 255)))
        return out

    def _breathe(self, color, phase):
        import math
        k = (math.sin(phase * 2 * math.pi) + 1) / 2
        return [tuple(int(c * k) for c in color)] * self.led_count


class Handler(BaseHTTPRequestHandler):
    controller = None  # set on the server

    def log_message(self, fmt, *args):
        _log("http %s" % (fmt % args))

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode())

    def do_GET(self):
        c = self.controller
        if self.path == "/health":
            self._send(200, {"status": "ok"})
        elif self.path == "/state":
            self._send(200, c.get_state())
        elif self.path == "/config":
            self._send(200, c.cfg)
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        c = self.controller
        try:
            data = self._read_json()
        except ValueError:
            self._send(400, {"error": "invalid json"})
            return
        try:
            if self.path == "/set":
                c.set_state(power=data.get("power"),
                            brightness=data.get("brightness"),
                            color=data.get("color"))
                self._send(200, c.get_state())
            elif self.path == "/scene":
                c.set_scene(data.get("scene", ""))
                self._send(200, c.get_state())
            else:
                self._send(404, {"error": "not found"})
        except ValueError as e:
            self._send(400, {"error": str(e)})


def main():
    cfg = _load_config()
    controller = Controller(cfg)
    controller.start()
    Handler.controller = controller
    port = int(cfg["http_port"])
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    _log("control API on :%d" % port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()


if __name__ == "__main__":
    main()
