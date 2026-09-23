#!/usr/bin/env python3
"""BulbBee cloud tunnel client (BULB-A3).

The device opens an OUTBOUND connection to the cloud broker and keeps it alive.
It never listens on the Internet: it is an MQTT client. It authenticates with
the session token (BULB-A3 / BULB-04), subscribes to its command topic, maps
each cloud message to a lighting command and applies it through the BULB-A1
adapter (bulb_client -> the single-owner :8082 daemon), and publishes state.

Transport (vuln-consistent):
  default (secure=false): plaintext MQTT :1883  (BULB-03 cleartext/replay substrate)
  secure  (secure=true) : MQTT over TLS  :8883

paho-mqtt (python3-paho-mqtt, already in the image) is guarded so the pure
mapping logic is unit-checkable and a missing dep degrades to a clean exit.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bulb_client
import session_token

try:
    import paho.mqtt.client as mqtt
    _HAS_MQTT = True
except ImportError:
    _HAS_MQTT = False

CONFIG_PATH = os.environ.get("BULBBEE_CONFIG", "/opt/bulbbee/config.json")
PROV_STATE_FILE = "/tmp/bulbbee/provisioning.json"
LIGHT_KEYS = ("power", "brightness", "color", "scene")


def _load_config():
    cfg = {"http_port": 8082, "secure": False, "cloud_host": "192.168.2.10",
           "cloud_mqtt_port": 1883, "cloud_mqtt_tls_port": 8883, "device_id": ""}
    try:
        with open(CONFIG_PATH) as f:
            cfg.update(json.load(f))
    except (OSError, ValueError):
        pass
    if not cfg.get("device_id"):
        cfg["device_id"] = session_token.device_serial()
    return cfg


def cmd_topic(device_id):
    return "bulbbee/%s/cmd" % device_id


def state_topic(device_id):
    return "bulbbee/%s/state" % device_id


def register_topic(device_id):
    return "bulbbee/%s/register" % device_id


def _load_claim_token():
    """The claim token the app delivered over BLE (pair_set -> provisioning.json).
    The device presents it on activation so the cloud binds it to the claiming
    account (BULB-R6, proof of possession)."""
    try:
        with open(PROV_STATE_FILE) as f:
            return json.load(f).get("pair_token", "")
    except (OSError, ValueError):
        return ""


def activation_payload(device_id, token, claim_token):
    """Pure: the activation message the device publishes on connect so the cloud
    binds device -> owner via the claim token (BULB-R6)."""
    return {"device_id": device_id, "token": token, "claim_token": claim_token}


def parse_command(payload):
    """Pure: a cloud MQTT message -> the lighting command dict it carries, or
    None. Only the lighting keys pass through to the daemon."""
    try:
        msg = json.loads(payload.decode() if isinstance(payload, (bytes, bytearray)) else payload)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(msg, dict):
        return None
    cmd = {k: msg[k] for k in LIGHT_KEYS if k in msg}
    return cmd or None


def _log(msg):
    print("[tunnel] %s" % msg, flush=True)


def run():
    if not _HAS_MQTT:
        _log("paho-mqtt not available — cannot open tunnel, exiting")
        sys.exit(1)
    cfg = _load_config()
    dev = cfg["device_id"]
    secure = bool(cfg.get("secure"))
    client = bulb_client.BulbClient(port=int(cfg.get("http_port", 8082)))
    token = session_token.issue(dev, secure=secure)

    c = mqtt.Client(client_id="bulbbee-%s" % dev)
    c.username_pw_set(dev, token)               # device authority on the tunnel

    def on_connect(cl, userdata, flags, rc):
        _log("connected rc=%s, subscribing %s" % (rc, cmd_topic(dev)))
        cl.subscribe(cmd_topic(dev))
        # BULB-R6: announce ourselves so the cloud binds us to the claiming account.
        claim = _load_claim_token()
        cl.publish(register_topic(dev), json.dumps(activation_payload(dev, token, claim)))
        _log("published activation on %s (claim=%s)"
             % (register_topic(dev), "yes" if claim else "none"))

    def on_message(cl, userdata, m):
        cmd = parse_command(m.payload)
        if cmd is None:
            _log("ignored non-command message on %s" % m.topic)
            return
        try:
            client.apply(cmd)
            cl.publish(state_topic(dev), json.dumps(client.state()))
        except Exception as e:                  # daemon transiently down — tolerate
            _log("apply/publish failed (%s)" % e)

    c.on_connect = on_connect
    c.on_message = on_message

    if secure:
        c.tls_set()                             # validate the broker cert (ca-certificates)
        port = int(cfg.get("cloud_mqtt_tls_port", 8883))
    else:
        port = int(cfg.get("cloud_mqtt_port", 1883))

    _log("opening outbound tunnel to %s:%d (secure=%s)" % (cfg["cloud_host"], port, secure))
    c.connect(cfg["cloud_host"], port, keepalive=30)   # OUTBOUND, never listens
    c.loop_forever()


def _selfcheck():
    assert cmd_topic("abc") == "bulbbee/abc/cmd"
    assert state_topic("abc") == "bulbbee/abc/state"
    assert register_topic("abc") == "bulbbee/abc/register"
    assert activation_payload("dev", "tok", "claim") == \
        {"device_id": "dev", "token": "tok", "claim_token": "claim"}
    assert parse_command(b'{"scene":"rainbow","junk":1}') == {"scene": "rainbow"}
    assert parse_command(b'{"power":true,"brightness":10,"color":[1,2,3]}') == \
        {"power": True, "brightness": 10, "color": [1, 2, 3]}
    assert parse_command(b'not json') is None
    assert parse_command(b'[1,2,3]') is None
    assert parse_command(b'{"nothing":1}') is None
    print("cloud_tunnel selfcheck OK")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selfcheck":
        _selfcheck()
    else:
        run()
