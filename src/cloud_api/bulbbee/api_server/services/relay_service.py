"""relay_service.py - MQTT relay + device subscriber for the BulbBee cloud API.

Publishes control commands to the device's cmd topic (BULB-R1) and runs a
background subscriber that consumes device state (BULB-R3) and activation
(BULB-R6) messages, dispatching them to callbacks. Transport mirrors the device
posture: plaintext :1883 by default (BULB-P02 substrate), TLS :8883 in secure mode.
"""

import json
import threading

try:
    import paho.mqtt.publish as mqtt_publish
    import paho.mqtt.client as mqtt
    _HAS_MQTT = True
except ImportError:
    _HAS_MQTT = False


def device_from_topic(topic, kind):
    """Pure: the device_id in a `bulbbee/<device_id>/<kind>` topic, else None."""
    parts = topic.split("/")
    if len(parts) == 3 and parts[0] == "bulbbee" and parts[2] == kind:
        return parts[1]
    return None


class RelayService:
    def __init__(self, config):
        self.cfg = config

    def cmd_topic(self, device_id):
        return "bulbbee/%s/cmd" % device_id

    def publish(self, device_id, cmd):
        """Publish a lighting command to the device. Best-effort, never raises."""
        if not cmd or not _HAS_MQTT:
            return False
        kw = {"hostname": self.cfg.BROKER_HOST}
        if self.cfg.SECURE:
            kw["port"] = self.cfg.BROKER_TLS_PORT
            kw["tls"] = {}                     # validate the broker cert
        else:
            kw["port"] = self.cfg.BROKER_PORT
        try:
            mqtt_publish.single(self.cmd_topic(device_id), payload=json.dumps(cmd), **kw)
            return True
        except Exception:
            return False

    def _client(self):
        try:
            return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)   # paho 2.x
        except (AttributeError, TypeError):
            return mqtt.Client()                                   # paho 1.x

    def start_subscriber(self, on_state, on_register):
        """Start the background subscriber. on_state(device_id, dict) receives
        BULB-R3 state, on_register(device_id, dict) receives BULB-R6 activation."""
        if not _HAS_MQTT:
            return
        threading.Thread(target=self._run, args=(on_state, on_register), daemon=True).start()

    def _run(self, on_state, on_register):
        c = self._client()

        def on_connect(cl, userdata, flags, rc):
            cl.subscribe("bulbbee/+/state")
            cl.subscribe("bulbbee/+/register")

        def on_message(cl, userdata, m):
            try:
                msg = json.loads(m.payload.decode() if isinstance(m.payload, (bytes, bytearray)) else m.payload)
            except (ValueError, UnicodeDecodeError):
                return
            if not isinstance(msg, dict):
                return
            dev = device_from_topic(m.topic, "register")
            if dev is not None:
                on_register(dev, msg)
                return
            dev = device_from_topic(m.topic, "state")
            if dev is not None:
                on_state(dev, msg)

        c.on_connect = on_connect
        c.on_message = on_message
        if self.cfg.SECURE:
            c.tls_set()
            port = self.cfg.BROKER_TLS_PORT
        else:
            port = self.cfg.BROKER_PORT
        c.connect(self.cfg.BROKER_HOST, port, keepalive=30)
        c.loop_forever()
