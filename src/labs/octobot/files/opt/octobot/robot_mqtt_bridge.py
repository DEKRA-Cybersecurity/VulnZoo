#!/usr/bin/env python3
# robot_mqtt_bridge.py - MQTT -> serial bus.
#
# Subscribes to the no-auth mosquitto broker and forwards payloads to the serial
# bus (127.0.0.1:2000). No credentials, no TLS. The bridge auto-injects the
# hardcoded actuator password, so anyone who can publish to the topic can move
# the arm. [IoT:I2] [IoT:I7]
#   mosquitto_pub -h <pi> -t cell01/cmd -m "S0:0"
import os
import socket
import time
import paho.mqtt.client as mqtt

BUS_HOST = '127.0.0.1'
BUS_PORT = int(os.environ.get('OCTOBOT_BUS_PORT', '2000'))
MQTT_HOST = os.environ.get('OCTOBOT_MQTT', '127.0.0.1')
TOPIC = os.environ.get('OCTOBOT_MQTT_TOPIC', 'cell01/cmd')

# Hardcoded actuator password shared with the serial bus and Arduino firmware. [IoT:I1]
HARD_CODED_PASSWORD = 'OctoSuperBot2026'
MOVEMENT_PREFIXES = ('S0:', 'S1:', 'S2:', 'S3:', 'RECORD', 'PLAY', 'STOP', 'DEMO', 'SPD:')


def is_movement(cmd):
    return cmd.strip().startswith(MOVEMENT_PREFIXES)


def bus_send(cmd):
    cmd = cmd.strip()
    if is_movement(cmd):
        cmd = f'PASS:{HARD_CODED_PASSWORD} {cmd}'
    try:
        with socket.create_connection((BUS_HOST, BUS_PORT), timeout=2) as s:
            s.sendall((cmd + '\n').encode())
    except OSError:
        pass


def on_connect(client, userdata, flags, rc, *args):
    client.subscribe(TOPIC)


def on_message(client, userdata, msg):
    bus_send(msg.payload.decode(errors='replace'))


def main():
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)  # paho-mqtt 2.x
    except AttributeError:
        client = mqtt.Client()                                  # paho-mqtt 1.x
    client.on_connect = on_connect
    client.on_message = on_message
    for _ in range(30):                       # wait out the broker startup race
        try:
            client.connect(MQTT_HOST, 1883, 60)   # [IoT:I2] anonymous, [IoT:I7] plaintext
            break
        except OSError:
            time.sleep(2)
    else:
        return                                # no broker reachable, exit quietly
    client.loop_forever()


if __name__ == '__main__':
    main()
