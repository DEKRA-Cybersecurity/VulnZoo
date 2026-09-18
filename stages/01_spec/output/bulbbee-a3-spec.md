# BULB-A3 - Cloud plane: outbound TLS tunnel + emulator + session token (spec)

Target: `BULB-A3` (Phase 2, secure baseline for the cloud plane).

## Why it matters

The remote channel. The bulb opens and keeps alive an OUTBOUND connection to the cloud (it never listens on the Internet) and relays app commands to the local lighting daemon. The session token is the device's authority on that tunnel. Built robust first, the degradations (BULB-03 cleartext, BULB-04 static/derivable token) are the default form this baseline degrades to.

## Decisions taken (sensible defaults, project convention)

- **Emulator location:** the cloud broker lives in `src/cloud_api/bulbbee/` as a Docker service (MQTT broker), consistent with the careotter / owlcam cloud labs. The device-side tunnel client lives on the Pi in `/opt/bulbbee/`. The existing Flask REST API (`:5004`, the BULB-CLD JWT/BOLA surface) is left untouched.
- **Transport (ponytail, vuln-consistent):** MQTT. Default = plaintext MQTT `:1883` (the BULB-03 cleartext/replay substrate). Secure mode (`secure=true`) = MQTT over TLS `:8883`. `python3-paho-mqtt` is already in the image `.config`, so no new device dep, the paho import is guarded like `ble_light.py`'s dbus.
- **Session token (vuln-consistent):** default = derived from the (enumerable) Pi serial + a hardcoded vendor salt, so it is forgeable by anyone who knows the serial (the BULB-04 substrate). Secure mode = HMAC-SHA256 over `{dev, iat, exp, nonce}` under a random per-device secret (`/opt/bulbbee/.session_secret`, 0600), rotatable.

## Components

- New device module `session_token.py`: `issue(device_id, secure)`, `confirm(token, device_id, secure)`, stdlib only (`hmac`, `hashlib`, `base64`, `json`). The security spine, fully unit-tested.
- New device module `cloud_tunnel.py`: outbound MQTT client. Subscribes `bulbbee/<device_id>/cmd`, maps each message to a lighting command and applies it via the BULB-A1 `bulb_client.BulbClient`, publishes state to `bulbbee/<device_id>/state`. Authenticates with the session token (MQTT username=device_id, password=token). Guarded paho import.
- Cloud: add a `mosquitto` broker service to `src/cloud_api/bulbbee/docker-compose.yml` (+ `mosquitto.conf`), listening `:1883` (and `:8883` for TLS when certs are provided). Command relay = publish to the device cmd topic.
- Config: `config.json` gains `device_id`, `cloud_host`, `cloud_mqtt_port` (1883), `cloud_mqtt_tls_port` (8883). `.config`: enable `ca-certificates` for secure-mode TLS trust.

## Acceptance criteria

1. `session_token.issue` then `confirm` round-trips to the claims; a tampered token or an expired token returns `None`.
2. Static (default) key is derivable from the serial: a forged token signed with `_static_key(device_id)` confirms in default mode (BULB-04 substrate) but NOT in secure mode.
3. Secure key is a random per-device secret: two devices' secure tokens do not cross-confirm.
4. `cloud_tunnel.parse_command` maps a cloud JSON message to only the lighting keys (`power`/`brightness`/`color`/`scene`), returns `None` for junk; `cmd_topic`/`state_topic` are `bulbbee/<id>/cmd|state`.
5. `cloud_tunnel` never listens: it is an MQTT client (`connect()` outbound), and it applies commands through `bulb_client`, not by opening spidev.
6. `py_compile` clean; both modules' `--selfcheck` pass; paho absent degrades to a clean exit.
