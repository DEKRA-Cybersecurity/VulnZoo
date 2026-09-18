# BULB-A3 - Verification

Target: `BULB-A3` (cloud plane: outbound TLS tunnel + emulator broker + session token).

## Acceptance criteria vs result

| # | Criterion | Result |
|---|-----------|--------|
| 1 | `session_token` issue -> confirm round-trips; tampered / expired -> `None` | `session_token --selfcheck` asserts round-trip, expiry, tamper. PASS |
| 2 | default key derivable from serial: forge confirms in default, not in secure | selfcheck forges with `_static_key(device_id)`: confirms default (BULB-04 substrate), rejected in secure. PASS |
| 3 | secure per-device secret: cross-device token does not confirm | selfcheck issues under secret A, swaps `SECRET_FILE` to B, confirm -> `None`. PASS |
| 4 | `parse_command` keeps only lighting keys, `None` on junk; topics `bulbbee/<id>/cmd|state` | `cloud_tunnel --selfcheck` asserts all cases. PASS |
| 5 | tunnel never listens; applies via `bulb_client`, not spidev | `cloud_tunnel.run()` is an MQTT client (`c.connect()` outbound, `loop_forever`), commands go through `bulb_client.BulbClient.apply`. PASS (code-evident) |
| 6 | `py_compile` clean; both selfchecks pass; paho absent degrades cleanly | `compile OK` x2, `session_token selfcheck OK`, `cloud_tunnel selfcheck OK`; `_HAS_MQTT` guard exits cleanly when paho missing. PASS |

## Live (on-device / broker) pending

The end-to-end tunnel (device connects out to the broker, a published `cmd` drives the ring) needs the broker up and the Pi reachable:

```sh
# cloud host: bring up the emulator broker
cd src/cloud_api/bulbbee && docker compose up -d bulbbee-broker
# device: point cloud_host at the broker, enable the tunnel
uci/edit config.json cloud_host; /etc/init.d/bulbbee-tunnel enable && start
# attacker/app: publish a command (default plaintext = the BULB-03 substrate)
mosquitto_pub -h <broker> -t bulbbee/<device_id>/cmd -m '{"scene":"rainbow"}'
# the ring animates; mosquitto_sub on bulbbee/<device_id>/state shows the snapshot
```

Badge -> DONE [logic verified]; live tunnel + broker round-trip on-device pending (Pi/broker not up at verify time).
