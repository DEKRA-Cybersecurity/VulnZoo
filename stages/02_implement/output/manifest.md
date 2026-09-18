# 02_implement manifest

Drafts written this stage, with their promotion target (`04_integrate` copies `output/code/<path>` -> `src/<path>`).

## BULB-A0 - Physical base + local CLI

| Draft (output/code/) | Target (src/) | Mode | Note |
|---|---|---|---|
| `labs/bulbbee/files/usr/bin/bulbctl` | `src/labs/bulbbee/files/usr/bin/bulbctl` | 0755 | local CLI, thin client of `:8082`, never opens spidev |

Reused unchanged (no draft): `ws2812.py`, `99-bulbbee-spi.sh`, `lighting_service.py`. `config.json` `led_count` stays a fitted-ring knob (16 on the current hardware).

Verified offline: `sh -n bulbctl` clean. Runtime check (bulbctl -> `:8082` -> state) deferred to `05_verify` on the Pi.

## BULB-A1 - Control daemon: single state owner + backend adapter

| Draft (output/code/) | Target (src/) | Mode | Note |
|---|---|---|---|
| `labs/bulbbee/files/opt/bulbbee/bulb_client.py` | `src/labs/bulbbee/files/opt/bulbbee/bulb_client.py` | 0644 | shared plane adapter (`BulbClient.apply()`/`.state()`), stdlib only, never opens spidev |

Reused unchanged: `lighting_service.py` (single state owner). `ble_light.py` keeps its inline forwarder (not refactored, provisioning depends on it).

Verified offline: `py_compile` clean, `--selfcheck` OK (command-split cases). Live apply/state round-trip on `:8082` deferred to `05_verify` (Pi unreachable at package time); the same round-trip is already certified in BULB-A0.

## BULB-A2 - BLE provisioning + control: robust pairing

| Draft (output/code/) | Target (src/) | Mode | Note |
|---|---|---|---|
| `labs/bulbbee/files/opt/bulbbee/ble_light.py` | `src/labs/bulbbee/files/opt/bulbbee/ble_light.py` | 0755 | added `Agent1` pairing agent, `_gen_passkey`, `_prov_flags`, secure `set_pairable`; all gated on `SECURE` |

Non-destructive: robust pairing only under `secure=true`. Default path (no agent, `set_pairable(False)`, plain characteristics) unchanged, BULB-01 substrate intact.

Verified offline: `py_compile` clean, `--selfcheck` OK (`_prov_flags` both branches + `_gen_passkey` range + unchanged BULB-01 checks). Live LE SC + Passkey pairing deferred to `05_verify` (needs Pi + BLE central).

## BULB-A3 - Cloud plane: outbound tunnel + emulator + session token

| Draft (output/code/) | Target (src/) | Mode | Note |
|---|---|---|---|
| `labs/bulbbee/files/opt/bulbbee/session_token.py` | `src/labs/bulbbee/files/opt/bulbbee/session_token.py` | 0644 | HMAC session token; default = serial-derived (BULB-04 substrate), secure = random per-device secret |
| `labs/bulbbee/files/opt/bulbbee/cloud_tunnel.py` | `src/labs/bulbbee/files/opt/bulbbee/cloud_tunnel.py` | 0644 | outbound MQTT client, relays via `bulb_client`, guarded paho import |
| `labs/bulbbee/files/etc/init.d/bulbbee-tunnel` | `src/labs/bulbbee/files/etc/init.d/bulbbee-tunnel` | 0755 | procd service, disabled by default (no respawn against absent broker) |
| `labs/bulbbee/files/opt/bulbbee/config.json` | (same) | 0644 | + `device_id`, `cloud_host`, `cloud_mqtt_port`, `cloud_mqtt_tls_port` |

Also (not under output/code, promoted directly): `src/cloud_api/bulbbee/docker-compose.yml` (+ `bulbbee-broker` mosquitto service), `src/cloud_api/bulbbee/mosquitto.conf`, `src/labs/vulnzoo/.config` (`ca-certificates=y` for secure TLS).

Verified offline: `py_compile` clean x2, `session_token --selfcheck` + `cloud_tunnel --selfcheck` OK. Live tunnel + broker round-trip deferred to `05_verify` (needs Pi + broker up).

## BULB-A4 - LAN/TCP plane: local port + AES-CCM

| Draft (output/code/) | Target (src/) | Mode | Note |
|---|---|---|---|
| `labs/bulbbee/files/opt/bulbbee/local_tcp.py` | `src/labs/bulbbee/files/opt/bulbbee/local_tcp.py` | 0644 | `:6668` AES-CCM plane; static key default (BULB-03/06 substrate), per-device key secure |
| `labs/bulbbee/files/etc/init.d/bulbbee-lan` | `src/labs/bulbbee/files/etc/init.d/bulbbee-lan` | 0755 | procd service, enabled by the hook |
| `labs/bulbbee/files/usr/lib/vulnzoo-hooks/profile-init.d/55-bulbbee-lan.sh` | `src/.../55-bulbbee-lan.sh` | 0755 | enable + start hook (mirrors 50-bulbbee-ble.sh) |

Also promoted directly: `src/labs/vulnzoo/.config` (`python3-cryptodome=y`).

Verified offline: `py_compile` clean, `sh -n` clean (init + hook), `local_tcp --selfcheck` OK with crypto (AES-CCM round-trip, tamper -> None, BULB-03 key isolation) against pycryptodome. Live `:6668` round-trip deferred to `05_verify` (needs Pi up).

## BULB-A5 - Secret store (simulated flash)

| Draft (output/code/) | Target (src/) | Mode | Note |
|---|---|---|---|
| `labs/bulbbee/files/opt/bulbbee/secret_store.py` | `src/labs/bulbbee/files/opt/bulbbee/secret_store.py` | 0644 | `LAYOUT` map + owner-binding store; non-invasive (default `check_owner` True) |

Verified offline: `py_compile` clean, `--selfcheck` OK (layout modes, write-once bind, secure-vs-default enforcement, dir 0700).
