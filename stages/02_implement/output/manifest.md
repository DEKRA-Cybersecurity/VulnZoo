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

## BULB-R1 - Cloud command relay (API -> broker cmd topic)

| Draft (output/code/) | Target (src/) | Mode | Note |
|---|---|---|---|
| `cloud_api/bulbbee/api_server/app.py` | `src/cloud_api/bulbbee/api_server/app.py` | 0644 | `/state` + new `/scene` publish the lighting subset to `bulbbee/<bulb_id>/cmd` via `paho.mqtt.publish.single`; BOLA preserved (secure branch enforces owner + TLS) |
| `cloud_api/bulbbee/api_server/requirements.txt` | `src/cloud_api/bulbbee/api_server/requirements.txt` | 0644 | add `paho-mqtt` (cloud-side only dep) |
| `cloud_api/bulbbee/docker-compose.yml` | `src/cloud_api/bulbbee/docker-compose.yml` | 0644 | pass `BULBBEE_BROKER_HOST`/`_PORT` to `bulbbee-cloud`, `depends_on: bulbbee-broker` |

Non-destructive: default posture unchanged (BOLA + plaintext `:1883`), the relay is added on top and the ownership check runs only under `BULBBEE_SECURE=1`. `bulb_id -> device_id` is a `ponytail:` identity map (topic == account bulb_id), superseded by the BULB-R2 binding. R1 stopgap: the demo device runs with `config.json device_id` set to the account `bulb_id` (baked into the tarball).

Verified offline: `py_compile` clean, `app.py --selfcheck` OK (`relay_payload`/`cmd_topic` pure cases + Flask `test_client`: alice drives bob's bulb-2 with the relay captured = BOLA remote hijack, scene relay, 401 relays nothing). The `InsecureKeyLengthWarning` on the 14-byte secret is the intentional weak-JWT finding (API2), not a defect. Live broker round-trip (`cloudctl.sh sub` observes the POST, tunnel `parse_command` maps it) deferred to `05_verify`.

## BULB-R2 - Cloud registration + account-device binding

| Draft (output/code/) | Target (src/) | Mode | Note |
|---|---|---|---|
| `cloud_api/bulbbee/api_server/app.py` | `src/cloud_api/bulbbee/api_server/app.py` | 0644 | `BULBS` records gain `device_id`/`binding_token` (seeded bee-0001/bee-0002); new `/api/register`; `cmd_topic`/`relay` take the transport `device_id`; control resolves `bulb_id -> device_id` via the binding; `_bulb_for_device`/`_new_bulb_id` |

Same file as BULB-R1 (evolved), `requirements.txt`/`docker-compose.yml` unchanged. Non-destructive: default keeps BOLA + unenforced binding. The R1 `bulb_id -> device_id` identity `ponytail:` note is superseded by the real binding. BULB-P05 owner binding is lifted from the app to the cloud, recorded but unenforced in default, authoritative in secure (`/api/register` 409 on cross-owner re-bind + owner check on control).

Verified offline: `py_compile` clean, `app.py --selfcheck` OK (`_bulb_for_device`/`cmd_topic` pure cases + `test_client`: control relays to the bound device_id, register a new device then drive it by the returned bulb_id, register needs auth + device_id, 401 relays nothing). Live register-then-relay + secure 409 deferred to `05_verify`.

## BULB-R3 - Device-to-cloud state uplink

| Draft (output/code/) | Target (src/) | Mode | Note |
|---|---|---|---|
| `cloud_api/bulbbee/api_server/app.py` | `src/cloud_api/bulbbee/api_server/app.py` | 0644 | background subscriber to `bulbbee/+/state`, `ingest_state` reflects the device report into the bound record (via R2 `_bulb_for_device`), so `GET /state` is live; `device_from_state_topic`, `_state_listener` (paho 2.x `CallbackAPIVersion.VERSION1`), daemon thread started on the server path only |

Same file as R1/R2 (evolved), `requirements.txt`/`docker-compose.yml` unchanged. No new weakness, honest wiring. The listener never runs in `--selfcheck`, a missing paho degrades to no listener.

Verified offline: `py_compile` clean, `app.py --selfcheck` OK (`device_from_state_topic` parse, `ingest_state` reflects into `BULBS["bulb-2"]`, unregistered device ignored, and `GET /state` returns the ingested `brightness`/`scene`). Live device-publish -> `GET /state` deferred to `05_verify`.

## BULB-R4 - App cloud client (remote leg)

| Draft (output/code/) | Target (src/) | Mode | Note |
|---|---|---|---|
| `vulnzoo_apps/bulbbee_app/app/src/main/java/com/vulnzoo/bulbbee_app/cloud/CloudClient.java` | `src/vulnzoo_apps/bulbbee_app/app/src/main/java/com/vulnzoo/bulbbee_app/cloud/CloudClient.java` | 0644 | dependency-free REST client (`login`/`control`/`scene`/`getState`), plain HTTP, `main` self-check |
| `.../cloud/CloudRepository.java` | `src/.../cloud/CloudRepository.java` | 0644 | Android singleton (mirrors `BleRepository`), JWT in plaintext prefs + Logcat (M9), state polling -> LiveData |
| `.../ui/LightViewModel.java` | `src/.../ui/LightViewModel.java` | 0644 | `Transport { BLE, CLOUD }` seam, `cloudConnect`, control routing; BLE path unchanged |

Net-new: `cloud/` package. Modified: `LightViewModel` (seam only). No new Gradle dep (`java.net` only). The automatic transport selector is BULB-R5.

Verified offline: `javac` clean on `CloudClient` (JDK 21) and `CloudClient --selfcheck` OK (`extractToken` cases). The Android glue (`CloudRepository`, `LightViewModel`) is consistent with the app package layout but needs the Android SDK to compile (same limitation as BULB-APP). Live cloud drive of the sim device via `CloudClient` deferred to `05_verify`.

## BULB-R5 - App local plane + transport selector

| Draft (output/code/) | Target (src/) | Mode | Note |
|---|---|---|---|
| `.../local/LocalClient.java` | `src/.../local/LocalClient.java` | 0644 | AES-CCM `:6668` frame codec (BouncyCastle lightweight), static firmware key (BULB-P03), TCP send + `reachable` probe, `main` self-check |
| `.../local/LocalRepository.java` | `src/.../local/LocalRepository.java` | 0644 | Android singleton (mirrors Ble/Cloud repos), wraps `LocalClient` on an executor, LiveData |
| `.../ui/TransportSelector.java` | `src/.../ui/TransportSelector.java` | 0644 | pure `Transport { LOCAL, CLOUD, BLE, NONE }` + `choose` (LAN -> Cloud -> BLE) + scan gating, `main` self-check |
| `.../ui/LightViewModel.java` | `src/.../ui/LightViewModel.java` | 0644 | uses `TransportSelector.Transport`, three legs, `autoSelect` failover + scan gating, control routing |
| `gradle/libs.versions.toml` | `src/.../gradle/libs.versions.toml` | 0644 | + `bcprov-jdk18on` 1.80 |
| `app/build.gradle.kts` | `src/.../app/build.gradle.kts` | 0644 | + `implementation(libs.bcprov)` |

Net-new: `local/` package + `ui/TransportSelector`. Modified: `LightViewModel` (three-transport routing + failover), gradle (bcprov, because AES-CCM is not in the Android/JDK provider). BLE path unchanged.

Verified offline: `javac` + `LocalClient --selfcheck` OK against `bcprov-1.80.jar` (CCM round-trip + tamper -> null), AES-CCM wire compatibility proven both directions against the reference CCM (`cryptography.AESCCM`, same construction as the server's pycryptodome), and `TransportSelector --selfcheck` OK (LAN -> Cloud -> BLE priority + scan gating). The Android glue (`LocalRepository`, `LightViewModel`) needs the SDK (BULB-APP limitation). Live socket round-trip deferred to `05_verify`.
