# BULB-P01..P07 - Three-plane weaknesses (spec)

Targets: `BULB-P01`..`BULB-P07` (Phase 4, seed the weaknesses). One consolidated spec, the seven findings share one shape.

## Decision (user, this session)

The blueprint's three-plane weaknesses get a new ID axis `BULB-P01..P07` under `src/docs/BulbBee/Vulns/Planes/`, mapping to the intact classic `BULB-01..07` catalogue where they overlap and net-new where they do not. The classic docs are not rewritten (they document still-present code, e.g. unsigned OTA, scene DoS), so Layer 3 stays in sync with Layer 4.

## Shape

Each finding is the shipped default degradation of a bring-up secure baseline (BULB-A2..A5). The code substrate already exists, it is the default branch built in the A-series, selectable back to robust with `secure=true` (BULB-SEC). So the Phase-4 deliverable per target is the finding doc (03) + the mapping, not new vulnerable code.

| ID | Finding | Substrate (default branch) | Baseline degraded |
|----|---------|----------------------------|-------------------|
| P01 | BLE pairing MITM | `ble_light.py` `set_pairable(False)`, no agent, plain prov flags | BULB-A2 |
| P02 | WiFi PSK over BLE cleartext | `ble_light.py` `_prov_read` returns PSK, unbonded link | BULB-A2 |
| P03 | static local key from firmware | `local_tcp.py` `STATIC_LOCAL_KEY` | BULB-A4 |
| P04 | session token static/derivable | `session_token.py` `_static_key` (salt+serial) | BULB-A3 |
| P05 | owner binding app-only | `secret_store.py` `check_owner` returns True | BULB-A5 |
| P06 | LAN proximity = control | `local_tcp.py` key-only gate + no owner check | BULB-A4/A5 |
| P07 | secure-by-default violations | `lighting_service.py` `/debug` on, prov logging, open re-provisioning | all A-series |

## Acceptance criteria

1. Each `BULB-P0x` doc exists under `Vulns/Planes/` with full frontmatter (id, title, category, status, severity, owasp, standard, regulation, cwe, maps_to, affected_components) and Why / Root Cause (with the code snippet marking the default vs secure branch) / Repro / Expected / How-it-should-be / Mapping.
2. Each doc's `maps_to` names the degraded baseline and the classic overlap (or net-new).
3. `Planes/README.md` and the main `Vulns/README.md` carry the mapping table and a pointer.
4. The degradation is provable: the corresponding A-series `--selfcheck` already asserts the secure-vs-default divergence (e.g. `confirm(forged, secure=True) is None`, `decrypt_frame(secure_key, static_frame) is None`, `check_owner(secure=True)` rejects).
5. No classic `BULB-01..07` doc is modified.
