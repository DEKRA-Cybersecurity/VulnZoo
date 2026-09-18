# BULB-P01..P07 - Verification

Targets: `BULB-P01`..`BULB-P07` (three-plane weakness findings). The deliverable is documentation of an already-shipped default degradation, so verification is (a) the docs exist and map correctly, and (b) the degradation is provable by the A-series selfchecks.

## Docs

| # | Criterion | Result |
|---|-----------|--------|
| 1 | 7 `BULB-P0x` docs under `Vulns/Planes/` with full frontmatter + sections | present (P01..P07). PASS |
| 2 | `maps_to` names the baseline degraded + classic overlap | each doc's mapping table + `maps_to` field. PASS |
| 3 | `Planes/README.md` + main `Vulns/README.md` mapping/pointer | both updated. PASS |
| 5 | no classic `BULB-01..07` doc modified | classic `IoT/` docs untouched (only the README got a new section). PASS |

## Degradation provable (criterion 4) - from the A-series selfchecks

| Finding | Proof the default is weak and secure fixes it |
|---------|----------------------------------------------|
| P01 pairing MITM | `ble_light --selfcheck`: `_prov_flags(base, False)` = plain, `_prov_flags(base, True)` = `encrypt-authenticated-*`; default `set_pairable(False)`, agent only `if SECURE` |
| P02 PSK cleartext | `ble_light --selfcheck`: `_prov_read()["wifi_psk"]` returns the PSK in default; secure branch omits it |
| P03 static local key | `local_tcp --selfcheck`: `decrypt_frame(secure_key, static_frame) is None` (static-key frame not readable per-device) |
| P04 session token | `session_token --selfcheck`: `confirm(forged, secure=False)` not None (forge works default), `confirm(forged, secure=True) is None` |
| P05 owner binding | `secret_store --selfcheck`: `check_owner("mallory", secure=False) is True`, `check_owner("mallory", secure=True) is False` |
| P06 proximity=control | `local_tcp` handler gates only on the AES-CCM tag; with the shared default key (P03) + `check_owner` True (P05) any LAN host controls it |
| P07 secure-by-default | `/debug` gated by `debug` (default true) and `_secure()`; `_prov_auth` default has no lockout and `authenticated` never clears |

## On-Pi repro (pending)

The live exploit runs (sniff pairing, forge a `:6668` frame with `b"bulbbee-local-16"`, `curl /debug`) need the Pi up, see each `BULB-P0x` doc's Steps to Reproduce. The logic that each exploit depends on is proven by the selfchecks above.

Badge -> DONE (documented, substrate + secure comparison proven by selfcheck; live exploit on-Pi pending).
