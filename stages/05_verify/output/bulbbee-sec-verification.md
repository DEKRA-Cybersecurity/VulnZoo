# BULB-SEC - Verification

Target: `BULB-SEC` (secure-mode toggle).

| # | Criterion | Result |
|---|-----------|--------|
| 1 | `SECURE_MODE.md` matrix (mechanism / default finding / robust branch / code) | present, 12 rows across BLE / cloud / LAN / storage / lighting. PASS |
| 2 | every plane module honours the same `secure` flag | `ble_light` SECURE, `lighting_service` `_secure()`, `session_token`/`local_tcp`/`secret_store`/`cloud_tunnel` `secure` param from `cfg.get("secure")`. PASS (grep-verified) |
| 3 | divergence provable per mechanism | A-series selfchecks assert default-vs-secure: `ble_light` (`_prov_flags`, `_prov_read`), `session_token` (forge), `local_tcp` (`decrypt_frame`), `secret_store` (`check_owner`), `lighting_service` (`/debug` gate). PASS |

## Note

Full live toggle (flip `secure:true`, rebuild, confirm every plane refuses the default-mode exploit) needs the Pi up. Each mechanism's flip is unit-proven by the selfcheck it ships with.

Badge -> DONE (per-mechanism robust branches implemented + matrix documented; full-image live toggle on-Pi pending).
