# BULB-SEC - Secure-mode toggle (spec)

Target: `BULB-SEC` (ongoing). Consolidate the secure branches this plan added so one flag flips every plane.

## Scope

The robust branches for the plan's mechanisms were built target-by-target (BULB-A2 pairing, BULB-A3 token/tunnel, BULB-A4 local key, BULB-A5 owner binding), each gated on `secure`. BULB-SEC's remaining job is (a) confirm every service reads the same `secure` flag so one toggle is authoritative, and (b) document the consolidated mechanism matrix (degraded default vs robust branch vs code) as the CRA "what conformity looks like" reference.

## Design

- Source of truth: `config.json` `"secure"`, read by `lighting_service.py` (`_secure()`), `ble_light.py` (`SECURE`), and the plane modules `session_token`/`cloud_tunnel`/`local_tcp`/`secret_store` (all `cfg.get("secure")` / `secure` param). No new sync mechanism (cold-boot re-extraction restores config.json, so bake the value for a secure image).
- Deliverable doc: `src/docs/BulbBee/SECURE_MODE.md` (the matrix).

## Acceptance criteria

1. `SECURE_MODE.md` lists every mechanism with its degraded default (finding ID), robust secure branch (baseline ID), and code file.
2. Each new plane module honours the same `secure` flag (grep-verifiable).
3. The divergence is provable per mechanism by the A-series selfchecks.
