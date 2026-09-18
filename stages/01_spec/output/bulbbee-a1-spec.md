# BULB-A1 - Control daemon: single state owner + backend adapter (spec)

Target: `BULB-A1` (Phase 0, bring-up, no intentional weakness).

## Why it matters

The three planes (BLE, cloud tunnel, LAN/TCP) must all drive the same ring without a second SPI writer. The control daemon is the single owner of the lighting state, and each plane is a thin adapter that translates its wire format into lighting commands applied through one interface. Formalising that contract now is what lets A2/A3/A4 plug in cleanly instead of each re-implementing ring access.

## Design

- **Single state owner (reuse):** `lighting_service.py` already owns the state and the ring, exposing the local control surface on `:8082` (`/set`, `/scene`, `/state`). It stays the one writer. No refactor of the running service.
- **Backend adapter (net-new):** a small shared `bulb_client.py` (stdlib only) that any plane imports to apply a command dict (`power`/`brightness`/`color`/`scene`) and to read state, by talking to the daemon's local surface. It centralises the command-split (`/set` vs `/scene`) so the LAN/TCP plane (A4) and the cloud tunnel (A3) do not each re-derive it.
- **Non-risky:** the existing BLE server (`ble_light.py`) keeps its own inline `_plan_calls`/`_apply_command` (working, provisioning depends on it) and is not refactored in this pass. `bulb_client.py` is the shared path for the new planes; migrating BLE onto it is a later, optional cleanup (ponytail: no risky refactor of working code).

## Affected components

- Reuse, unchanged: `src/labs/bulbbee/files/opt/bulbbee/lighting_service.py`.
- New: `src/labs/bulbbee/files/opt/bulbbee/bulb_client.py` (backend adapter + self-check).
- Repackage: `bulbbee.tar.gz`.

## Acceptance criteria

1. `bulb_client.BulbClient.apply({"scene":"rainbow"})` posts `/scene`; `apply({"power":true,"brightness":200,"color":[r,g,b]})` posts `/set`; a combined dict posts both, in `/set` then `/scene` order.
2. `apply()` never opens `/dev/spidev0.0` (it is an HTTP client of the daemon).
3. `state()` returns the parsed `/state` dict.
4. A `--selfcheck` self-check verifies the command-split (pure, no network) and passes.
5. Importable on the device (`python3 -c "import bulb_client"`) with no new package.
