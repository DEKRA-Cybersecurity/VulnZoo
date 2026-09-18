# BULB-A2 - BLE provisioning + control service: robust pairing (spec)

Target: `BULB-A2` (Phase 1, secure baseline for the BLE plane).

## Why it matters

The BLE GATT server (`ble_light.py`) is the app's local channel: lighting control (`0xFF30`) and provisioning (`0xFF40`). Built "robust first", the pairing is LE Secure Connections + Passkey Entry and the provisioning characteristics only work over an authenticated (bonded, MITM-protected) link. The Phase-4 findings (BULB-01 Just Works / broken passkey, BULB-02 no-auth control) are the degradations of this baseline, so the robust form must exist to degrade from.

## Design (non-destructive)

The default (shipped) path stays the intentional-vuln form: `set_pairable(False)`, no bonding, plain `read`/`write` provisioning characteristics, hardcoded PIN. The robust baseline is the `secure` branch (`bulbbee.@bulbbee[0].secure=1` -> `config.json` `secure:true`), consistent with BULB-SEC. Nothing hardens the default. Net-new, all gated on `SECURE`:

- **Pairing agent:** register an `org.bluez.Agent1` with `KeyboardDisplay` capability and make it the default agent, so pairing negotiates LE Secure Connections + Passkey Entry / Numeric Comparison instead of Just Works. The device generates a fresh random 6-digit passkey per pairing (`RequestPasskey`/`DisplayPasskey`). Default path registers no agent (Just Works substrate of BULB-01 preserved).
- **Adapter:** `set_pairable(True)` under `SECURE` (default stays `set_pairable(False)`).
- **Characteristic access control:** the provisioning characteristics (`0xFF41` auth, `0xFF42` config) require `encrypt-authenticated-read/write` under `SECURE`, so BlueZ refuses reads/writes on an unpaired or Just-Works link. Default keeps plain `read`/`write`.

The session-material robustness that is not the BLE plane's job (per-device local AES key = BULB-A4, session-token issue/rotate = BULB-A3, owner binding = BULB-05) is out of scope here. A2 delivers that the token/PSK exchange rides a bonded+MITM link when secure, the flags enforce it.

## Affected components

- Modify: `src/labs/bulbbee/files/opt/bulbbee/ble_light.py` (add pairing agent, secure char flags, secure `set_pairable`). Default path unchanged.
- Repackage: `bulbbee.tar.gz`.

## Acceptance criteria

1. `_prov_flags(base, secure=False)` returns the base flags unchanged; `secure=True` maps `read`/`write` to `encrypt-authenticated-read`/`encrypt-authenticated-write` and leaves `notify`/`write-without-response`.
2. `_gen_passkey()` returns an int in `[0, 999999]`.
3. With `secure=false` (default), no agent is registered and `set_pairable(False)` (BULB-01 substrate intact); the existing `--selfcheck` still passes unchanged.
4. With `secure=true`, `main()` exports and registers the `Agent1` as default agent and `set_pairable(True)` (verified by code path; live pairing needs a BLE central).
5. `py_compile` clean; `--selfcheck` passes (extended with the two new pure helpers).
