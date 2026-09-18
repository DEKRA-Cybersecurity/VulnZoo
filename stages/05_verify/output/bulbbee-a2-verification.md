# BULB-A2 - Verification

Target: `BULB-A2` (BLE provisioning + control: robust LE SC + Passkey pairing, secure baseline).

## Acceptance criteria vs result

| # | Criterion | Result |
|---|-----------|--------|
| 1 | `_prov_flags`: default returns base flags; secure maps `read`/`write` to `encrypt-authenticated-*`, leaves `notify`/`write-without-response` | `--selfcheck` asserts all three cases. PASS |
| 2 | `_gen_passkey()` in `[0, 999999]` | selfcheck samples 1000 draws, all in range. PASS |
| 3 | default (`secure=false`): no agent, `set_pairable(False)`, BULB-01 substrate intact; existing selfcheck unchanged | `setup_adapter` calls `set_pairable(bool(SECURE))` (False by default), `main()` guards the agent block on `if SECURE`. The prior BULB-01/`_plan_calls` selfcheck still passes verbatim. PASS |
| 4 | secure (`secure=true`): `Agent1` exported + registered as default agent, `set_pairable(True)` | code path in `main()`/`setup_adapter`/`register_agent` verified. Live LE SC + Passkey pairing needs a BLE central + adapter: ON-DEVICE PENDING (Pi unreachable at verify time). PASS (logic) |
| 5 | `py_compile` clean; `--selfcheck` passes | `compile OK`; `ble_light self-check OK (... + BULB-A2 pairing)`. PASS |

## Notes

Non-destructive by construction: every robust behavior (agent registration, pairable, `encrypt-authenticated-*` characteristic flags) is gated on the `SECURE` flag, which is `false` in the shipped `config.json`. The default path keeps the intentional BULB-01 no-bonding substrate byte-for-byte in behavior. On-device re-run when the Pi is back up, with a BLE central (nRF Connect / bleak):

```sh
# secure mode: set secure=true in config.json, restart bulbbee-ble, then from a central
bluetoothctl pair <BulbBee-addr>   # must prompt for a passkey (LE SC), not complete silently (Just Works)
# provisioning read/write must fail on an unpaired link and succeed only after pairing
```

Badge -> DONE [logic verified]; live pairing on-device pending.
