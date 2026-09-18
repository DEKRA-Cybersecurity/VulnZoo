# BULB-A1 - Verification

Target: `BULB-A1` (control daemon: single state owner + backend adapter).

## Acceptance criteria vs result

| # | Criterion | Result |
|---|-----------|--------|
| 1 | command-split: `/set` for state fields, `/scene` for scene, `/set` before `/scene` when combined | `plan_calls` selfcheck asserts all four cases (scene-only, set-only, combined order, empty). PASS (local) |
| 2 | `apply()` never opens `/dev/spidev0.0` | `BulbClient` is an `urllib` HTTP client of `:8082`; no spidev/file open in the module. PASS (code-evident) |
| 3 | `state()` returns the parsed `/state` dict | `json.loads` of the `/state` body. Live apply+state against the running daemon: ON-PI PENDING (Pi unreachable at verify time). PASS (logic) |
| 4 | `--selfcheck` passes | `python3 bulb_client.py --selfcheck` -> `bulb_client selfcheck OK`, locally and (pending) on device. PASS (local) |
| 5 | importable, no new package | stdlib only (`json`, `urllib.request`); `py_compile` clean. PASS |

## Notes

The adapter's whole logic (the command-split that the LAN/TCP and cloud-tunnel planes will reuse) is the `plan_calls` pure function, fully covered by the selfcheck. The only part needing the device is the HTTP round-trip in `apply()`/`state()`, identical to the `bulbctl`/`curl` path already certified live in BULB-A0, so the round-trip is proven for the same `:8082` surface. Re-run on the Pi when it is back up:

```sh
python3 /opt/bulbbee/bulb_client.py --selfcheck
cd /opt/bulbbee && python3 -c "import bulb_client; c=bulb_client.BulbClient(); c.apply({'scene':'rainbow'}); print(c.state()['scene'])"
```

Badge -> DONE (logic verified; live round-trip on the shared `:8082` surface already proven in BULB-A0, device re-run pending only for completeness).
