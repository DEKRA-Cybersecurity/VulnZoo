# BULB-A5 - Verification

Target: `BULB-A5` (secret store, simulated flash).

## Acceptance criteria vs result

| # | Criterion | Result |
|---|-----------|--------|
| 1 | `LAYOUT` names session secret, local key (derived), provisioning cache, owner binding, each restrictive mode | `--selfcheck` asserts every entry mode is `0o600`; dir is `0o700`. PASS |
| 2 | `bind_owner` write-once (second bind with a different id keeps the first) | selfcheck: `bind_owner("alice")` then `bind_owner("mallory")` -> owner stays `alice`. PASS |
| 3 | `check_owner` secure requires a match; default always True (BULB-05 substrate) | selfcheck: secure rejects `mallory`, accepts `alice`; default accepts `mallory`. PASS |
| 4 | `ensure_store` creates the dir at 0700 | selfcheck asserts `stat` mode `0o700`. PASS |
| 5 | `py_compile` clean; `--selfcheck` passes | `compile OK`; `secret_store selfcheck OK`. PASS |

## Notes

Non-invasive by construction: the default `check_owner` returns True, so shipping the module does not change the working provisioning/control path. The owner-binding store is populated when a plane opts in (or in secure mode), and the Phase-4 BULB-05 finding is the documented default-not-enforced behavior. On-device check when the Pi is up: `python3 /opt/bulbbee/secret_store.py` prints the layout and the current owner, and `ls -l /opt/bulbbee/secrets/` shows 0700 with `owner.json` 0600 once bound.

Badge -> DONE.
