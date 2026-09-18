# BULB-EVAL - Verification

Target: `BULB-EVAL` (assessor evaluation battery).

| # | Criterion | Result |
|---|-----------|--------|
| 1 | 8-test battery with commands + default/secure results + weakness + requirement | `ASSESSOR_BATTERY.md` tests 0-7. PASS |
| 2 | scoreboard maps test -> weakness -> EN 303 645 -> secure refusal | scoreboard table present. PASS |
| 3 | tests reference BULB-P0x + classic | each test names both. PASS |

## Note

Test 5 (token spoof) is directly runnable and its result (`confirms default: True`, `confirms secure: False`) is proven by `session_token --selfcheck`. The network/BLE tests (0-4, 6-7) need the live Pi + a BLE central/sniffer; the logic each depends on is unit-proven by the A-series selfchecks. Full live run on-Pi pending.

Badge -> DONE (battery documented + mapped; live full run on-Pi pending).
