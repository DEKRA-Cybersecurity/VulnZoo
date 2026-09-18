# BULB-EVAL - Assessor evaluation battery (spec)

Target: `BULB-EVAL` (Phase 5). One guided assessor run against the live device.

## Scope

Consolidate the per-finding repro steps (scattered across the `Vulns/` docs and `LAB_SETUP.md`) into a single ordered battery a student-assessor follows: surface scan, debug dump, unauth LAN control, BLE sniff + pairing MITM, secret recovery, session-token spoof, device hijack, abusive re-provisioning. Each test names the weakness (P0x / classic) and the EN 303 645 / CRA requirement it fails, and states whether `secure=true` refuses it, so the run doubles as the vuln-vs-secure comparison and feeds the BULB-CRA gap key.

## Acceptance criteria

1. `src/docs/BulbBee/ASSESSOR_BATTERY.md` covers the 8 tests (0-7) with runnable commands, expected default result, secure-mode result, weakness ID, and failed requirement.
2. A scoreboard table maps each test to its weakness, EN 303 645 provision, and secure-mode refusal.
3. Tests reference the plane findings (BULB-P0x) and the classic catalogue.
