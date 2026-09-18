# BULB-CRA - Default-category manufacturer dossier (re-map) (spec)

Target: `BULB-CRA` (Phase 5). The dossier already exists under `src/docs/BulbBee/CRA/`. Net-new: re-map the findings to this plan's IDs and cover the three-plane weaknesses.

## Scope

Non-destructive, consistent with the P-ID decision: keep the existing dossier (plan, EU DoC, essential-requirements mapping, SBOM, user info, gap key) and the classic BULB-01..07 mapping intact, and ADD the three-plane BULB-P01..P07 mapping alongside it.

## Acceptance criteria

1. The assessor gap key (`99-Assessor-Gap-Key.md`) gains a three-plane table mapping each dossier claim to its BULB-P0x contradiction + how the assessor proves it (via the battery).
2. The essential-requirements mapping (`BB-ERM-002`) points at the three-plane catalogue, `SECURE_MODE.md`, and the assessor battery.
3. No existing dossier claim or the classic gap table is altered.
