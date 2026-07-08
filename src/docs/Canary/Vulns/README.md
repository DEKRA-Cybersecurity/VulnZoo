# Canary - Vulnerability Roadmap

> **Layer:** 3 (Reference Material) - MWP Methodology
> **Scope:** `labs/canary/` (and, later, `cloud_api/canary/` and `vulnzoo_apps/canary_app/`).
> **Purpose:** Machine-parseable roadmap of the automotive vulnerabilities planned for canary, with their certification mapping.
> **Status:** Phase 0. Nothing here is implemented yet, every item is `PENDING`. Phase 0 is the functional bring-up only (see [`../Canary.md`](../Canary.md)).

---

## Certification mapping

Canary documents findings the way a certification body (a TIC company such as DEKRA) structures a type-approval assessment report, with a dual mapping.

- **UNECE R155 Annex 5** threat categories for the in-vehicle and update surfaces, communication channels (spoofing, injection, replay, denial of service), update procedures, back-end servers, and vulnerabilities that could be exploited if not hardened. Exact Annex 5 clause numbers are pinned against the standard text when each vulnerability is specified, not guessed here.
- **ISO/SAE 21434** as the process wrapper, TARA and cybersecurity goals, and the deliberately flawed cybersecurity case that the student-assessor must break.
- **OWASP** API, Mobile and IoT for the cloud, app and telematics surfaces added in later phases.

The custom identifier scheme for the in-vehicle CAN and SOME/IP findings is `AUTO-##`, consistent with the project's other custom IDs (`IGP-01`, `BLE-07`). Cloud and app findings reuse the OWASP `API#:2023` and `M#` schemes.

---

## Planned vulnerabilities (roadmap)

| ID | Title | Surface | R155 Annex 5 category | Status | Severity (est.) | CWE (candidate) |
|----|-------|---------|-----------------------|--------|-----------------|-----------------|
| AUTO-01 | SOME/IP service with no authentication on SetLock and unrestricted event subscription | SOME/IP / Ethernet | communication channels, unauthorized access | PENDING | High | CWE-306 / CWE-862 |
| AUTO-02 | CAN injection and replay of LOCK_CMD from the bus | in-vehicle CAN | communication channels, message injection and spoofing | PENDING | High | CWE-345 / CWE-294 |
| AUTO-03 | CAN bus-flood denial of service | in-vehicle CAN | communication channels, denial of service | PENDING | Medium | CWE-400 |
| AUTO-04 | UDS over ISO-TP: weak SecurityAccess seed/key, RoutineControl actuator unlock, ReadMemoryByAddress | diagnostics (ISO 14229 / ISO 15765) | vulnerabilities if not hardened, unauthorized diagnostic access | PENDING | High | CWE-1390 / CWE-321 |
| AUTO-05 | Unsigned OTA / software update path | update procedure | update procedures (also R156 / ISO 24089) | PENDING | Critical | CWE-494 / CWE-345 |
| API/M (TBD) | Connected-car cloud fleet backend and Android app (remote-to-CAN kill chain) | cloud / mobile | back-end servers, external connectivity | PENDING | High | TBD per finding |

Notes:

- AUTO-04 requires enabling `kmod-can-isotp`, which is not in the current base-image feed selection and must be added when that phase is specified.
- The connected-car row expands into concrete OWASP `API#:2023` and `M#` entries when the cloud and app are built, reusing the octobot cloud and app scaffolding.
- A deliberately flawed cybersecurity case / TARA ships with the lab as the assessor exercise, mapped to ISO/SAE 21434 rather than to a single CWE.

---

## Legend

| Badge | Meaning |
|-------|---------|
| DONE | Implemented in code and verified in the lab. |
| PENDING | Documented or scoped, not yet implemented or verified. |
| IN PROGRESS | Implemented and documented, not yet verified on the live lab. |

Every row is `PENDING` because phase 0 delivers only the functional environment. The functional bring-up itself carries no intentional weakness.

---

## Cross-Reference to Other Layers

- **Layer 4 (Working Artifacts):** `labs/canary/`
- **Layer 3 (Landing page):** [`../Canary.md`](../Canary.md)
- **Layer 2 (Lab Contract):** [`../../../labs/canary/CONTEXT.md`](../../../labs/canary/CONTEXT.md)
- **Stage 01 Spec:** `stages/01_spec/output/canary-spec.md`
- **Layer 0 (Global Identity):** [`../../../AGENTS.md`](../../../AGENTS.md)
