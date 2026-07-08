# Canary - Vulnerability Roadmap

> **Layer:** 3 (Reference Material) - MWP Methodology
> **Scope:** `labs/canary/` (and, later, `cloud_api/canary/` and `vulnzoo_apps/canary_app/`).
> **Purpose:** Machine-parseable roadmap of the automotive vulnerabilities planned for canary, with their certification mapping.
> **Status:** The Jeep kill chain (`AUTO-01/05/02`) is implemented, documented, and verified on the Pi in simulation (`DONE`). The remaining items are `PENDING`. See [`../Canary.md`](../Canary.md).

---

## Certification mapping

Canary documents findings the way a certification body (a TIC company such as DEKRA) structures a type-approval assessment report, with a dual mapping.

- **UNECE R155 Annex 5** threat categories for the in-vehicle and update surfaces, communication channels (spoofing, injection, replay, denial of service), update procedures, back-end servers, and vulnerabilities that could be exploited if not hardened. Exact Annex 5 clause numbers are pinned against the standard text when each vulnerability is specified, not guessed here.
- **ISO/SAE 21434** as the process wrapper, TARA and cybersecurity goals, and the deliberately flawed cybersecurity case that the student-assessor must break.
- **OWASP** IoT Top 10 (2018) as a secondary cross-map for the in-vehicle findings (see the coverage table below), plus API and Mobile for the cloud, app and telematics surfaces added in later phases.

The custom identifier scheme for the in-vehicle CAN and SOME/IP findings is `AUTO-##`, consistent with the project's other custom IDs (`IGP-01`, `BLE-07`). Cloud and app findings reuse the OWASP `API#:2023` and `M#` schemes.

---

## Planned vulnerabilities (roadmap)

| ID | Title | Surface | R155 Annex 5 category | Status | Severity (est.) | CWE (candidate) |
|----|-------|---------|-----------------------|--------|-----------------|-----------------|
| AUTO-01 | Gateway management interface exposed on the network with no authentication (Jeep chain, entry) | SOME/IP / Ethernet | communication channels, unauthorized access | DONE | High | CWE-306 |
| AUTO-02 | Arbitrary CAN injection through the subverted gateway, plus replay of a sniffed SetLock (SOME/IP) or LOCK_CMD (bus) (Jeep chain, impact) | in-vehicle CAN | communication channels, message injection and spoofing | DONE | High | CWE-306 / CWE-345 |
| AUTO-03 | CAN bus-flood denial of service | in-vehicle CAN | communication channels, denial of service | PENDING | Medium | CWE-400 |
| AUTO-04 | UDS over ISO-TP: weak SecurityAccess seed/key, RoutineControl actuator unlock, ReadMemoryByAddress | diagnostics (ISO 14229 / ISO 15765) | vulnerabilities if not hardened, unauthorized diagnostic access | PENDING | High | CWE-1390 / CWE-321 |
| AUTO-05 | Unsigned firmware update reflashes the gateway from firewall to bridge (Jeep chain, escalation) | update procedure | update procedures (also R156 / ISO 24089) | DONE | Critical | CWE-347 / CWE-494 |
| API/M (TBD) | Connected-car cloud fleet backend and Android app (remote-to-CAN kill chain) | cloud / mobile | back-end servers, external connectivity | PENDING | High | TBD per finding |

Notes:

- AUTO-04 requires enabling `kmod-can-isotp`, which is not in the current base-image feed selection and must be added when that phase is specified.
- The connected-car row expands into concrete OWASP `API#:2023` and `M#` entries when the cloud and app are built, reusing the octobot cloud and app scaffolding.
- A deliberately flawed cybersecurity case / TARA ships with the lab as the assessor exercise, mapped to ISO/SAE 21434 rather than to a single CWE.

---

## OWASP IoT Top 10 coverage

CANary is assessed natively against UNECE R155 Annex 5 and ISO/SAE 21434 (above). As a secondary lens it also cross-maps to the OWASP IoT Top 10 (2018), the same framework the other VulnZoo labs use. Each attack document names its OWASP entry, this table is the coverage view. `DONE` and `PARTIAL` reflect what the implemented findings realize, `PENDING` is on the roadmap, and `N/A` is out of scope for this in-vehicle locking subsystem, each with a one-line reason.

| OWASP IoT (2018) | CANary finding(s) | Status | Note |
|------------------|-------------------|--------|------|
| I1 Weak, Guessable, or Hardcoded Passwords | Jeep chain | PARTIAL | the `setlock_token` and firmware `fw_key` are static shared secrets in UCI |
| I2 Insecure Network Services | AUTO-01, AUTO-02 | DONE | exposed unauthenticated management endpoint, and unauthenticated CAN injection through the subverted gateway |
| I3 Insecure Ecosystem Interfaces | - | PENDING | web, cloud and mobile interfaces arrive with the connected-car phase |
| I4 Lack of Secure Update Mechanism | AUTO-05 | DONE | unsigned firmware applied with no signature, version, or origin check |
| I5 Use of Insecure or Outdated Components | - | N/A | the stack is hand-rolled standard library, not a component-CVE surface |
| I6 Insufficient Privacy Protection | - | N/A | the central-locking subsystem holds no personal data |
| I7 Insecure Data Transfer and Storage | AUTO-02 (replay), chain | PARTIAL | SOME/IP is plaintext, so the SetLock token is sniffable and replayable, and CAN carries no integrity or encryption |
| I8 Lack of Device Management | AUTO-01, AUTO-05 | PARTIAL | the management and reflash paths have no authentication or audit trail |
| I9 Insecure Default Settings | lab toggle | PARTIAL | the lab ships in `mode=vulnerable`, a `secure` mode exists |
| I10 Lack of Physical Hardening | AUTO-02 (from the bus), AUTO-03 | PENDING | on-bus injection, replay and flood via the USB-CAN tap, needs hardware mode |

---

## Jeep Cherokee kill chain (AUTO-01 -> AUTO-05 -> AUTO-02)

`AUTO-01`, `AUTO-05` and `AUTO-02` are specified together as one kill chain that reconstructs the 2015 Jeep Cherokee (Miller and Valasek) remote-to-CAN attack, adapted to canary. Entry is the exposed unauthenticated gateway management interface (`AUTO-01`), escalation is an unsigned firmware update that reflashes the gateway from a filtering firewall into an attacker-controlled bridge (`AUTO-05`), and the impact is arbitrary CAN injection to the BCM (`AUTO-02`). They share the gateway endpoint surface but are three distinct weaknesses with three CWEs and three R155 categories. The load-bearing property is that arbitrary CAN, and thus reaching any ECU beyond the lock, is unreachable without the reflash. Lock actuation specifically also falls to sniff-and-replay of the cleartext `SetLock` token (OWASP I7) once there is traffic to capture, but the reflash is what buys arbitrary bus access. The concrete finding document is [`Automotive/AUTO-Jeep-Kill-Chain.md`](Automotive/AUTO-Jeep-Kill-Chain.md).

---

## Legend

| Badge | Meaning |
|-------|---------|
| DONE | Implemented in code and verified in the lab. |
| PENDING | Documented or scoped, not yet implemented or verified. |
| IN PROGRESS | Implemented and documented, not yet verified on the live lab. |

The Jeep kill-chain rows (`AUTO-01/05/02`) are `DONE` (verified on the Pi in simulation). The remaining rows are `PENDING`. The functional bring-up itself carries no intentional weakness.

---

## Cross-Reference to Other Layers

- **Layer 4 (Working Artifacts):** `labs/canary/`
- **Layer 3 (Landing page):** [`../Canary.md`](../Canary.md)
- **Layer 2 (Lab Contract):** [`../../../labs/canary/CONTEXT.md`](../../../labs/canary/CONTEXT.md)
- **Stage 01 Spec:** `stages/01_spec/output/canary-spec.md`
- **Layer 0 (Global Identity):** [`../../../AGENTS.md`](../../../AGENTS.md)
