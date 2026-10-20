---
id: BULBBEE-CRA-GAPKEY
title: BulbBee CRA Assessor Gap Key (trainer answer key)
category: Compliance
status: DONE
severity: N/A
affected_components: [bulbbee]
regulation: EU Cyber Resilience Act (Regulation (EU) 2024/2847)
version: 1.0
date: 2026-09-04
owner: VulnZoo (trainer)
---

# Assessor Gap Key

The trainer's answer key: each manufacturer claim in the dossier, the device ground truth that contradicts it, and how the student-assessor proves the gap. This is the point of the exercise, a Module A self-declaration (BB-DOC-001) that market-surveillance verification disproves.

| #   | Dossier claim (where)                                                   | Contradicted by                                                                                        | How the assessor proves it                                                                                                                                                     |
| --- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | "per-device pairing secret" (BB-ERM-002, BB-UM-004 setup)               | Per-device PIN derived from the enumerable serial via the app's routine, lockout after 5 (**BULB-01**) | Reverse `derivePin` from the APK, read the serial over BLE (`0xFF41`) or from `/debug?diag=bulbbee-diag`, compute the PIN, unlock provisioning over the unbonded link.         |
| 2   | "control interfaces require authentication" (BB-ERM-002)                | Session forgeable from the serial, not a real secret (**BULB-02**)                                     | Anonymous `curl :8082/set` returns 401, but a session forged from the serial (**BULB-01** derivation) drives it, and a BLE write from an unpaired central applies on `0xFF31`. |
| 3   | "traffic is encrypted" (BB-ERM-002)                                     | Cleartext, replayable BLE + HTTP (**BULB-03**)                                                         | Sniff a command and replay it, plain-HTTP capture, unencrypted BLE ATT write.                                                                                                  |
| 4   | "updates are signed and verified" (BB-ERM-002, BB-UM-004 update policy) | Unsigned OTA runs attacker code (**BULB-04**)                                                          | `POST /update` an attacker URL, the payload executes on the device.                                                                                                            |
| 5   | "sensitive parameters stored protected" (BB-ERM-002, BB-UM-004 reset)   | Cleartext world-readable secrets (**BULB-05**)                                                         | Read the WiFi PSK / cloud token from `provisioning.json` or the BLE Config read.                                                                                               |
| 6   | "no debug interfaces in production" (BB-ERM-002)                        | `/debug` shipped enabled, diag-key gated, returns recon only (**BULB-06**)                             | Recover the diag key from firmware `strings`, then `curl ':8082/debug?diag=bulbbee-diag'` returns the serial, MQTT topic and firmware version (bare `/debug` 404s).            |
| 7   | "inputs validated, resource use bounded" (BB-ERM-002)                   | Unbounded scene count DoS (**BULB-07**)                                                                | `POST /scene {custom, count: huge}` exhausts memory.                                                                                                                           |
| 8   | "no known exploitable vulnerabilities" + self-declared DoC (BB-DOC-001) | Seven documented findings                                                                              | The catalogue in `../Vulns/` and gaps 1-7 above.                                                                                                                               |
| 9   | "coordinated disclosure channel published/monitored" (BB-UM-004)        | To be tested                                                                                           | Verify `security@bulbbee.example` resolves and is monitored (process gap, not a code finding).                                                                                 |

## Technical-documentation gaps (Annex VII dossier)

The Annex VII process documents (BB-RMR-005, BB-SCP-006, BB-VVR-007, BB-VMP-008, BB-TD-000) carry their own manufacturer claims. These are the gaps between what the paperwork states and what the delivered device does, the same claim-versus-ground-truth exercise applied to the technical documentation.

| # | Dossier claim (where) | Contradicted by | How the assessor proves it |
|---|-----------------------|-----------------|----------------------------|
| TD-1 | "technical documentation complete and consistent, product meets the Annex I essential requirements" (BB-TD-000 s.1, s.6) | The delivered device fails every Annex I theme (BB-ERM-002) and each process-document claim is disproved below | Open BB-TD-000, follow its Annex VII map, then disprove each mapped claim against the live device with the assessor battery (`../README.md`). |
| RMR-1 | Residual High risks accepted with optimistic justifications (BB-RMR-005 s.6.4.5: T-01 "per-device PIN", T-02 "not anonymous", T-04 "updates infrequent", T-06 "no secrets") | The accepted risks are a derivable PIN (**BULB-01**), a forgeable session (**BULB-02**), an unsigned OTA to root (**BULB-04**), and a shipped debug surface (**BULB-06**) | Challenge each justification against the 6.3 acceptance criteria, which forbid accepting a High risk, and reproduce the finding. |
| SCP-1 | "secure by default, signed updates, encrypted transport, no debug interface" (BB-SCP-006 s.4, s.6, s.8) | The shipped default sets `secure` off and degrades every control (**BULB-01..07**) | Compare the device in the default posture against `secure=true`. The robust baseline exists in the product but is not the default. |
| VVR-1 | "every requirement SR-01..SR-12 verified Pass" (BB-VVR-007 s.4) | The verdicts hold only under `secure=true`, not the delivered default | Reproduce SR-01 through SR-08 and SR-11 on the delivered device. They fail. The V&V was run against a configuration the product does not ship. |
| VMP-1 | "monitored coordinated-disclosure channel and signed, integrity-protected update distribution" (BB-VMP-008 s.3, s.5) | The published contact is unverified (process gap, see row 9), and the OTA applies unsigned payloads (**BULB-04**) | Verify `security@bulbbee.example` resolves and is monitored, and reproduce the unsigned OTA (**BULB-04**). |

## Three-plane findings (BULB-P01..P07)

The same dossier claims are also broken along the BLE three-plane architecture (local BLE, cloud tunnel, LAN/TCP). These are the shipped default degradations of the secure baselines (BULB-A2..A5), restored by `secure=true` (BULB-SEC). The three-plane findings table and the assessor battery that proves each are consolidated in the device overview [`../README.md`](../README.md).

| # | Dossier claim | Contradicted by | How the assessor proves it |
|---|---------------|-----------------|----------------------------|
| P1 | "pairing uses secure connections" | Just Works / no LE SC (**BULB-P01**) | Pair from a central with no passkey prompt, sniff the pairing in the clear (battery test 3). |
| P2 | "credentials protected in transit" | WiFi PSK over BLE in cleartext (**BULB-P02**) | Sniff provisioning or read `0xFF42` and recover the PSK (battery test 4). |
| P3 | "per-device cryptographic keys" | Static local key in firmware (**BULB-P03**) | Extract `bulbbee-local-16`, forge a `:6668` frame that any device accepts (battery test 2). |
| P4 | "device identity is unforgeable" | Token derivable from serial+salt (**BULB-P04**) | Reproduce `_static_key(serial)`, forge a confirming token (battery test 5). |
| P5 | "only the owner controls the device" | Owner binding app-only (**BULB-P05**) | Drive the device from a non-owner client (battery test 6). |
| P6 | "control interfaces require authentication" | LAN proximity = control (**BULB-P06**) | Any LAN host with the shared key drives `:6668` (battery test 2). |
| P7 | "secure by default, no debug in production" | Debug on, secret logging, open re-provisioning (**BULB-P07**) | `curl ':8082/debug?diag=bulbbee-diag'`, re-provision repeatedly (battery tests 1, 7). |

Every P-row is neutralized by `secure=true`, so the assessor's report can state both the gap and the remediation (flip to the robust baseline the manufacturer already shipped but did not default to).

## Default vs important (the pedagogical contrast)

BulbBee (default category) reaches CE marking on a self-declared Module A DoC with this compact dossier and **no notified body**. RoutCoon (important, Annex III) carries the far heavier prEN 40000-1-2 dossier (14 documents, `../../RoutCoon/CRA/`). Same regulation, same essential requirements, very different assurance burden, and in BulbBee's case a self-declaration that does not hold up, which is precisely the market-surveillance risk the default route carries.
