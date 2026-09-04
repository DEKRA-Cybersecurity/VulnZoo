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

| # | Dossier claim (where) | Contradicted by | How the assessor proves it |
|---|-----------------------|-----------------|----------------------------|
| 1 | "per-device pairing secret" (BB-ERM-002, BB-UM-004 setup) | Hardcoded PIN `8080`, no lockout (**BULB-01**) | Connect over BLE with no bonding, unlock provisioning with `8080` on any unit, brute-force with no lockout. |
| 2 | "control interfaces require authentication" (BB-ERM-002) | No auth on BLE `0xFF31` / HTTP `:8082` (**BULB-02**) | `curl :8082/set` and a BLE write from an unpaired central both succeed. |
| 3 | "traffic is encrypted" (BB-ERM-002) | Cleartext, replayable BLE + HTTP (**BULB-03**) | Sniff a command and replay it, plain-HTTP capture, unencrypted BLE ATT write. |
| 4 | "updates are signed and verified" (BB-ERM-002, BB-UM-004 update policy) | Unsigned OTA runs attacker code (**BULB-04**) | `POST /update` an attacker URL, the payload executes on the device. |
| 5 | "sensitive parameters stored protected" (BB-ERM-002, BB-UM-004 reset) | Cleartext world-readable secrets (**BULB-05**) | Read the WiFi PSK / cloud token from `provisioning.json` or the BLE Config read. |
| 6 | "no debug interfaces in production" (BB-ERM-002) | `/debug` shipped enabled, dumps secrets (**BULB-06**) | `curl :8082/debug` returns config + secrets. |
| 7 | "inputs validated, resource use bounded" (BB-ERM-002) | Unbounded scene count DoS (**BULB-07**) | `POST /scene {custom, count: huge}` exhausts memory. |
| 8 | "no known exploitable vulnerabilities" + self-declared DoC (BB-DOC-001) | Seven documented findings | The catalogue in `../Vulns/` and gaps 1-7 above. |
| 9 | "coordinated disclosure channel published/monitored" (BB-UM-004) | To be tested | Verify `security@bulbbee.example` resolves and is monitored (process gap, not a code finding). |

## Default vs important (the pedagogical contrast)

BulbBee (default category) reaches CE marking on a self-declared Module A DoC with this compact dossier and **no notified body**. RoutCoon (important, Annex III) carries the far heavier prEN 40000-1-2 dossier (14 documents, `../../RoutCoon/CRA/`). Same regulation, same essential requirements, very different assurance burden, and in BulbBee's case a self-declaration that does not hold up, which is precisely the market-surveillance risk the default route carries.
