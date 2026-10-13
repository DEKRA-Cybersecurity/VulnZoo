# BulbBee - Attack-Chain Model

> **Layer:** 3 (Reference Material) - MWP Methodology
> **Scope:** `labs/bulbbee/`, `cloud_api/bulbbee/`, `vulnzoo_apps/bulbbee_app/`.
> **Purpose:** The BulbBee vulnerability model. The findings are a single attack chain: controlling the bulb requires composing several weaknesses, not exercising any one of them. Only reconnaissance is independent. This is the shipped default, `secure` mode closes every link.
> **Status:** IMPLEMENTED. This is how the lab behaves out of the box. There is no instant-win posture, each finding is a link. The per-finding specifics are in each `Vulns/*.md`, the secure remediation is each finding's "How It Should Be".

---

## Two postures

The lab has exactly two postures, flipped by the one `secure` toggle (`bulbbee.@bulbbee[0].secure=1` or `"secure": true` in `config.json`, and `BULBBEE_SECURE=1` for the cloud API).

- **Default (the chain):** each finding yields an artifact, and control of the bulb is the composition of links. No single finding is a full compromise. Only reconnaissance (BULB-06) is independent, and it yields no secrets.
- **Secure:** every link is closed. This is the defensive-analysis reference, the remediation each finding's "How It Should Be" and "Controls to Implement" describes.

## The lever

> Each finding grants an artifact, not control: a serial, a derivation routine, a session, a binding token, a PSK, a foothold. Control is the composition of artifacts.

BULB-02 is the convergence point rather than a skeleton key. Control (BLE `0xFF31` and HTTP `/set`, `/scene`, `/update`, `/config`) requires a device-bound session, minted only from material obtained upstream (a derived PIN, a binding token, or a valid cloud token). The residual weakness that keeps BULB-02 a finding is that the session derivation is weak and serial-derivable, so it is forgeable by composing upstream artifacts (the serial plus the derivation routine), but it is never anonymous.

The invariant: no single link yields device control. The only free link is reconnaissance (BULB-06, recut below), and it yields no secrets.

## Dependency graph

```
  BULB-APP (derivation routines)          BULB-06 (serial, topic, version)
        \                                        |
         \                                       v
  BULB-03 (sniff)  -->  derive per-device PIN -> BULB-01 --> binding token + PSK
        |                                         |                 |
        |                                         v                 v
        +-----------------------------------> BULB-02           BULB-CLD --> BOLA --> fleet
                        device-bound SESSION (convergence)
                              |         |          |
                              v         v          v
                          BULB-04    BULB-07     BULB-05
                          root RCE   DoS / loop  PSK + token loot
                              |
                              v
                     persistence + on-disk secret read
```

## Chains

### Chain A - proximity (reverse engineering plus sniffing)

This is the canonical chain: reversing and sniffing replace the free PIN.

1. **BULB-APP**: disassemble the APK to recover `PIN = f(serial)` and the local-key derivation (the method, not the value).
2. **BULB-06** or the BLE advertisement: obtain the `serial` (and, as a bonus, the command topic and the firmware version).
3. Compute the per-device PIN. Optionally **BULB-03** confirms it by sniffing a real onboarding and capturing the `pair_token` in transit.
4. **BULB-01**: unlock provisioning with the derived PIN, read the binding token and, over the authenticated config read, the WiFi PSK.
5. **BULB-02**: with the session minted, there is now real control of the ring.
6. Branch: **BULB-07** (DoS, or a reboot that reopens BULB-01) or **BULB-04** (OTA to root RCE, then read BULB-05 on disk, then persistence).

### Chain B - remote over the cloud

This chain joins the local arm to the remote arm through the binding token.

1. **BULB-03** (sniff the `pair_set` during onboarding) or **BULB-01** (config read): harvest the binding token and the serial.
2. **BULB-CLD**: with `alg:none` closed, that binding token mints the cloud session, and the BOLA then controls the target bulb over the MQTT relay (BULB-R1).
3. The BOLA pivots to the rest of the fleet.

### Chain C - stolen phone or malware

An alternative entry that skips the radio work.

1. A foothold on the phone reads BULB-APP's cleartext prefs, yielding the per-device key and the cloud JWT.
2. Reuse the JWT at the cloud (BULB-CLD BOLA) for remote control, or the local key (BULB-R5) for local control through BULB-02.

### Loop

BULB-07 to a forced reboot to a reopened BULB-01 onboarding window closes the graph and gives material for a persistence exercise.

## Chain-role matrix

The same roles are recorded in each finding's "Chain role" section. This table is the single-page reference.

| Finding | Yields | Consumes | Unlocks |
|---------|--------|----------|---------|
| [BULB-APP](Mobile/BULB-APP-hardcoded-pin-and-plaintext-storage.md) | the derivation routines (static analysis), or the per-device key and cloud JWT with a phone foothold | the APK, or a foothold on the phone | BULB-01, BULB-R5, BULB-CLD |
| [BULB-06](IoT/BULB-06-insecure-default-debug.md) | reconnaissance only: serial, MQTT topic, firmware version (no secrets) | network reachability | BULB-01, BULB-CLD, BULB-04 |
| [BULB-03](IoT/BULB-03-cleartext-replayable-channel.md) | serial, command structure, a live session window, the binding token in transit | Bluetooth range with a sniffer, or a LAN tap | BULB-01, BULB-CLD, the BULB-02 replay window |
| [BULB-01](IoT/BULB-01-unauthenticated-ble-onboarding.md) | a provisioning unlock, the binding token, the WiFi PSK (authenticated read) | the per-device PIN (BULB-APP routine plus the serial) | BULB-02, BULB-05, BULB-CLD |
| [BULB-02](IoT/BULB-02-unauthenticated-control-surface.md) | full runtime control, the sensitive config read, the `/update` trigger | a device-bound session (BULB-01, BULB-R5, or BULB-CLD) | BULB-04, BULB-07, BULB-05 |
| [BULB-05](IoT/BULB-05-plaintext-secret-storage.md) | the WiFi PSK and the cloud pairing/binding token | the authenticated read (BULB-02), or a device foothold (BULB-04) | lateral movement, BULB-CLD, persistence |
| [BULB-04](IoT/BULB-04-unsigned-ota-update.md) | root code execution on the device (the apex) | the session (BULB-02), the version (BULB-06), a reachable URL | persistence, BULB-05 loot, a lateral pivot |
| [BULB-07](IoT/BULB-07-scene-payload-dos.md) | loss of availability, or a reboot that reopens onboarding | the session (BULB-02) | denial, or a loop back to BULB-01 |
| [BULB-CLD](API/BULB-CLD-cloud-api-bola-weak-jwt.md) | remote control of the target bulb and, via BOLA, the fleet | a valid account token, or the harvested device binding token | remote physical control (BULB-R1), a fleet pivot |

## Notes

- Every finding is still demonstrable in isolation at the artifact level. BULB-03 still shows cleartext and replay, BULB-05 is still a plaintext read, BULB-CLD still has the BOLA. What does not exist is loose "instant full control" from a single finding.
- The one defensive toggle is `secure`. The default is this chain, and `secure` closes every link, so each finding's "How It Should Be" and "Controls to Implement" are the secure target. There is no third posture.
- The model reuses concepts the project already has, nothing exotic. The serial-derivable token is BULB-P04, the MQTT relay is BULB-R1, the account-device binding is BULB-R2 and BULB-R6. Control converges on a device-bound session and secret disclosure sits behind it.

## Cross-reference to other layers

- **Roadmap and shipped findings:** [`README.md`](README.md)
- **Device landing page:** [`../README.md`](../README.md), setup [`../LAB_SETUP.md`](../LAB_SETUP.md)
- **Layer 2 (lab contract):** [`../../../labs/bulbbee/CONTEXT.md`](../../../labs/bulbbee/CONTEXT.md)
- **Layer 4 (working artifacts):** `labs/bulbbee/`, `cloud_api/bulbbee/`, `vulnzoo_apps/bulbbee_app/`
