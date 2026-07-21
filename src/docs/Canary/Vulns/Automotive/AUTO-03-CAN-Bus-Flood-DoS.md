---
id: "AUTO-03"
title: "CAN bus-flood denial of service"
category: Automotive
status: PENDING
severity: Medium
owasp: "OWASP IoT Top 10 (2018): I2 Insecure Network Services (bus-flood DoS), I10 Lack of Physical Hardening (on-bus tap). Native framing is UNECE R155 Annex 5 (communication channels, denial of service) and ISO/SAE 21434, see Certification mapping."
cwe: "CWE-400 (Uncontrolled Resource Consumption)"
source_docs:
  - "stages/01_spec/output/canary-spec.md"
  - "docs/Canary/Vulns/README.md"
affected_components:
  - "labs/canary/files/etc/init.d/canary-can"
  - "labs/canary/files/opt/canary/bcm_ecu.py"
  - "labs/canary/files/etc/config/canary"
---

## Why It Matters

Classic CAN was designed for a closed, trusted network of cooperating ECUs, so it has no arbitration fairness guarantee, no per-node rate limiting and no sender authentication. Any node that can put frames on the wire can deny service to every other node, and the safety-relevant traffic has no priority claim it can defend. This is not a bug in a specific ECU, it is a property of the bus, which is why a certification assessment treats it as a communication-channels denial-of-service threat under UNECE R155 Annex 5 rather than a coding defect.

Unlike the Jeep kill chain (`AUTO-01/05/02`), this finding needs no gateway compromise and no SOME/IP. It only needs a node on the bus. In Model A the tester's USB-CAN adapter is clipped to the same physical bus as the CGW and the BCM, so a flood from the PC starves the legitimate `LOCK_CMD` (`0x120`) and the BCM `LOCK_STAT` heartbeat (`0x121`). In a real vehicle the same primitive is reachable from an OBD-II dongle, a diagnostic Ethernet-to-CAN bridge, or any compromised ECU, and on a shared bus it degrades every function on that bus, not just the lock.

## Root Cause

CAN arbitration is priority-based on the identifier and the lowest id wins, because a dominant bit (0) overrides a recessive bit (1) on the shared wire. A node that transmits id `0x000` back to back therefore wins every arbitration round, and no higher-numbered id ever gets on the bus while the flood runs. The lock traffic uses `0x120` and `0x121`, both far above `0x000`, so both lose unconditionally.

The bus has three missing properties, and any one of them would blunt the attack:

- No bandwidth reservation for safety frames, so a periodic `LOCK_STAT` heartbeat has no guaranteed slot.
- No mechanism to throttle or quarantine a node that transmits abusively.
- No sender authentication, so the victims cannot tell the flood from a legitimate high-priority ECU.

In the lab the `canary-can` service brings the bus up at 500 kbit/s from UCI (`canary.main`), and `bcm_ecu.py` emits the `LOCK_STAT` heartbeat and reacts to `LOCK_CMD`. Neither has, or could have, a defense against bus exhaustion. Nothing has to be reflashed or misconfigured for the attack to work, which is the whole point: the weakness is structural.

## Steps to Reproduce

This requires hardware mode. The two MCP2515 modules bring up `can0`/`can1` on the Pi and the PC USB-CAN adapter is on the same bus. On a bare Pi the lab falls back to a single `vcan0`, which has no bitrate and no real arbitration, so the starvation effect is not observable in simulation. Tooling is `can-utils` on the PC (`cangen`, `candump`, `canbusload`), deliberately not baked into the vehicle image.

```bash
# PC, USB-CAN tap up at 500 kbit/s
sudo ip link set can0 up type can bitrate 500000

# 1. Baseline: watch the legitimate BCM heartbeat (0x121 every ~500 ms).
candump -t d can0

# 2. Flood the bus with the highest-priority id at line rate (second terminal).
cangen can0 -I 000 -L 8 -D i -g 0        # id 0x000 wins every arbitration round
#   volume variant (random ids, no gap):  cangen can0 -I r -L 8 -D r -g 0

# 3. Measure the load and confirm saturation (third terminal).
canbusload can0@500000                    # bus load pinned near 100%
```

While the flood runs, drive the lock from the legitimate head-unit client and watch it fail to actuate in time:

```bash
python3 tools/someip_client.py 192.168.2.1 lock AGL-HEADUNIT-7c2f
# the SetLock is accepted by the CGW, but LOCK_CMD 0x120 loses arbitration behind 0x000
ssh root@192.168.2.1 'cat /tmp/canary/lock_state'   # state does not track the command under load
```

Stop the flood (Ctrl-C on `cangen`) and confirm the bus recovers: the `0x121` heartbeat resumes and a `SetLock` actuates normally again.

## Attack walkthrough

Getting onto the bus is the same physical-access step described in the Jeep chain doc (OBD-II, diagnostic Ethernet, or a bus tap). Once on the bus, this attack takes no reconnaissance of SOME/IP at all.

1. Passively map the bus. `candump -t d can0` shows the id set and the periods with no active probing. You see `0x121` arriving about every 500 ms and `0x120` on each lock action. Those are the frames the DoS will suppress, and knowing they exist is enough.
2. Pick the primitive. To deny all traffic, flood the lowest possible id (`0x000`). To deny selectively, flood just above the target id, but for a locking subsystem the blanket `0x000` flood is simplest and total.
3. Sustain and observe. Run `cangen` with no inter-frame gap and watch `canbusload` climb to saturation while the victim heartbeat disappears from the `candump` window.

No credential, no token, no reflash. The only prerequisite is the ability to transmit on the bus.

## Expected Result

Under the flood the BCM `LOCK_STAT` heartbeat gaps grow and then stop, `canbusload` reports the bus near saturation, and a legitimate `SetLock` no longer actuates the lock within its normal timing because `LOCK_CMD 0x120` cannot win arbitration against `0x000`. Stopping the flood restores normal traffic, the heartbeat resumes and locking works again.

A harsher variant that injects error frames to drive victim controllers into the bus-off state exists on controllers that expose low-level error handling. It is out of scope for the MCP2515 reference setup and is noted only so the finding does not imply the reference hardware demonstrates it.

## How It Should Be

Classic CAN cannot authenticate or encrypt its way out of a flood, so the controls are detection and containment rather than a message-level fix. The lab ships no mitigation for this finding today, its `mode=secure` toggle closes the SOME/IP chain (`AUTO-01/05`) and does not address on-bus exhaustion. The real-vehicle equivalents are what the assessment checks for.

A bus guardian or a CAN intrusion-detection system baselines the id set and their periods and alarms on an id-`0x000` storm or an abnormal bus load. A gateway rate-limits or drops frames arriving from an untrusted segment before they reach the safety bus, so a compromised comfort-domain node cannot saturate the powertrain bus. Safety functions fall back to a fail-operational default when an expected periodic frame goes missing rather than hanging on stale state. SecOC authenticates frame content and stops spoofing and replay, but it does not stop a bandwidth-exhaustion DoS, which is why segmentation and monitoring carry this one.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Segmentation | Gateway that rate-limits or drops frames from an untrusted segment | Keep a flood on one domain off the safety bus (AUTO-03) |
| Detection | Bus guardian / CAN IDS baselining ids, periods and bus load | Alarm on an id-`0x000` storm or abnormal load (AUTO-03) |
| Availability | Fail-operational default when an expected periodic frame is missing | Degrade safely instead of acting on stale state |
| Hardware | Controller bus-off recovery and transmit-error-counter monitoring | Survive and report an error-frame DoS variant |
| Physical | Restrict physical bus access (OBD-II gating, tamper detection) | Raise the bar to placing a node on the bus (I10) |

## Verification Checklist

- [ ] In hardware mode, a `0x000` flood pins `canbusload can0@500000` near 100 percent
- [ ] The BCM `LOCK_STAT` (`0x121`) heartbeat stalls or stops while the flood runs
- [ ] A legitimate `SetLock` does not actuate the lock during the flood (`/tmp/canary/lock_state` does not track the command)
- [ ] Bus traffic and locking recover after the flood is stopped
- [ ] In simulation (`vcan0`) the flood is acknowledged as not observable, no false positive is claimed

## Deviations from the real case

1. Observable only on hardware. A real bus has a fixed bitrate and physical arbitration, so the flood starves lower-priority frames. The lab's `vcan0` fallback has neither, so AUTO-03 is a hardware-mode finding by nature, not a simulation one.
2. Priority-flood, not bus-off. The reference reproduction uses a high-priority id flood to starve the bus. The error-frame / bus-off escalation is real on production controllers but is out of scope for the MCP2515 reference modules.
3. Safe actuator. The impact shown is the lock going unresponsive. On a shared production bus the same exhaustion would suppress safety-relevant frames, the chain shape is identical.

## Certification mapping

Findings carry the dual mapping a TIC assessment report uses. Exact R155 Annex 5 clause numbers are pinned against the regulation text when specified and are intentionally not invented here.

- AUTO-03 maps to denial of service on the in-vehicle communication channels, under the communication-channels threat category.
- The OWASP IoT Top 10 (2018) cross-map, as a secondary lens, is I2 Insecure Network Services for the bus-flood itself, with I10 Lack of Physical Hardening for the on-bus tap that makes it reachable.
- For ISO/SAE 21434, the affected cybersecurity goal is the availability of the central-locking function, and the TARA gap the assessor must surface is that the bus applies no rate limiting, no prioritization guarantee for safety frames, and no monitoring, so any node can exhaust it.

The full OWASP IoT Top 10 coverage matrix for CANary is in [`../README.md`](../README.md).

## Related Vulnerabilities

- [Vulnerability roadmap](../README.md): the AUTO-03 row and the on-bus (I10) notes.
- [`AUTO-Jeep-Kill-Chain.md`](AUTO-Jeep-Kill-Chain.md): AUTO-02 reaches arbitrary CAN from the network through the reflashed gateway. AUTO-03 needs no gateway, it abuses the bus directly from a node already on it. Injection versus exhaustion on the same unauthenticated bus.
- AUTO-04 (weak UDS SecurityAccess over ISO-TP): another on-bus surface reachable from the same physical position, deferred until `kmod-can-isotp` is added.
