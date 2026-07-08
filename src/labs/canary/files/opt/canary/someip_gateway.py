#!/usr/bin/env python3
# someip_gateway.py - canary Central Gateway (CGW) ECU.
#
# Hosts the CentralLockingService over SOME/IP (UDP) on eth0 and bridges it to the
# CAN bus. In its shipped state the CGW is a FILTERING GATEWAY (a firewall, the
# V850 analog of the 2015 Jeep chain): the only thing it puts on CAN is the one
# whitelisted LOCK_CMD (0x120) it derives from an authenticated SetLock. It does
# NOT relay arbitrary CAN.
#
# The Jeep kill chain (AUTO-01/05/02, see docs/Canary/Vulns/Automotive/):
#   AUTO-01  the management endpoint (:30510) is exposed with no authentication.
#   AUTO-05  UpdateFirmware applies a firmware/policy artifact WITHOUT verifying its
#            signature, flipping the gateway from firewall to bridge.
#   AUTO-02  once flipped, RelayFrame relays attacker-supplied arbitrary CAN frames.
#
# Hard invariant: the running gateway has no code path that emits an ARBITRARY CAN
# frame. RelayFrame is refused unless the firmware policy set allow_raw=1, and only
# UpdateFirmware (unsigned) can set it. UpdateFirmware never transmits CAN. Note:
# lock actuation specifically has two paths (the reflash chain, or sniff+replay of
# an authenticated SetLock since SOME/IP is cleartext), but reaching an arbitrary
# CAN id still requires the reflash.
#
# Dynamic-analysis surface: the service answers with standard SOME/IP return codes
# (E_UNKNOWN_SERVICE / E_UNKNOWN_METHOD / E_MALFORMED_MESSAGE) so a black-box tester
# can enumerate it, and a minimal SOME/IP-SD responder answers FindService so the
# service is discoverable without reading the firmware.
#
# Standard library only (no vsomeip, no python-can): the SOME/IP header is a fixed
# 16-byte layout and CAN frames are raw AF_CAN sockets.
import hashlib
import hmac
import os
import socket
import struct
import threading

# SOME/IP CentralLockingService (main) and GatewayUpdateService (management)
SERVICE_ID = 0x1401
M_SETLOCK = 0x0001
M_GETSTATE = 0x0002
M_RELAYFRAME = 0x0003          # added by the malicious firmware, gated by allow_raw
E_LOCKSTATUS = 0x8001
MGMT_SERVICE_ID = 0x1402
M_UPDATEFW = 0x0001
PROTO_VER = 0x01
IFACE_VER = 0x01
MT_REQUEST = 0x00
MT_RESPONSE = 0x80
MT_NOTIFICATION = 0x02
MT_ERROR = 0x81

# SOME/IP return codes (subset)
E_OK = 0x00
E_NOT_OK = 0x01
E_UNKNOWN_SERVICE = 0x02
E_UNKNOWN_METHOD = 0x03
E_MALFORMED_MESSAGE = 0x09

# SOME/IP Service Discovery (message id 0xFFFF8100)
SD_SERVICE = 0xFFFF
SD_METHOD = 0x8100

# CAN frame IDs (classic CAN, 11-bit)
LOCK_CMD_ID = 0x120       # CGW -> BCM
LOCK_STAT_ID = 0x121      # BCM -> bus
CAN_FRAME_FMT = '=IB3x8s'  # struct can_frame: id, dlc, pad, data

# Firmware / forwarding policy artifact. Runtime (tmpfs): a reboot or lab reload
# restores the shipped firewall (clean slate per run). Absent = firewall default.
POLICY_PATH = os.environ.get('CANARY_POLICY_PATH', '/tmp/canary/gw_policy')


def someip_pack(service, method, mtype, client, session, payload=b'', rc=0):
    msg_id = (service << 16) | method
    req_id = (client << 16) | session
    length = 8 + len(payload)   # request id (4) + proto/iface/type/ret (4) + payload
    return struct.pack('>IIIBBBB', msg_id, length, req_id,
                       PROTO_VER, IFACE_VER, mtype, rc) + payload


def someip_parse(pkt):
    msg_id, length, req_id, _p, _i, mtype, _r = struct.unpack('>IIIBBBB', pkt[:16])
    payload = pkt[16:16 + (length - 8)]
    return msg_id >> 16, msg_id & 0xFFFF, mtype, req_id >> 16, req_id & 0xFFFF, payload


def can_pack(can_id, data):
    return struct.pack(CAN_FRAME_FMT, can_id, len(data), data.ljust(8, b'\x00'))


def can_unpack(frame):
    can_id, dlc, data = struct.unpack(CAN_FRAME_FMT, frame)
    return can_id & 0x1FFFFFFF, data[:dlc]


def open_can(iface):
    s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    s.bind((iface,))
    return s


def check_token(payload, token):
    # Legitimate SetLock is token-gated: payload = token || lock(1 byte). This closes
    # the front door to a blind caller. The token is cleartext on the wire, so an
    # attacker who can sniff a legit SetLock recovers it (see the AUTO-02 replay path).
    tb = token.encode()
    if len(payload) < len(tb) + 1 or not hmac.compare_digest(payload[:len(tb)], tb):
        return False, 0
    return True, payload[len(tb)] & 1


def read_policy(path=POLICY_PATH):
    # ponytail: policy is one flag in a tiny file; absent = firewall default.
    try:
        with open(path) as f:
            return {'allow_raw': 'allow_raw=1' in f.read()}
    except OSError:
        return {'allow_raw': False}


def apply_firmware(blob, mode, fw_key, path=POLICY_PATH):
    # blob = signature(32) || policy_body. AUTO-05: in vulnerable mode the
    # signature is NEVER checked, any firmware is applied. Secure mode verifies an
    # HMAC-SHA256 over the body. Writing the policy is the whole "reflash": no code
    # is executed (honest abstraction of the V850 machine-code rewrite).
    if len(blob) < 32:
        return False
    sig, body = blob[:32], blob[32:]
    if mode == 'secure':
        expected = hmac.new(fw_key.encode(), body, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(body)
    return True


def build_sd_offer(ip, svc_port):
    # Minimal SOME/IP-SD OfferService announcing SERVICE_ID at (ip, svc_port, UDP).
    # Entry (16 bytes): OfferService type, option indices, service/instance, major+TTL, minor.
    entry = struct.pack('>BBBBHHII', 0x01, 0, 0, 0x10, SERVICE_ID, 0x0001,
                        (0x01 << 24) | 3, 0x00000000)
    # IPv4 endpoint option (12 bytes): length(9), type(0x04), reserved, ip, reserved, UDP, port.
    option = struct.pack('>HBB', 9, 0x04, 0x00) + socket.inet_aton(ip) \
        + struct.pack('>BBH', 0x00, 0x11, svc_port)
    payload = struct.pack('>BBBB', 0x80, 0, 0, 0) \
        + struct.pack('>I', len(entry)) + entry \
        + struct.pack('>I', len(option)) + option
    return someip_pack(SD_SERVICE, SD_METHOD, MT_NOTIFICATION, 0x0000, 0x0001, payload)


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('192.168.2.2', 9))
        return s.getsockname()[0]
    except OSError:
        return '0.0.0.0'
    finally:
        s.close()


def sd_server(svc_ip, svc_port, sd_port):
    # AUTO / dynamic surface: answer FindService with our OfferService so the service
    # is discoverable over SD (unicast). ponytail: minimal, no periodic multicast offer.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', sd_port))
    offer = build_sd_offer(svc_ip, svc_port)
    while True:
        pkt, addr = s.recvfrom(4096)
        if len(pkt) < 16:
            continue
        service, method, _t, _c, _s, _p = someip_parse(pkt)
        if service == SD_SERVICE and method == SD_METHOD:
            s.sendto(offer, addr)


def send_event(udp, target, state):
    if not target:
        return
    host, _, port = target.partition(':')
    if not port:
        return
    pkt = someip_pack(SERVICE_ID, E_LOCKSTATUS, MT_NOTIFICATION, 1, 0, bytes([state]))
    try:
        udp.sendto(pkt, (host, int(port)))
    except OSError:
        pass


def mgmt_server(mode, mgmt_port, fw_key):
    # AUTO-01: exposed management interface (Uconnect D-Bus 6667 analog). Update-only:
    # it applies firmware, it never transmits CAN. Secure mode binds it internal-only.
    m = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    m.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    m.bind(('127.0.0.1' if mode == 'secure' else '0.0.0.0', mgmt_port))
    while True:
        pkt, addr = m.recvfrom(4096)
        if len(pkt) < 16:
            continue
        service, method, mtype, client, session, payload = someip_parse(pkt)
        if mtype != MT_REQUEST:
            continue
        if service != MGMT_SERVICE_ID:
            m.sendto(someip_pack(service, method, MT_ERROR, client, session, b'', E_UNKNOWN_SERVICE), addr)
        elif method != M_UPDATEFW:
            m.sendto(someip_pack(service, method, MT_ERROR, client, session, b'', E_UNKNOWN_METHOD), addr)
        else:
            ok = apply_firmware(payload, mode, fw_key)
            m.sendto(someip_pack(MGMT_SERVICE_ID, M_UPDATEFW, MT_RESPONSE,
                                 client, session, bytes([1 if ok else 0])), addr)


def main():
    iface = os.environ.get('CANARY_IFACE', 'vcan0')
    port = int(os.environ.get('CANARY_SOMEIP_PORT', '30509'))
    event_target = os.environ.get('CANARY_EVENT_TARGET', '')
    mode = os.environ.get('CANARY_MODE', 'vulnerable')
    mgmt_port = int(os.environ.get('CANARY_MGMT_PORT', '30510'))
    token = os.environ.get('CANARY_SETLOCK_TOKEN', '')
    fw_key = os.environ.get('CANARY_FW_KEY', '')
    sd_enabled = os.environ.get('CANARY_SD_ENABLED', '1') != '0'
    sd_port = int(os.environ.get('CANARY_SD_PORT', '30490'))
    can = open_can(iface)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind(('0.0.0.0', port))
    state = {'lock': 0}

    def reader():
        while True:
            can_id, data = can_unpack(can.recv(16))
            if can_id == LOCK_STAT_ID and data:
                new = data[0] & 1
                if new != state['lock']:
                    state['lock'] = new
                    send_event(udp, event_target, new)

    threading.Thread(target=reader, daemon=True).start()
    threading.Thread(target=mgmt_server, args=(mode, mgmt_port, fw_key), daemon=True).start()
    if sd_enabled:
        threading.Thread(target=sd_server, args=(local_ip(), port, sd_port), daemon=True).start()
    print(f'canary CGW someip :{port} mgmt :{mgmt_port} sd :{sd_port if sd_enabled else "off"} mode={mode} iface={iface}')

    while True:
        pkt, addr = udp.recvfrom(1024)
        if len(pkt) < 16:
            continue
        service, method, mtype, client, session, payload = someip_parse(pkt)
        if mtype != MT_REQUEST:
            continue

        def err(rc):
            # Standard SOME/IP error so a black-box tester can enumerate the surface.
            udp.sendto(someip_pack(service, method, MT_ERROR, client, session, b'', rc), addr)

        if service != SERVICE_ID:
            err(E_UNKNOWN_SERVICE)
        elif method == M_SETLOCK:
            ok, val = check_token(payload, token)
            if not ok:
                err(E_NOT_OK)                                # method exists, request refused (auth)
            else:
                can.send(can_pack(LOCK_CMD_ID, bytes([val])))
                udp.sendto(someip_pack(SERVICE_ID, M_SETLOCK, MT_RESPONSE, client, session, bytes([val])), addr)
        elif method == M_GETSTATE:
            udp.sendto(someip_pack(SERVICE_ID, M_GETSTATE, MT_RESPONSE, client, session, bytes([state['lock']])), addr)
        elif method == M_RELAYFRAME:
            if len(payload) < 2:
                err(E_MALFORMED_MESSAGE)                     # reveals the method exists
            elif read_policy()['allow_raw']:
                # AUTO-02: reachable only after the unsigned reflash flips allow_raw.
                can_id = (payload[0] << 8) | payload[1]
                can.send(can_pack(can_id, payload[2:10]))
                udp.sendto(someip_pack(SERVICE_ID, M_RELAYFRAME, MT_RESPONSE, client, session, b'\x01'), addr)
            else:
                err(E_NOT_OK)                                # exists but refused until the reflash
        else:
            err(E_UNKNOWN_METHOD)


if __name__ == '__main__':
    main()
