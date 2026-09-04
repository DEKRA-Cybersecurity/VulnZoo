---
id: BULB-03
title: "Cleartext, replayable control channel (BLE + HTTP)"
category: IoT
status: IN PROGRESS
severity: Medium
owasp: "OWASP IoT Top 10 (2018) I7 - Insecure Data Transfer and Storage"
standard: "ETSI EN 303 645 5.5 (communicate securely)"
regulation: "CRA (EU) 2024/2847 Annex I Part I - protect data in transit"
cwe: "CWE-319 (Cleartext Transmission of Sensitive Information) / CWE-294 (Authentication Bypass by Capture-replay)"
source_docs:
  - "stages/01_spec/output/bulbbee-03-spec.md"
affected_components:
  - "labs/bulbbee/files/opt/bulbbee/lighting_service.py"
  - "labs/bulbbee/files/opt/bulbbee/ble_light.py"
verified_date: "2026-09-04"
---

## Why It Matters

BulbBee's control traffic is unencrypted and replayable on both surfaces. The BLE Lighting Control link (`0xFF31`) uses no LE encryption or bonding, so a sniffer in range recovers the "set scene / set colour" GATT writes in cleartext and replays them verbatim. The HTTP control API on `:8082` is plain HTTP with no TLS, and its commands carry no nonce, timestamp, or sequence number, so a captured `POST /set` or `POST /scene` replays byte-for-byte and re-applies. Nothing makes a captured command stale.

The confidentiality loss is small for colour and scene, but the same cleartext channel carries the provisioning and configuration reads (BULB-02), so a passive listener also recovers whatever those disclose. The replayability means an attacker who once observed a legitimate command can reissue it at will without ever authenticating.

## Root Cause

The BLE characteristic uses plain flags and a non-pairable adapter, so the link is never encrypted:

```python
# ble_light.py
self.flags = ["read", "write", "write-without-response"]   # no encrypt-* variant
```

The HTTP API is plain `http.server` with no TLS, and commands are applied idempotently with no anti-replay token:

```python
# lighting_service.py
server = ThreadingHTTPServer(("0.0.0.0", port), Handler)   # plain HTTP, no TLS
...
def do_POST(self):
    if self.path == "/set":
        c.set_state(...)        # no nonce / timestamp / sequence -> replays re-apply
```

The missing controls are transport encryption (TLS on HTTP, LE Secure Connections on BLE) and per-command freshness (a nonce or monotonic sequence).

## Steps to Reproduce

HTTP capture and replay (works on the LAN with no credential):

```sh
# capture a legitimate command in flight
sudo tcpdump -i any -A -s0 'tcp port 8082 and tcp[tcpflags] & tcp-push != 0'
# ... a user sets a scene ...
# replay the captured POST verbatim, it re-applies with no rejection
printf 'POST /scene HTTP/1.1\r\nHost: 192.168.2.1:8082\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{"scene":"rainbow"}' | nc 192.168.2.1 8082
```

BLE sniff and replay (needs a radio / sniffer):

```sh
btmon                                  # observe the cleartext ATT write to 0xFF31
# replay the same value from a central, it re-applies (no encryption, no freshness)
```

## Expected Result

- The HTTP command is visible in cleartext in the capture, and a byte-identical replay re-applies with no error.
- The BLE ATT write to `0xFF31` is visible in cleartext (the link is not encrypted), and a replay re-applies.

## How It Should Be

- Serve the HTTP control API over TLS, and require LE Secure Connections encryption on the BLE Control characteristic.
- Add per-command freshness (a nonce or monotonic sequence with a short window) so a captured command cannot be replayed.

These land behind the `secure` UCI toggle (BULB-SEC).

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Device (HTTP) | TLS on `:8082` | Confidentiality in transit (CWE-319) |
| Device (BLE) | LE Secure Connections encryption on `0xFF31` | Confidentiality in transit (CWE-319) |
| Device (protocol) | Per-command nonce / monotonic sequence | Stop replay (CWE-294) |

## Verification Checklist

- [ ] A byte-identical replay of a captured `POST /set` / `POST /scene` re-applies (no anti-replay).
- [ ] The BLE Control write is cleartext (no LE encryption), confirmed by the characteristic flags.
- [ ] In `secure` mode the HTTP is TLS, the BLE link is encrypted, and replays are rejected (BULB-SEC).
