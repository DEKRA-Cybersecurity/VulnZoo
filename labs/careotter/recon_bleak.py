#!/usr/bin/env python3
"""
CareOtter BLE reconnaissance script — discovers ALL GATT services,
including hidden ones not advertised in the BLE scan response.

Compatible with bleak >= 0.20 (client.services is a property).
Usage:
    python3 recon_bleak.py          # auto-scan for CareOtter_HR
    python3 recon_bleak.py <MAC>    # connect directly by MAC address
"""

import asyncio
import sys

from bleak import BleakClient, BleakScanner


async def scan():
    print("[*] Scanning for BLE peripherals...")
    devices = await BleakScanner.discover(timeout=5.0)
    targets = [d for d in devices if d.name and "CareOtter" in d.name]
    if not targets:
        print("[-] No CareOtter device found.")
        return None
    for d in targets:
        rssi = getattr(d, "rssi", "?")
        print(f"[+] Found: {d.name} @ {d.address}  RSSI={rssi}")
    return targets[0].address


async def recon(mac: str):
    print(f"[*] Connecting to {mac} ...")
    async with BleakClient(mac) as client:
        print(f"[+] Connected: {client.is_connected}")

        # bleak API varies across distributions; services are usually
        # auto-discovered on connect and exposed via client.services.
        services = client.services
        if services is None:
            print("[-] client.services is None — trying fallback")
            services = []

        svc_list = list(services) if hasattr(services, "__iter__") else []
        print(f"[+] Discovered {len(svc_list)} service(s)\n")

        for svc in svc_list:
            print(f"Service: {svc.uuid}")
            for ch in svc.characteristics:
                props = ",".join(ch.properties)
                print(f"  Characteristic: {ch.uuid}  [{props}]")
            print()

        # Highlight the hidden provisioning service
        prov = [s for s in svc_list if "ff10" in s.uuid.lower()]
        if prov:
            print("[!] HIDDEN PROVISIONING SERVICE DETECTED (0xFF10)")
            for ch in prov[0].characteristics:
                print(f"    -> {ch.uuid}  props={ch.properties}")
        else:
            print("[-] No provisioning service (0xFF10) found.")


async def main():
    if len(sys.argv) > 1:
        mac = sys.argv[1]
    else:
        mac = await scan()
        if mac is None:
            sys.exit(1)

    await recon(mac)


if __name__ == "__main__":
    asyncio.run(main())
