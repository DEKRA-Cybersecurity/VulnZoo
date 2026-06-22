---
id: IoT:I10
title: "Lack of Physical Hardening"
category: IoT
status: IN PROGRESS
severity: Medium
owasp: "IoT I10 - Lack of Physical Hardening"
cwe: "CWE-1263 (Improper Physical Access Control) / CWE-1191 (Exposed Chip Debug/Test Interface)"
source_docs:
  - "src/docs/OctoBot/OPENWRT_INTEGRATION.md §2, §4, §7 (IoT:I10)"
  - "stages/01_spec/output/octobot-spec.md"
  - "stages/02_implement/output/manifest.md"
affected_components:
  - "labs/octobot/arduino_stuff/Youfang Smart-ARM-code-v1.71-joystick/Youfang Smart-ARM-code-v1.71-joystick.ino"
verified_date: ""
---

## Why It Matters

Physical access to the cell is game over. The Arduino is reflashable over its USB bootloader with no protection, the serial/UART header is exposed, and the Raspberry Pi SD card holds the lab secrets in cleartext and can be pulled and read in another machine. The firmware serial parser also appends input to an unbounded Arduino `String`, so an overlong frame grows the heap until the ATmega328P (2 KB SRAM) exhausts memory and resets, a denial of service reachable once an attacker is on the wire.

## Root Cause

The controller has no boot/flash protection, so anyone with the USB port reflashes it (this is the local counterpart of the network OTA in IoT:I4). The firmware command parser appends each byte to a dynamic `String` with no length cap, so an unbounded frame grows the heap until SRAM is exhausted:

```cpp
// labs/octobot/arduino_stuff/.../Youfang Smart-ARM-code-v1.71-joystick.ino
void handle_serial() {
  static String line;
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n') { process_command(line); line = ""; }
    else if (c != '\r') { line += c; }
  }
}
```

The SD card stores the overlay (and thus the cleartext UCI secrets) with no encryption, and the UART/USB interfaces are unauthenticated and unlocked.

## Steps to Reproduce

```bash
# A. Reflash the controller over USB, no protection (local)
avrdude -c arduino -p atmega328p -P /dev/ttyACM0 -b 115200 -U flash:w:evil.hex:i

# B. Pull the SD card, mount elsewhere, read cleartext secrets
#    -> etc/config/octobot contains api_key / admin_pass in cleartext

# C. Memory-exhaustion: an unbounded frame grows the String heap until the MCU resets
python3 -c 'import socket; s=socket.create_connection(("192.168.2.1",2000)); s.sendall(b"S0:"+b"9"*200000)'
```

## Expected Result

The Arduino accepts a reflash over USB with no authentication, the SD card yields cleartext secrets when mounted externally, and the serial parser accepts an unbounded frame with no length cap (on real hardware this grows the heap to a memory-exhaustion reset).

## How It Should Be

Lock the bootloader and enable read protection where the MCU supports it, disable or authenticate exposed debug/UART interfaces, encrypt sensitive data at rest on the SD card, and add tamper-evident enclosure measures. Bound and validate serial input length in firmware.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| MCU | Lock bootloader, enable read protection | Stop trivial reflash |
| Interfaces | Disable/authenticate UART/debug headers | Remove physical footholds |
| Storage | Encrypt secrets at rest on the SD | Survive card theft |
| Firmware | Bounded, validated serial input | Harden the parser |

## Verification Checklist

- [ ] Arduino reflashes over USB with no protection
- [ ] SD card mounted externally exposes cleartext secrets
- [ ] Serial parser accepts an unbounded frame (no length cap on the `String`)
