# Octobot Driver — Project Overview

This repository contains the firmware and drivers for a low-cost 4-DOF robotic arm (often sold on AliExpress) controlled by an Arduino UNO/NANO with dual joysticks. The project is organized in two folders:

- `Youfang Smart-ARM-code-v1.71-joystick/` — Arduino sketch/source code.
- `Driver/` — Windows driver installers/archives for the USB-to-serial chips used on Arduino clones.

Only files that can be inspected without reverse engineering are documented below. PE/executable binaries are identified by name and purpose but not analyzed at the machine-code level.

---

## 1. Arduino Firmware

### File
`Youfang Smart-ARM-code-v1.71-joystick/Youfang Smart-ARM-code-v1.71-joystick.ino`

### What it is
A self-contained Arduino sketch (C/C++) that reads two analog joysticks, drives four hobby servos, and supports a simple “teach & repeat” motion recorder.

### Hardware mapping
| Function | Arduino pin | Notes |
|----------|-------------|-------|
| Base servo   | D11 | Rotates the whole arm left/right |
| Left arm     | D10 | Shoulder/elbow joint |
| Right arm    | D9  | Elbow/wrist joint |
| Claw servo   | D5  | Gripper open/close |
| Left joystick button  | D2 | Hold at boot to enter learning mode |
| Right joystick button | D4 | Hold at boot to play the built-in demo |
| Status LED            | D3 | Lit in normal mode; off while recording |
| Joystick ADC          | A0–A3 | One axis per servo |

### Software behavior

#### Normal joystick mode (default)
- Reads each joystick axis (`analogRead(A0..A3)`).
- ADC values range from `0` to `1023`.
- If the value is below `300` or above `700`, the corresponding servo is incremented/decremented by 1° per loop, clamped to configurable min/max limits.
- Servo positions are refreshed every ~20 ms.
- The claw is treated as a binary open/close action instead of a smooth proportional movement.

#### Built-in demo mode
- Triggered by holding the **right** joystick button while the board resets.
- Plays a hard-coded sequence of 9 poses (`demo_actions` array) in a loop.
- Motion between poses is interpolated for smooth movement.
- Any joystick button press exits demo mode.

#### Learning / teach-repeat mode
- Triggered by holding the **left** joystick button while the board resets. The LED turns off to indicate recording.
- The user manually moves the arm with the joysticks to each desired pose and presses the left button to save that pose.
- Up to `100` poses can be stored (volatile RAM; lost on power-down).
- Pressing the right button ends recording and starts automatic playback.
- Playback loops through the recorded poses, interpolates between them, and returns from the last pose to the first.
- Any joystick button press stops playback and returns to joystick control.

### Key constants
| Constant | Default | Meaning |
|----------|---------|---------|
| `SERVOS` | 4 | Number of servos controlled |
| `JOYSTICK_MIN_THRESH` | 300 | ADC value considered “low” / pushed one way |
| `JOYSTICK_MAX_THRESH` | 700 | ADC value considered “high” / pushed the other way |
| `CLAW_OPEN_ANGLE` | 45° | Gripper open position |
| `CLAW_CLOSE_ANGLE` | 5° | Gripper closed position |
| `MAXSPEED` | 10 | Upper bound for playback speed |
| `LEARN_MAX_ACTIONS` | 100 | Maximum recorded poses |

### Serial output
The sketch prints status messages and live ADC/servo values at `115200` baud, useful for debugging via the Arduino Serial Monitor.

---

## 2. USB-to-Serial Drivers

These archives provide the Windows drivers needed so the host PC can talk to the Arduino board over USB. Many low-cost Arduino UNO/NANO clones use either a **CH340/CH341** or an **FTDI FT232** USB-to-UART chip instead of the original Atmega16U2.

### 2.1 `Driver/CH341SER.ZIP`

**Contents (from archive listing):**

| File | Type | Purpose |
|------|------|---------|
| `CH341SER.INF` | INF text | Windows driver installation metadata |
| `CH341SER.CAT` | Catalog | Driver package signature/catalog file |
| `CH341SER.SYS` | Driver | 32-bit Windows driver for CH341 |
| `CH341S64.SYS` | Driver | 64-bit Windows driver for CH341 |
| `CH341S98.SYS` | Driver | Windows 9x driver for CH341 |
| `CH341PT.DLL` | Library | Port/helper DLL |
| `CH341SER.VXD` | Driver | Windows VXD driver (legacy 9x) |
| `SETUP.EXE` | PE binary | Graphical installer / self-extracting setup |
| `DRVSETUP64/DRVSETUP64.exe` | PE binary | 64-bit driver installer |

**What it does:**
Installs the driver for the **CH340/CH341** USB-to-serial bridge chip. Once installed, the Arduino clone appears as a COM port (e.g., `COM3`) in the Arduino IDE and other serial tools. The actual binaries (`SETUP.EXE`, `DRVSETUP64.exe`) are Windows executables and are not reverse-engineered here.

### 2.2 `Driver/CH341SER.EXE`

**File type:** PE32 executable (RAR self-extracting archive) for Windows.

**What it does:**
This is an alternative, self-extracting installer for the same CH341 driver package. Running it on Windows extracts the driver files and/or launches the installer. The executable itself is not analyzed at machine-code level.

### 2.3 `Driver/FTDI232_windows_212226.zip`

**Contents (from archive listing):**

| Path | Description |
|------|-------------|
| `Linux/ftdi_sio.tar.gz` | Linux kernel module source/package for FTDI SIO devices |
| `Windows 7_8_10/CDM 2 12 26 Release Info.rtf` | Release notes for the FTDI driver bundle |
| `Windows 7_8_10/CDM21226_Setup.zip` | Compressed installer for Windows 7/8/10 |
| `Windows ME98_SE/R10906.zip` | Driver package for legacy Windows ME/98/SE |
| `Windows XP_Vista/CDM20824_Setup.exe` | Installer for Windows XP/Vista |

**What it does:**
Provides drivers for the **FTDI FT232** USB-to-serial chip, another common chip found on Arduino clones and USB-to-TTL adapters. The zip contains OS-specific sub-packages; the inner `.exe` and `.zip` installers are binary artifacts and are not reverse-engineered here.

---

## 3. Quick Notes on Flashing

1. Connect the Arduino-compatible board to the PC via USB.
2. Install the correct driver for the USB chip:
   - `CH341SER.*` → use `CH341SER.ZIP` or `CH341SER.EXE`.
   - `FT232` → use `FTDI232_windows_212226.zip`.
3. Open `Youfang Smart-ARM-code-v1.71-joystick.ino` in the Arduino IDE.
4. Select the appropriate board (`Arduino UNO` or `Arduino Nano`) and COM port.
5. Upload the sketch.
6. After reset, the arm enters joystick control mode by default.

---

## 4. Files Not Analyzed

The following files are binary/executable Windows artifacts. They are identified by purpose and source metadata but are **not reverse-engineered**:

- `Driver/CH341SER.EXE` — self-extracting installer.
- `Driver/CH341SER.ZIP`/`Driver/FTDI232_windows_212226.zip` — archives whose inner `.exe`/`.sys`/`.dll` files are binaries.

Only the filenames, archive contents, and the publicly known purpose of the CH341/FTDI driver packages are documented above.

---

## 5. Related Documents

- [`OPENWRT_INTEGRATION.md`](./OPENWRT_INTEGRATION.md) — how to control the arm remotely from OpenWRT on a Raspberry Pi 3B+ and use it as an ICS/IoT pentesting lab target.
