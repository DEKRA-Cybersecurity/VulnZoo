# CareOtter Admin - Android Application (Layer 2)

**Stage Purpose**: Mobile application for administering and testing the CareOtter medical device, providing interfaces for both BLE medical data and the vulnerable TCP admin service.

## Scenario

The CareOtter Admin app allows security researchers and students to interact with the CareOtter medical device. The app demonstrates:
- Normal BLE connectivity for medical monitoring
- TCP communication with the vulnerable admin service
- Exploitation of intentional vulnerabilities (Format String, Integer Underflow)
- Protocol analysis and reverse engineering of the IGP v4 protocol

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    ANDROID DEVICE                               │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   CareOtter Admin App                    │   │
│  │                                                          │   │
│  │  ┌─────────────────┐      ┌─────────────────────────┐   │   │
│  │  │  BLE Client     │      │  TCP Client             │   │   │
│  │  │  (Medical)      │      │  (Admin/Exploits)       │   │   │
│  │  │                 │      │                         │   │   │
│  │  │  • Heart Rate   │      │  • Protocol IGP v4      │   │   │
│  │  │  • SpO2         │      │  • Format String        │   │   │
│  │  │  • Battery      │      │  • Integer Underflow    │   │   │
│  │  └────────┬────────┘      └──────────┬──────────────┘   │   │
│  │           │                          │                  │   │
│  │  ┌────────┴──────────────────────────┴──────────────┐  │   │
│  │  │              MainActivity (UI)                   │  │   │
│  │  │                                                  │  │   │
│  │  │  • IP Configuration (192.168.2.1)               │  │   │
│  │  │  • Auth Status Indicator                        │  │   │
│  │  │  • Command Buttons (0x01-0x05)                  │  │   │
│  │  │  • Output Console                               │  │   │
│  │  └──────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
└──────────────────────────────┼──────────────────────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │ BLE              │ TCP              │
          ▼                  ▼                  ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  CareOtter      │  │  CareService    │  │  HTTP API       │
│  BLE GATT       │  │  Port 9999      │  │  Port 8081      │
│                 │  │                 │  │                 │
│  • Heart Rate   │  │  • Admin cmds   │  │  • Vitals       │
│  • Pulse Ox     │  │  • Vulns        │  │  • Health       │
└─────────────────┘  └─────────────────┘  └─────────────────┘
       │                      │                  │
       └──────────────────────┴──────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │   Raspberry Pi    │
                    │   192.168.2.1     │
                    └───────────────────┘
```

## Components

### 1. CareOtterClient.java
**Purpose**: TCP client for the IGP v4 admin protocol

**Location**: `app/src/main/java/com/example/careotter_app/CareOtterClient.java`

**Protocol**: IGP v4 (IoT Gateway Protocol)
```
Header: [Magic(4) | Cmd(1) | Status(1) | Len(2)]
Magic: 0x474F4154 ("GOAT")
Payload: variable length
```

**Commands**:
| Cmd | Name | Auth | Description |
|-----|------|------|-------------|
| 0x01 | SYS_INFO | No | System information (kernel, arch) |
| 0x02 | AUTHENTICATE | No | Login with token |
| 0x03 | WIFI_CONFIG | Yes | Read WiFi configuration |
| 0x04 | SET_PREFS | Yes | TLV parser (underflow vuln) |
| 0x05 | VERIFY_STATUS | No | Status check (format string vuln) |

**Token Obfuscation**:
```java
// Token: "OtterMobile2026"
// XOR Key: 0x5A
private static final byte[] ENCODED_TOKEN = {
    0x15, 0x2E, 0x2E, 0x3F, 0x28, 0x17, 0x35, 0x38, 
    0x33, 0x36, 0x3F, 0x68, 0x6A, 0x68, 0x6C
};
```

**Vulnerability Methods**:
- `exploitFormatString()` - Sends `%x %x %x %x` to leak stack
- `exploitUnderflow()` - Sends malformed TLV to trigger underflow

### 2. MainActivity.java
**Purpose**: Android UI for device administration

**Location**: `app/src/main/java/com/example/careotter_app/MainActivity.java`

**Features**:
- IP address configuration (default: 192.168.2.1)
- Authentication status indicator (GUEST/ADMIN)
- Command buttons for all IGP commands
- Output console with scrollable text

**Flow - Check Status** (from original code):
```java
1. Connect to device
2. Get SYS_INFO (public)
3. Attempt AUTH with decoded token
4. If success → fetch WiFi config
5. Display results
```

### 3. activity_main.xml
**Purpose**: UI layout with Material Design components

**Elements**:
- `etIpAddress` - IP input field
- `tvAuthStatus` - Authentication status indicator
- `btnCheckStatus` - Complete auth flow button
- Command buttons grid (SYS INFO, AUTH, WIFI, etc.)
- `tvOutput` - Response console

## Inputs

| Layer | Source Path | Role/Description |
|-------|-------------|------------------|
| **Layer 2** | `../../labs/careotter/CareOtterClient.java` | Reference protocol implementation |
| **Layer 2** | `../../labs/careotter/careservice.c` | Service protocol specification |
| **Layer 4** | `app/src/main/java/` | Android Java source |
| **Layer 4** | `app/src/main/res/` | Android resources (XML) |

## Process

### 1. Build Application

```bash
cd vulnzoo_apps/careotter_app

# Build with Gradle
./gradlew assembleDebug

# Or use Android Studio
# File → Open → Select careotter_app folder
# Build → Build Bundle(s) / APK(s) → Build APK
```

### 2. Deploy to Device

```bash
# Install via ADB
adb install app/build/outputs/apk/debug/app-debug.apk

# Or transfer APK to phone and install manually
```

### 3. Connect to CareOtter

1. Connect phone to same WiFi as Raspberry Pi
2. Open CareOtter Admin app
3. Verify IP shows `192.168.2.1`
4. Tap **"Conectar"**
5. Tap **"CHECK STATUS"** for full auth flow

### 4. Test Vulnerabilities

**Format String Exploit**:
- Tap **"FMT STRING"** button
- App sends: `%x %x %x %x %x`
- Output shows leaked stack addresses

**Integer Underflow Exploit**:
- First tap **"AUTH"** to authenticate
- Then tap **"UNDERFLOW"**
- App sends malicious TLV: `[0xAA, 0xFF, 0x41, 0x41, 0x41, 0x41]`

## Outputs

| Artifact | Location | Description |
|----------|----------|-------------|
| APK Debug | `app/build/outputs/apk/debug/` | Debug build |
| APK Release | `app/build/outputs/apk/release/` | Release build |
| AAB | `app/build/outputs/bundle/` | Android App Bundle |

## Network Requirements

| Requirement | Value |
|-------------|-------|
| Target IP | 192.168.2.1 (default) |
| Admin Port | 9999 (TCP) |
| BLE | hci0 (Bluetooth) |
| Permissions | INTERNET, BLUETOOTH |

## Dependencies

| Component | Version | Purpose |
|-----------|---------|---------|
| Android SDK | 29+ (min) | API compatibility |
| AppCompat | Latest | UI components |
| Material | Latest | Material Design |

## Verification Checklist

- [ ] App compiles without errors
- [ ] Installs on Android device
- [ ] Connects to 192.168.2.1:9999
- [ ] SYS_INFO returns kernel version
- [ ] AUTH succeeds with "OtterMobile2026"
- [ ] WiFi Config readable after auth
- [ ] Format String leaks stack data
- [ ] UI responsive and scrollable

## Security Notes

**Vulnerabilities for Testing**:
- Hardcoded token is intentionally obfuscated with XOR
- Format string allows memory leak
- Integer underflow can crash service
- WiFi config disclosure after auth

**Educational Purpose Only**:
This app is designed for security training in controlled environments.

## References

- Service: `labs/careotter/careservice.c`
- Protocol: IGP v4 (documented in CareOtterClient.java)
- Lab: `labs/careotter/CONTEXT.md`
