# Cloud API - External Services (Layer 2)

**Stage Purpose**: Deploy Dockerized external APIs that simulate cloud backends for IoT devices with multiple intentional security vulnerabilities for comprehensive IoT/cloud security training.

## Structure

The cloud_api directory contains subdirectories organized by laboratory:

```
cloud_api/
├── CONTEXT.md              # This file - Global cloud API documentation
├── octobot/                # OctoBot Industrial Arm Lab (Layer 2 Sub-stage)
│   ├── docker-compose.yml # Service orchestration
│   ├── app.py             # Flask operator console + Modbus/TCP master
│   ├── services/          # Auth, Modbus master, firmware push
│   └── static/templates/  # Operator web UI
├── owlcam/                 # OwlCam IP Camera Lab (Layer 2 Sub-stage)
│   ├── CONTEXT.md         # Lab-specific documentation
│   ├── docker-compose.yml # Service orchestration
│   ├── api_server/        # Flask API with JWT vulnerabilities
│   ├── c2_server/         # Command & Control SSE server
│   └── camera_sim/        # Simulated camera stream generator
├── careotter/              # CareOtter Medical Device Lab (Layer 2 Sub-stage)
│   ├── CONTEXT.md         # Lab-specific documentation
│   ├── docker-compose.yml # Service orchestration
│   └── api_server/        # Flask API with IGP protocol bridge
```

## Available Labs

| Lab | Path | Description | Primary Interface |
|-----|------|-------------|-------------------|
| **octobot** | `cloud_api/octobot/` | Industrial robot-arm operator console; Modbus/TCP master to the Pi gateway | HTTP :5003 |
| **owlcam** | `cloud_api/owlcam/` | IP Camera cloud backend with JWT, C2, and SSRF vulnerabilities | HTTP :5000, :4999 |
| **careotter** | `cloud_api/careotter/` | Medical device cloud gateway with IGP protocol bridge | HTTP :5002 |

## Quick Navigation

- **OwlCam Lab**: See `cloud_api/owlcam/CONTEXT.md` for detailed lab documentation
- **Global Cloud Docs**: Continue reading this file for cross-cutting concerns

## Common Components

### Service Architecture (per lab)

| Component | Type | Technology | Purpose |
|-----------|------|------------|---------|
| API Server | Docker | Python/Flask + MongoDB | Main API backend with vulnerable JWT |
| C2 Server | Docker | Python/Flask + SSE | Botnet Command & Control simulation |
| Camera Sim | Docker | Python/OpenCV | Video stream simulation |
| Database | Docker | MongoDB | User/camera/message storage |

### Common Vulnerability Categories

| Category | Examples |
|----------|----------|
| **JWT Attacks** | Weak secrets, algorithm confusion, none algorithm |
| **Path Traversal** | LFI via weak sanitization, arbitrary file write |
| **SSRF** | URL fetching from uploaded files |
| **Auth Bypass** | Referer checks, missing decorators, ID exposure |
| **Injection** | Template injection, NoSQL injection |

## Cross-Cutting Concerns

### Network Configuration

All cloud API labs use Docker networking:
```yaml
# Standard docker-compose network
networks:
  vulnzoo_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

### Database Pattern (MongoDB)

```javascript
// Standard schema across labs
db.users.insert({
    username: String,
    password: String,  // bcrypt hashed
    role: String,      // user, viewer, admin
    cameras_access: Array
})

db.messages.insert({
    sender_id: ObjectId,
    sender_username: String,
    recipient_id: ObjectId,
    message: String,
    timestamp: ISODate
})
```

### Deployment Pattern

```bash
# Generic deployment (see specific lab CONTEXT.md for details)
cd cloud_api/<lab_name>
docker-compose up -d --build
```

## References

| Resource | Location |
|----------|----------|
| OctoBot Lab Details | `src/docs/OctoBot/OPENWRT_INTEGRATION.md` |
| OwlCam Lab Details | `cloud_api/owlcam/CONTEXT.md` |
| API Vulnerabilities | `docs/OwlCam/API/Vulnerabilities.md` |
| C2 Architecture | `docs/OwlCam/Mobile/ARCHITECTURE_SSE_C2.md` |
| OWASP API Top 10 | 2023 |
| JWT Attacks | https://portswigger.net/web-security/jwt |

## Task Routing

| User Intent | Go To | Read First |
|-------------|-------|------------|
| Deploy OctoBot cloud API | `cloud_api/octobot/` | `src/docs/OctoBot/OPENWRT_INTEGRATION.md` |
| Deploy OwlCam cloud API | `cloud_api/owlcam/` | `cloud_api/owlcam/CONTEXT.md` |
| Deploy CareOtter cloud API | `cloud_api/careotter/` | `cloud_api/careotter/CONTEXT.md` |
| Understand cloud vulnerabilities | `docs/OwlCam/` | `docs/OwlCam/API/Vulnerabilities.md` |
| Configure specific service | `cloud_api/<lab>/` | Lab-specific CONTEXT.md |
