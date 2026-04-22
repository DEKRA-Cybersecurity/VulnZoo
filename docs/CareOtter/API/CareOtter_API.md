# CareOtter Cloud API Documentation

> **Path**: `cloud_api/careotter/`  
> **Port**: `:5002` (Docker)  
> **Purpose**: HTTP-to-IGP bridge between clients and the CareOtter medical device.

---

## Overview

The CareOtter Cloud API is a Flask application that acts as an intermediary between HTTP clients (mobile apps, web dashboards) and the CareOtter DAI device. It translates REST requests into the legacy IGP v4 binary protocol and provides persistent storage via SQLite.

### Operating Modes

| Mode | `VULNERABLE` | Behavior |
|------|-------------|----------|
| Vulnerable | `1` (default) | Debug mode ON, raw WiFi PSK exposed, format strings forwarded, Werkzeug debugger active |
| Safe | `0` | Debug OFF, sensitive data filtered, generic error messages |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     CareOtter Cloud API                         │
│                         (Docker :5002)                          │
├─────────────────────────────────────────────────────────────────┤
│  HTTP REST API  │  JWT Auth  │  IGP v4 Client  │  HTTP Client   │
│   (Flask)       │  (PyJWT)   │  (Binary TCP)   │  (vitals)      │
├─────────────────────────────────────────────────────────────────┤
│  SQLite DB — vitals_readings, device_events, device_config,     │
│  users (with roles)                                             │
└────────┬────────────────────────────────────────────────────────┘
         │                              │
         │ HTTP :5002                   │ IGP :9999 / HTTP :8081
         ▼                              ▼
┌─────────────────┐             ┌──────────────────────┐
│  Mobile Client  │             │   CareOtter Device   │
│  (Android App)  │             │   (192.168.2.1)      │
└─────────────────┘             └──────────────────────┘
```

---

## Database Schema

The API uses an embedded SQLite database (`/app/data/careotter.db` in Docker, fallback to `/tmp/careotter.db`).

### Tables

#### `vitals_readings`
Stores cardiac telemetry from the device.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK | Auto-increment |
| `timestamp` | REAL | Epoch time from sensor |
| `bpm` | INTEGER | Heart rate |
| `spo2` | INTEGER | Blood oxygen saturation |
| `ir_raw` | INTEGER | Raw IR sensor value |
| `red_raw` | INTEGER | Raw red sensor value |
| `source` | TEXT | "simulator" or "hardware" |
| `created_at` | TIMESTAMP | Insertion time |

#### `device_events`
Tracks administrative events.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK | Auto-increment |
| `event_type` | TEXT | auth_success, auth_fail, config_change, etc. |
| `details` | TEXT | Additional context |
| `ip_address` | TEXT | Client IP |
| `timestamp` | TIMESTAMP | Event time |

#### `device_config`
Key-value store for persistent settings.

| Column | Type | Description |
|--------|------|-------------|
| `key` | TEXT PK | Setting name |
| `value` | TEXT | Setting value |
| `updated_at` | TIMESTAMP | Last modification |

#### `users` *(new)*
User accounts with role-based access control.

| Column          | Type        | Description                             |
| --------------- | ----------- | --------------------------------------- |
| `id`            | INTEGER PK  | Auto-increment                          |
| `username`      | TEXT UNIQUE | Login name                              |
| `password_hash` | TEXT        | SHA-256 hash of password                |
| `role`          | TEXT        | `admin`, `user`, `operator`, `readonly` |
| `created_at`    | TIMESTAMP   | Account creation time                   |

### Default User

On first startup, the API automatically creates:

| Username | Password         | Role    |
| -------- | ---------------- | ------- |
| `admin`  | `CareOtter2026!` | `admin` |

> ⚠️ **Intentional vulnerability**: Passwords are stored with simple SHA-256 hashing (no salt, no bcrypt/Argon2), making them susceptible to rainbow table attacks if the database is exfiltrated.

---

## Authentication

### Admin Login

`POST /api/auth/login`

Authenticates against the local SQLite user database. The endpoint verifies the username and password (SHA-256 without salt) and **requires the user role to be `admin`**. On success, a JWT containing the role is issued.

```bash
curl -X POST http://localhost:5002/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "CareOtter2026!"}'
```

**Response (success):**
```json
{
  "token": "<JWT>",
  "expires_in": "8h",
  "type": "Bearer",
  "role": "admin"
}
```

**Response (invalid credentials):**
```json
{
  "error": "Invalid username or password",
  "code": "AUTH_FAIL"
}
```

**Response (non-admin user):**
```json
{
  "error": "Admin access required",
  "code": "FORBIDDEN"
}
```

> 🔒 **Note**: The old hardcoded device token login (`{"token": "OtterMobile2026"}`) has been removed from the web admin panel. The Admin Panel now exclusively uses database-backed username/password authentication with role enforcement.

### Programmatic User Verification

The `DatabaseService.verify_user(username, password)` method is available for role-based authentication in custom scripts:

```python
from services.database_service import DatabaseService
db = DatabaseService()
user = db.verify_user('admin', 'CareOtter2026!')
# Returns: {'id': 1, 'username': 'admin', 'role': 'admin', 'created_at': '...'}
```

### JWT Protected Endpoints

Protected endpoints require:
```
Authorization: Bearer <JWT>
```

---

## API Endpoints

### Public Endpoints (No Auth)

| Method | Endpoint | IGP Cmd | Description |
|--------|----------|---------|-------------|
| GET | `/api/health` | — | API status, version, device connectivity |
| GET | `/api/device/info` | 0x01 SYS_INFO | Kernel version and architecture |
| GET | `/api/device/status` | 0x05 VERIFY_STATUS | Module diagnostics (vulnerable to format string) |
| GET | `/api/vitals` | HTTP :8081 | Current BPM/SpO2 from sensor |
| GET | `/api/vitals/history` | HTTP :8081 | Vitals history buffer |

### JWT Protected Endpoints

| Method | Endpoint | IGP Cmd | Description |
|--------|----------|---------|-------------|
| GET | `/api/network` | 0x03 GET_NETWORK | WiFi config (raw exposes PSK) |
| POST | `/api/network/wifi` | 0x06 SET_WIFI | Configure WiFi (shell injection) |
| POST | `/api/config/preferences` | 0x04 SET_PREFS | TLV preferences (integer underflow) |
| POST | `/api/config/thresholds` | 0x08 SET_THRESHOLD | Clinical alert thresholds |
| POST | `/api/services/restart` | 0x09 REBOOT_SERVICE | Restart init.d services |
| GET | `/api/logs` | 0x0A GET_LOG | Last 512 bytes of device log |

### Admin Panel (Web UI)

| URL | Page |
|-----|------|
| `/` | Public dashboard — live vitals |
| `/admin/login` | Username/password login form |
| `/admin/dashboard` | Live vitals + device info |
| `/admin/network` | View/change WiFi configuration |
| `/admin/config` | Clinical thresholds + TLV preferences |
| `/admin/services` | Restart init.d services |
| `/admin/logs` | Device log viewer + vitals history table |
| `/history` | SQLite vitals history with stats and export |

---

## Database Service API

### User Management Methods

```python
from services.database_service import DatabaseService

db = DatabaseService()

# Create a new user
db.create_user(username="dr_smith", password="secret123", role="doctor")

# Verify credentials (returns user dict without password_hash)
user = db.verify_user("admin", "CareOtter2026!")

# List all users
users = db.list_users()  # [{'id': 1, 'username': 'admin', 'role': 'admin', ...}]

# Update role
db.update_user_role("dr_smith", "admin")

# Delete user
db.delete_user("dr_smith")
```

### Vitals Methods

```python
# Store vitals reading
db.store_vitals({"timestamp": 1758317888.48, "bpm": 72, "spo2": 98, ...})

# Get history
db.get_vitals_history(hours=24, limit=100)

# Get statistics
db.get_vitals_stats(hours=24)

# Database info
db.get_db_info()
```

---

## Vulnerability Surface

### Critical

| #   | Type                  | Location              | Evidence                                                  |
| --- | --------------------- | --------------------- | --------------------------------------------------------- |
| 1   | Weak JWT Secret       | `config.py`           | `JWT_SECRET = 'careotter_jwt_2026'`                       |
| 2   | Debug Mode RCE        | `app.py`              | `debug=(vuln == 1)` enables Werkzeug console              |
| 3   | Format String Proxy   | `app.py`              | `/api/device/status?module=` passes unsanitized to device |
| 4   | Weak Password Storage | `database_service.py` | SHA-256 without salt (rainbow-table vulnerable)           |

### High

| # | Type | Location | Evidence |
|---|------|----------|----------|
| 5 | WiFi PSK Disclosure | `device_service.py` | `raw` field in `/api/network` |
| 6 | Info Leak | `app.py` | `/api/health` exposes device IP |
| 7 | Shell Injection | `careservice.c` | `SET_WIFI` uses `system()` without escaping |

### Medium

| # | Type | Location | Evidence |
|---|------|----------|----------|
| 8 | Partial Role Checks | `app.py` | Login enforces `admin` role, but JWT-protected API endpoints only validate token signature/expiry, not the `role` claim inside the token |
| 9 | No Rate Limiting | Global | `flask-limiter` not implemented |
| 10 | Plaintext HTTP | Global | No TLS termination |

---

## Deployment

```bash
cd cloud_api/careotter
docker compose up -d --build

# Verify
curl http://localhost:5002/api/health
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VULNERABLE` | `1` | Enable/disable vulnerable features |
| `DEVICE_IP` | `192.168.2.1` | CareOtter device IP |
| `IGP_PORT` | `9999` | IGP protocol port |
| `HTTP_PORT` | `8081` | Medical sensor HTTP port |
| `JWT_SECRET` | `careotter_jwt_2026` | JWT signing key |
| `JWT_EXPIRATION_HOURS` | `8` | Token validity |
| `PORT` | `5002` | API listening port |
| `DB_PATH` | `/app/data/careotter.db` | SQLite database path |

---

## References

- Parent Stage: `cloud_api/CONTEXT.md`
- Device Lab: `labs/careotter/CONTEXT.md`
- Mobile App: `vulnzoo_apps/careotter_app/CONTEXT.md`
- IGP Protocol: `docs/CareOtter/CareOtter.md`
