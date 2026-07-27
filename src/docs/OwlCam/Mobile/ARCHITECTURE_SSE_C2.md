# VulnZoo C2 - New HTTP/SSE Architecture

## Transformation Summary

The Command and Control (C2) system architecture has been fully migrated from native TCP/WebSocket to HTTP with Server-Sent Events (SSE). This transformation provides greater pedagogical realism for advanced persistent threat (APT) simulations.

## Before vs After

| Characteristic | Old (TCP/WS) | New (HTTP/SSE) |
|---------------|------------------|------------------|
| **C2 ports** | 8443 (TCP), 8444 (WS) | 4999 (HTTP) |
| **Protocol** | Native TCP + WebSocket | HTTP + Server-Sent Events |
| **Infrastructure** | Embedded in Flask API | Standalone container |
| **FW evasion** | Low (non-standard ports) | High (standard HTTP) |
| **NAT traversal** | Problems with 4G/5G | Works on any network |
| **Containment** | Not possible | C2 can be isolated without affecting the API |

## File Structure

```
cloud_api/
├── docker-compose.yml           # Updated: new c2-server service
├── api_server/
│   ├── Dockerfile               # Updated: no C2 ports
│   ├── app.py                   # Updated: no C2 initialization
│   ├── config.py                # Updated: C2_SERVER_URL
│   └── core/
│       └── c2_diag.py           # Updated: validation/proxy only
│
└── c2_server/                   # NEW: standalone C2 server
    ├── Dockerfile
    ├── requirements.txt
    ├── c2_server.py             # Main HTTP/SSE server
    ├── device_simulator.py      # Device simulator
    └── README.md

vulnzoo_app/
└── app/src/main/java/...
    ├── util/ApiConfig.kt        # Updated: HTTP/SSE endpoints
    └── service/
        ├── DiagSysService.kt    # TCP version (legacy)
        └── DiagSysServiceSSE.kt # NEW: HTTP/SSE version

docs/VulnZoo-Documentation/
├── C2-HTTP-SSE-Migration.md     # Full migration guide
└── ...
```

## Quick Start

### 1. Build and Start Services

```bash
cd cloud_api

# Build all containers
docker-compose build

# Start infrastructure
docker-compose up -d

# Check status
docker-compose ps
```

### 2. Verify Operation

```bash
# Health check C2
curl http://localhost:4999/health

# Flask API running
curl http://localhost:5000/api/health

# Validate diagnostic token
curl -X POST http://localhost:5000/api/v2/diag/validate \
  -H "Content-Type: application/json" \
  -d '{"token": "000007", "device_id": "test", "model": "TestDevice"}'
```

### 3. Access the C2 Panel

Open in browser: `http://localhost:4999/panel`

Credentials: `letstechin`

### 4. Simulate Mobile Device

```bash
# Terminal 1: Start simulator
cd cloud_api/owlcam/c2_server
python device_simulator.py --token 000007

# Terminal 2: Simulate multiple devices
python device_simulator.py --multi 5
```

### 5. Full C2 Flow

1. **C2 Panel** (`http://localhost:4999/panel`) → Login → View active sessions
2. **Simulator** automatically connects via SSE to `http://localhost:4999/stream`
3. In the panel: Select device → Type command → Enter
4. Command travels: Panel → C2 Server → SSE → Simulator
5. Response travels: Simulator → POST → C2 Server → Panel

## C2 API Endpoints

### Downstream Channel (SSE)

```http
GET /stream
Headers:
  X-Device-ID: <device_id>
  X-Diag-Token: <token>
  X-Device-Model: <model>
  Accept: text/event-stream
```

### Upstream Channel (POST)

```http
POST /response
Content-Type: application/json

{
  "session_id": "...",
  "type": "output",
  "data": "result",
  "timestamp": 1234567890000
}
```

### Control Panel

```http
POST /panel/auth              # Login
GET  /panel/sessions          # List sessions
POST /panel/command           # Send command
GET  /panel/responses/<id>    # Get responses
GET  /panel/logs              # Audit logs
```

## Valid Tokens

Algorithm: `sum(hex_digits) % 7 == 0`

Valid examples:
- `000000` (sum=0)
- `000007` (sum=7)
- `000016` (sum=7)
- `00A00D` (sum=18, 18%7=4 → **invalid**)

Python generator:
```python
def generate_valid_token():
    import random
    while True:
        token = ''.join(random.choices('0123456789ABCDEF', k=6))
        total = sum(int(c, 16) for c in token)
        if total % 7 == 0:
            return token
```

## Security and Isolation

### Docker Network

```
┌─────────────────────────────────────────────────────────┐
│  NETWORK: c2_net (isolated)                             │
│  ├── c2-server:4999  ◄── External C2 connections      │
│  ├── vulnzoo-vulnerable:5000 ──► Proxy to C2          │
│  └── mongo:27017 ◄── Logs and persistence             │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  NETWORK: cam_net (internal, cameras only)              │
│  ├── camera_admin:9090                                  │
│  ├── camera_elliot:9090                                 │
│  └── vulnzoo-vulnerable:5000                            │
│  NOTE: c2-server has NO access to this network          │
└─────────────────────────────────────────────────────────┘
```

### Containment

```bash
# Stop C2 without affecting the API
docker-compose stop c2-server

# API keeps working normally
curl http://localhost:5000/api/cameras \
  -H "X-Auth-Token: <token>"
```

## Pedagogical Benefits

### 1. Realistic Forensic Analysis

Students must:
- Identify "suspicious" HTTP traffic among normal browsing
- Detect persistent SSE connections (`Accept: text/event-stream`)
- Find custom headers (`X-Diag-Token`, `X-Device-ID`)
- Correlate periodic heartbeats with C2 beaconing

### 2. Traffic Analysis

```bash
# Capture C2 traffic
tcpdump -i any -w c2_traffic.pcap port 4999

# Analysis with tshark
tshark -r c2_traffic.pcap -Y "http"

# Filter suspicious headers
tshark -r c2_traffic.pcap -T fields \
  -e http.request.header \
  -Y "http.header contains 'X-Diag'"
```

### 3. Beaconing Detection

Pattern to detect:
- SSE connections lasting minutes/hours
- Heartbeats every ~30 seconds
- Periodic HTTP POST responses
- Constant headers (`X-Device-ID`)

## Troubleshooting

### C2 not responding

```bash
# Check logs
docker-compose logs -f c2-server

# Manual health check
curl -v http://localhost:4999/health

# Check MongoDB
docker-compose exec mongo mongosh -u admin -p supersecret \
  --eval "db.adminCommand('ping')"
```

### Device not connecting

```bash
# Manual SSE test
curl -N http://localhost:4999/stream \
  -H "X-Device-ID: test" \
  -H "X-Diag-Token: 000007" \
  -H "X-Device-Model: Test"

# Check Docker network
docker network inspect owlcam_c2_net
```

### Panel not showing sessions

```bash
# Check authentication
curl -X POST http://localhost:4999/panel/auth \
  -H "Content-Type: application/json" \
  -d '{"password": "letstechin"}'
```

## References

- Full documentation: `docs/VulnZoo-Documentation/C2-HTTP-SSE-Migration.md`
- C2 Server README: `cloud_api/owlcam/c2_server/README.md`

---

**Note**: This architecture is intentionally vulnerable for educational purposes. Do not use in production.
