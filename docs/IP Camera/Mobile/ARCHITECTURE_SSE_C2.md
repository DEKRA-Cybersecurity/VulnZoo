# VulnZoo C2 - Nueva Arquitectura HTTP/SSE

## Resumen de la Transformación

La arquitectura del sistema de Comando y Control (C2) ha sido completamente migrada de TCP/WebSocket nativo a HTTP con Server-Sent Events (SSE). Esta transformación proporciona mayor realismo pedagógico para simulaciones de amenazas persistentes avanzadas (APT).

## Antes vs Después

| Característica | Antigua (TCP/WS) | Nueva (HTTP/SSE) |
|---------------|------------------|------------------|
| **Puertos C2** | 8443 (TCP), 8444 (WS) | 4999 (HTTP) |
| **Protocolo** | TCP nativo + WebSocket | HTTP + Server-Sent Events |
| **Infraestructura** | Embebido en API Flask | Contenedor independiente |
| **Evasión FW** | Baja (puertos no estándar) | Alta (HTTP estándar) |
| **NAT Traversal** | Problemas con 4G/5G | Funciona en cualquier red |
| **Contención** | No posible | C2 aislable sin afectar API |

## Estructura de Archivos

```
cloud_api/
├── docker-compose.yml           # Actualizado: nuevo servicio c2-server
├── api_server/
│   ├── Dockerfile               # Actualizado: sin puertos C2
│   ├── app.py                   # Actualizado: sin inicialización C2
│   ├── config.py                # Actualizado: C2_SERVER_URL
│   └── core/
│       └── c2_diag.py           # Actualizado: solo validación/proxy
│
└── c2_server/                   # NUEVO: Servidor C2 independiente
    ├── Dockerfile
    ├── requirements.txt
    ├── c2_server.py             # Servidor HTTP/SSE principal
    ├── device_simulator.py      # Simulador de dispositivos
    └── README.md

vulnzoo_app/
└── app/src/main/java/...
    ├── util/ApiConfig.kt        # Actualizado: endpoints HTTP/SSE
    └── service/
        ├── DiagSysService.kt    # Versión TCP (legacy)
        └── DiagSysServiceSSE.kt # NUEVO: Versión HTTP/SSE

docs/VulnZoo-Documentation/
├── C2-HTTP-SSE-Migration.md     # Guía de migración completa
└── ...
```

## Inicio Rápido

### 1. Construir e Iniciar Servicios

```bash
cd cloud_api

# Construir todos los contenedores
docker-compose build

# Iniciar infraestructura
docker-compose up -d

# Verificar estado
docker-compose ps
```

### 2. Verificar Funcionamiento

```bash
# Health check C2
curl http://localhost:4999/health

# API Flask funcionando
curl http://localhost:5000/api/health

# Validar token de diagnóstico
curl -X POST http://localhost:5000/api/v2/diag/validate \
  -H "Content-Type: application/json" \
  -d '{"token": "000007", "device_id": "test", "model": "TestDevice"}'
```

### 3. Acceder al Panel C2

Abrir en navegador: `http://localhost:4999/panel`

Credenciales: `letstechin`

### 4. Simular Dispositivo Móvil

```bash
# Terminal 1: Iniciar simulador
cd cloud_api/c2_server
python device_simulator.py --token 000007

# Terminal 2: Simular múltiples dispositivos
python device_simulator.py --multi 5
```

### 5. Flujo Completo C2

1. **Panel C2** (`http://localhost:4999/panel`) → Login → Ver sesiones activas
2. **Simulador** conecta automáticamente vía SSE a `http://localhost:4999/stream`
3. En el panel: Seleccionar dispositivo → Escribir comando → Enter
4. Comando viaja: Panel → C2 Server → SSE → Simulador
5. Respuesta viaja: Simulador → POST → C2 Server → Panel

## API Endpoints C2

### Canal Descendente (SSE)

```http
GET /stream
Headers:
  X-Device-ID: <device_id>
  X-Diag-Token: <token>
  X-Device-Model: <model>
  Accept: text/event-stream
```

### Canal Ascendente (POST)

```http
POST /response
Content-Type: application/json

{
  "session_id": "...",
  "type": "output",
  "data": "resultado",
  "timestamp": 1234567890000
}
```

### Panel de Control

```http
POST /panel/auth              # Login
GET  /panel/sessions          # Listar sesiones
POST /panel/command           # Enviar comando
GET  /panel/responses/<id>    # Obtener respuestas
GET  /panel/logs              # Logs de auditoría
```

## Tokens Válidos

Algoritmo: `sum(hex_digits) % 7 == 0`

Ejemplos válidos:
- `000000` (suma=0)
- `000007` (suma=7)
- `000016` (suma=7)
- `00A00D` (suma=18, 18%7=4 → **inválido**)

Generador en Python:
```python
def generate_valid_token():
    import random
    while True:
        token = ''.join(random.choices('0123456789ABCDEF', k=6))
        total = sum(int(c, 16) for c in token)
        if total % 7 == 0:
            return token
```

## Seguridad y Aislamiento

### Red Docker

```
┌─────────────────────────────────────────────────────────┐
│  RED: c2_net (aislada)                                  │
│  ├── c2-server:4999  ◄── Conexiones C2 externas       │
│  ├── vulnzoo-vulnerable:5000 ──► Proxy al C2          │
│  └── mongo:27017 ◄── Logs y persistencia              │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  RED: cam_net (interna, solo cámaras)                   │
│  ├── camera_admin:9090                                  │
│  ├── camera_elliot:9090                                 │
│  └── vulnzoo-vulnerable:5000                            │
│  NOTA: c2-server NO tiene acceso a esta red             │
└─────────────────────────────────────────────────────────┘
```

### Contención

```bash
# Detener C2 sin afectar API
docker-compose stop c2-server

# API sigue funcionando normalmente
curl http://localhost:5000/api/cameras \
  -H "X-Auth-Token: <token>"
```

## Ventajas Pedagógicas

### 1. Análisis Forense Realista

Los estudiantes deben:
- Identificar tráfico HTTP "sospechoso" entre navegación normal
- Detectar conexiones SSE persistentes (`Accept: text/event-stream`)
- Encontrar headers personalizados (`X-Diag-Token`, `X-Device-ID`)
- Correlacionar heartbeats periódicos con beaconing C2

### 2. Análisis de Tráfico

```bash
# Capturar tráfico C2
tcpdump -i any -w c2_traffic.pcap port 4999

# Análisis con tshark
tshark -r c2_traffic.pcap -Y "http"

# Filtrar headers sospechosos
tshark -r c2_traffic.pcap -T fields \
  -e http.request.header \
  -Y "http.header contains 'X-Diag'"
```

### 3. Detección de Beaconing

Patrón a detectar:
- Conexiones SSE que duran minutos/horas
- Heartbeats cada ~30 segundos
- Respuestas HTTP POST periódicas
- Headers constantes (`X-Device-ID`)

## Troubleshooting

### C2 no responde

```bash
# Verificar logs
docker-compose logs -f c2-server

# Health check manual
curl -v http://localhost:4999/health

# Verificar MongoDB
docker-compose exec mongo mongosh -u admin -p supersecret \
  --eval "db.adminCommand('ping')"
```

### Dispositivo no conecta

```bash
# Test SSE manual
curl -N http://localhost:4999/stream \
  -H "X-Device-ID: test" \
  -H "X-Diag-Token: 000007" \
  -H "X-Device-Model: Test"

# Verificar red Docker
docker network inspect cloud_api_c2_net
```

### Panel no muestra sesiones

```bash
# Verificar autenticación
curl -X POST http://localhost:4999/panel/auth \
  -H "Content-Type: application/json" \
  -d '{"password": "letstechin"}'
```

## Referencias

- Documentación completa: `docs/VulnZoo-Documentation/C2-HTTP-SSE-Migration.md`
- README C2 Server: `cloud_api/c2_server/README.md`

---

**Nota**: Esta arquitectura es intencionalmente vulnerable para fines educativos. No usar en producción.
