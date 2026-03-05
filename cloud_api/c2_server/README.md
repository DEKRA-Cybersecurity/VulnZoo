# C2 Server - VulnZoo

Servidor de Comando y Control (C2) basado en HTTP/SSE (Server-Sent Events) para el laboratorio de ciberseguridad VulnZoo.

## Arquitectura

```
┌─────────────────┐      HTTP/SSE       ┌─────────────────┐
│  Dispositivo    │◄────────────────────►│   C2 Server     │
│  Móvil (App)    │   (puerto 4999)     │  (c2-server)    │
└─────────────────┘                      └────────┬────────┘
                                                  │
                                                  │ HTTP
                                                  │
                       ┌──────────────────────────┘
                       │
              ┌────────▼────────┐
              │    MongoDB      │
              │   (logs, data)  │
              └─────────────────┘
```

### Separación de Infraestructuras

- **vulnzoo-vulnerable**: API Flask en puerto 5000 (endpoints señuelo)
- **c2-server**: Servicio C2 independiente en puerto 4999
- **mongo**: Base de datos compartida

## Protocolo C2

### Canal Descendente (C2 → Dispositivo)

**Endpoint SSE**: `GET /stream`

Headers requeridos:
- `X-Device-ID`: Identificador único del dispositivo
- `X-Diag-Token`: Token de autenticación (6 caracteres hex)
- `X-Device-Model`: Modelo del dispositivo

Eventos SSE:
- `connected`: Confirmación de conexión
- `cmd`: Comando a ejecutar (`{"type": "shell_cmd", "data": "comando"}`)
- `heartbeat`: Keepalive cada 30 segundos

### Canal Ascendente (Dispositivo → C2)

**Endpoint POST**: `POST /response`

```json
{
  "session_id": "c2_DEV001_1234567890",
  "type": "output",
  "data": "resultado del comando",
  "timestamp": 1234567890000
}
```

## Panel de Control

El panel web está disponible en: `http://localhost:4999/panel`

Credenciales:
- Password: `letstechin`

## API Endpoints

### Dispositivo

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/stream` | Conexión SSE persistente |
| POST | `/response` | Enviar respuesta de comando |
| POST | `/metrics` | Enviar métricas del dispositivo |

### Panel de Control

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| POST | `/panel/auth` | Autenticación del panel |
| GET | `/panel` | Interfaz web del panel |
| GET | `/panel/sessions` | Listar sesiones activas |
| POST | `/panel/command` | Enviar comando a dispositivo |
| GET | `/panel/responses/<id>` | Obtener respuestas |
| GET | `/panel/logs` | Logs de auditoría |

### Health Check

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/health` | Estado del servicio |

## Simulador de Dispositivo

```bash
# Dispositivo único
python device_simulator.py --token 000007

# Múltiples dispositivos
python device_simulator.py --multi 5

# Verbose
python device_simulator.py --token 000007 -v
```

## Tokens Válidos

Algoritmo: Suma de dígitos hexadecimales módulo 7 == 0

Ejemplos:
- `000000` (suma=0)
- `000007` (suma=7)
- `000016` (suma=7)
- `ABCDEF` (suma=45, 45%7=3 → inválido)

## Seguridad

Este sistema es **intencionalmente vulnerable** para fines educativos:
- Validación débil de tokens
- Sin autenticación fuerte en dispositivos
- Comunicación sin cifrado (HTTP plano)

**NO usar en producción.**

## Ventajas Pedagógicas

1. **Evasión de firewalls**: Tráfico HTTP estándar, indistinguible de navegación web
2. **NAT Traversal**: Funciona en redes 4G/5G y corporativas con proxy
3. **Análisis forense**: Estudiantes deben identificar patrones de beaconing
4. **Contención**: El C2 puede aislarse sin afectar la API legítima

## Docker

```bash
docker-compose up -d c2-server
```

El contenedor `c2-server`:
- Expone puerto 4999
- Se conecta a MongoDB
- NO tiene acceso a la red de cámaras IoT
