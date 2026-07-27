from core.decorators import session_required_html, admin_required, tech_session_required_html
from core.auth_utils import validate_jwt_token, contains_mongo_operators
from core.c2_diag import c2_server
import requests
import hmac
import hashlib
import os
import time
import traceback
from datetime import datetime, timedelta, timezone
import uuid
import json

import requests

import cv2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import subprocess
from flask import Flask, jsonify, request, Response, render_template, redirect, url_for, abort, make_response, send_from_directory, render_template_string
from bson.objectid import ObjectId
from pymongo import MongoClient
from pymongo.errors import OperationFailure
from werkzeug.utils import secure_filename
from services.jwt_service import JWTService
from functools import wraps
from bs4 import BeautifulSoup

from config import Config
from config import mongo_client
from repositories.user_repository import UserRepository
from services.user_service import UserService
from repositories.snapshot_repository import SnapshotRepository
from services.snapshot_service import SnapshotService
from services.db_status_service import DbStatusService


app = Flask(__name__)
vuln = int(os.getenv('VULNERABLE', 1))

app.config['C2_PANEL_PASSWORD'] = Config.C2_PANEL_PASSWORD

user_repo = (UserRepository(mongo_client))
user_service = UserService(user_repo)
snapshot_repository = SnapshotRepository(mongo_client)
snapshot_service = SnapshotService(snapshot_repository, mongo_client, Config.CAMERA_URLS.get("1"))
db_status_service = DbStatusService(mongo_client)

UPLOAD_FOLDER = '/vulnzoo/firmware'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)



# Welcome endpoint
@app.route('/')
def welcome():
    if (os.getenv('VULNERABLE') == '1'):
        return jsonify({"message": "Welcome to the Vulnerable VulnZoo API!", "hint": "Starting point would be /login endpoint"})
    else:
        return jsonify({"message": "Welcome to the Secure VulnZoo API!", "hint": "Starting point would be /login endpoint"})


@app.route('/api/health')
def health_check():
    return jsonify({"status": "healthy"})


@app.errorhandler(Exception)
def handle_exception(e):
    """Manejo global de errores"""
    code = 500
    if isinstance(e, OperationFailure):
        code = 401
    elif hasattr(e, 'code'):
        code = e.code
    return jsonify(error=str(e), code=code), code
    

@app.route('/api/debug/decode_token', methods=['POST'])
def debug_decode_token():
    """
    VULNERABILITY: Debug endpoint que decodifica tokens sin verificar firma
    Permite a atacantes ver el contenido de cualquier token
    """
    token = request.headers.get('X-Auth-Token') or request.form.get('token')
    
    if not token:
        return jsonify({'error': 'Token required'}), 400
    
    # VULNERABILITY: Decodes token without verifying signature, exposing payload data to attackers
    result = JWTService.decode_without_verification(token)
    
    if result['success']:
        return jsonify({
            'decoded': True,
            'payload': result['payload'],
            'note': 'Token decoded without signature verification (debug mode)'
        }), 200
    else:
        return jsonify({
            'decoded': False,
            'error': result['error']
        }), 400



# VULNERABILITY: API status endpoint with sensitive information
# VULNERABILITY: Exposes PUT option so attackers can modify server files (related with file upload - firmware - Lack of )
@app.route('/api/status', methods=['GET', 'OPTIONS', 'PUT'])
def api_status():
    if vuln == 1:
        if request.method == 'OPTIONS':
            return jsonify({"allowed_methods": ["GET", "PUT", "OPTIONS"]}), 200
        else:
            feature = request.args.get('feature')
            if not feature:
                return jsonify({"available_features": list(Config.FEATURES.keys()),
                                "usage": "/api/status?feature=<feature_name>"}), 400
            # Vulnerability: Exposing file paths in response
            file_path = Config.FEATURES.get(feature, feature) # If feature not found, use as is
            safe_path = file_path.replace("../", '')
            path = os.path.join(os.getcwd(), safe_path)
            if os.path.exists(path):
                with open(path, 'r') as f:
                    return jsonify({"feature": feature, "content": f.read()}), 200
            elif not os.path.exists(path) and request.method == 'PUT':
                try:
                    # Vulnerability: Allowing file modification via PUT
                    new_content = request.data
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, 'wb') as f:
                        f.write(new_content)
                    return jsonify({"feature": feature, "status": "file updated"}), 200
                except Exception as e:
                  return jsonify({"error": str(e)}), 500
            abort(404)
    else:
        """Secure version: only basic status info, no file exposure"""
        status_info = {
            "api_status": "operational",
            "version": "1.0.0",
            "database_status": db_status_service.get_database_status(),
            "timestamp": datetime.now().isoformat()
        }
        return jsonify(status_info), 200


##############################################################################
############################# SUPPORT REQUESTS ###############################
##############################################################################


@app.route('/support')
@session_required_html
def support_template():
    return render_template('support.html')


@app.route('/api/support/submit', methods=['POST'])
def submit_support_request():
    """Handle support requests and send automated admin response"""
    token = request.headers.get('X-Auth-Token')
    result = validate_jwt_token(token)
    
    if result.get('status') != 200:
        return jsonify({'error': 'Authentication required'}), 401
    
    user_id = result.get('user_id')
    
    issue_type = request.form.get('issue_type')
    message = request.form.get('message')
    
    # Validación básica
    if not all([issue_type, message]):
        return jsonify({
            'error': 'validation_failed',
            'message': 'All fields are required'
        }), 400
    
    # Si solicita acceso a cámaras y ya es viewer
    user = mongo_client.vulnzoo_vuln.users.find_one({'_id': ObjectId(user_id)})
    if issue_type == 'camera_access' and user.get('role') == 'viewer':
        return jsonify({
            'error': 'already_has_access',
            'message': 'User already has camera access (viewer role)'
        }), 400
    username = user.get('username')
    # Guardar la solicitud
    ticket_id = int(time.time())
    support_data = {
        'issue_type': issue_type,
        'user_id': user_id,
        'username': username,
        'message': message,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'ticket_id': ticket_id
    }
    mongo_client.vulnzoo_vuln.support_requests.insert_one(support_data)
    
    # --- RESPUESTA AUTOMÁTICA DEL ADMINISTRADOR ---
    admin_user = mongo_client.vulnzoo_vuln.users.find_one({'role': 'admin'})
    if not admin_user:
        return jsonify({'error': 'Admin user not found in system'}), 500
    
    admin_id = str(admin_user['_id'])
    admin_username = admin_user.get('username', 'admin')
    
    # VULNERABILITY: Enviar mensaje al usuario con sender_id expuesto
    admin_message = {
        "sender_id": admin_id,  # VULNERABILITY: Admin ID expuesto
        "sender_username": admin_username,
        "recipient_id": user_id,
        "recipient_username": username,
        "subject": f"Support Request Received - Ticket #{ticket_id}",
        "message": Config.SUPPORT_RESPONSE_TEMPLATE.format(
            username=username,
            issue_type=issue_type,
            ticket_id=ticket_id,
            camera_access_note="For camera access requests, the administrator will review and upgrade your account if approved." if issue_type == "camera_access" else "",
            admin_username=admin_username
        ),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    mongo_client.vulnzoo_vuln.messages.insert_one(admin_message)

    if mongo_client.vulnzoo_vuln.sessions.count_documents({'user_id': admin_id}) == 0:
        # Crear sesión activa para el admin si no existe
        session_data = {
            'user_id': admin_id,
            'username': admin_username,
            'role': 'admin',
            'status': 'active',
            'ip': '175.200.13.78',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
            'timestamp': datetime.now().isoformat()
        }
        mongo_client.vulnzoo_vuln.sessions.insert_one(session_data)

    return jsonify({'message': Config.SUPPORT_SUCCESS_RESPONSE_TEMPLATE.format(
        issue_type=issue_type,
        ticket_id=ticket_id)
    }), 200


@app.route('/support/list', methods=['GET'])
def list_support_requests():
    """
    Lista las solicitudes de soporte del usuario autenticado
    Requiere JWT token válido en header X-Auth-Token
    """
    token = request.headers.get('X-Auth-Token')
    result = validate_jwt_token(token)
    
    if result.get('status') != 200:
        return jsonify({'error': 'Authentication required'}), 401
    
    user_id = result.get('user_id')
    username = result.get('username')
    
    # Obtener parámetros de paginación
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    skip = (page - 1) * per_page
    
    # Opcional: filtrar por tipo de issue
    issue_type = request.args.get('issue_type')
    
    # Construir query
    query = {'user_id': user_id}
    if issue_type:
        query['issue_type'] = issue_type
    
    # Obtener solicitudes de soporte del usuario
    support_requests = list(
        mongo_client.vulnzoo_vuln.support_requests.find(query)
        .sort('timestamp', -1)  # Más recientes primero
        .skip(skip)
        .limit(per_page)
    )
    
    # Contar total de solicitudes
    total = mongo_client.vulnzoo_vuln.support_requests.count_documents(query)
    
    # Serializar ObjectId
    for req in support_requests:
        req['_id'] = str(req['_id'])
    
    return jsonify({
        'support_requests': support_requests,
        'total': total,
        'page': page,
        'per_page': per_page,
        'username': username
    }), 200

##############################################################################
############################## MESSAGES SYSTEM ###############################
###############################################################################

@app.route('/messages', methods=['GET'])
@session_required_html
def messages_page():
    return render_template('messages.html')


@app.route('/api/messages', methods=['GET', 'POST'])
def api_messages():
    """API endpoint for messages - requires JWT authentication"""
    token = request.headers.get('X-Auth-Token')
    result = validate_jwt_token(token)
    
    if result.get('status') != 200:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id = result.get('user_id')
    username = result.get('username')
    
    if request.method == 'GET':
        # Paginación
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        skip = (page - 1) * per_page
        
        
        # Obtener mensajes donde el usuario es destinatario
        messages = list(mongo_client.vulnzoo_vuln.messages.find(
            {'recipient_id': ObjectId(user_id)}
        ).sort('timestamp', -1).skip(skip).limit(per_page))
        
        # Contar total de mensajes que coinciden con el filtro
        total = mongo_client.vulnzoo_vuln.messages.count_documents({'recipient_id': ObjectId(user_id)})        

        result_messages = []
        for msg in messages:
            # VULNERABILITY: Exponer sender_id en la respuesta
            sender_id = msg.get("sender_id", "unknown")
            recipient_id = msg.get("recipient_id", "unknown")
            
            # Convert ObjectId to string if necessary
            if isinstance(sender_id, ObjectId):
                sender_id = str(sender_id)
            if isinstance(recipient_id, ObjectId):
                recipient_id = str(recipient_id)
            
            result_messages.append({
                "id": str(msg['_id']),
                "sender": msg.get("sender_username"),
                "sender_id": sender_id,  # VULNERABILITY: ID expuesto
                "recipient_id": recipient_id,
                "subject": msg.get("subject", "(no subject)"),
                "body": msg.get("message"),
                "timestamp": msg.get("timestamp"),
            })
        
        return jsonify({
            "messages": result_messages, 
            "total": total,
            "page": page,
            "per_page": per_page
        }), 200
    else:  # POST - enviar mensaje
        data = request.json
        sender_username = data.get('sender')
        recipient_username = data.get('recipient')
        message_body = data.get('message')
        
        if not sender_username or not recipient_username or not message_body:
            return jsonify({'error': 'Sender, recipient and message are required'}), 400
        
        if len(message_body) > 5000:
            return jsonify({'error': 'Message too long (max 5000 characters)'}), 400
        
        subject = data.get('subject', '(no subject)')
        if len(subject) > 200:
            return jsonify({'error': 'Subject too long (max 200 characters)'}), 400

        sender = mongo_client.vulnzoo_vuln.users.find_one({'username': sender_username})
        if not sender:
            return jsonify({'error': 'Sender not found'}), 404

        recipient = mongo_client.vulnzoo_vuln.users.find_one({'username': recipient_username})
        if not recipient:
            return jsonify({'error': 'Recipient not found'}), 404
        
        
        mongo_client.vulnzoo_vuln.messages.insert_one({
            "sender_id": sender['_id'],
            "sender_username": sender_username,
            "recipient_id": recipient['_id'],
            "recipient_username": recipient_username,
            "subject": subject,
            "message": message_body,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
        return jsonify({"status": "ok", "message": "Message sent"}), 201


@app.route('/api/messages/<message_id>', methods=['DELETE'])
def delete_message(message_id):
    """Delete a message"""
    token = request.headers.get('X-Auth-Token')
    result = validate_jwt_token(token)
    
    if result.get('status') != 200:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id = result.get('user_id')
    
    try:
        delete_result = mongo_client.vulnzoo_vuln.messages.delete_one(
            {'_id': ObjectId(message_id), 'recipient_id': ObjectId(user_id)}
        )
        
        if delete_result.deleted_count == 0:
            return jsonify({'error': 'Message not found'}), 404
            
        return jsonify({'status': 'ok', 'message': 'Message deleted'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


###################################################
##### FUTURE FEATURE: UPLOAD UNSECURED FILES  #####
###################################################


@app.route('/support/modify', methods=['GET'])
@session_required_html
def support_modify_template():
    return render_template('support_modify.html')


def process_support_file(support_request):
    """
    Procesa el archivo adjunto de una solicitud de soporte para buscar referencias a imágenes
    y realiza peticiones HTTP a las URLs encontradas (demostración SSRF).
    """
    filename = support_request.get('attached_file_name', '')
    file_data = support_request.get('attached_file_data', '')
    if not filename or not file_data:
        return None

    # Solo procesa si el archivo es HTML
    if not filename.lower().endswith(('.html', '.htm')):
        return None

    try:
        html = base64.b64decode(file_data).decode('utf-8', errors='ignore')
    except Exception as e:
        return [{'error': f'Failed to decode file: {str(e)}'}]

    soup = BeautifulSoup(html, 'html.parser')
    img_tags = soup.find_all('img')
    results = []
    for img in img_tags:
        src = img.get('src')
        if src:
            try:
                resp = requests.get(src, timeout=3)
                results.append({'src': src, 'status': resp.status_code})
            except Exception as e:
                results.append({'src': src, 'error': str(e)})
    return results


@app.route('/api/support/modify', methods=['POST'])
def modify_support_request():
    token = request.headers.get('X-Auth-Token')
    result = validate_jwt_token(token)
    if result.get('status') != 200:
        return jsonify({'error': 'Authentication required'}), 401
    
    ticked_id = request.form.get('ticket_id')
    comment = request.form.get('comment')
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    allowed_types = ['image/jpeg', 'image/png', 'image/jpg', 'application/pdf']
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file.content_type not in allowed_types:
        return jsonify({'error': 'Unsupported file type'}), 400
    
    filename = secure_filename(file.filename)
    file_bytes = file.read()
    file_b64 = base64.b64encode(file_bytes).decode('utf-8')
    
    update_result = mongo_client.vulnzoo_vuln.support_requests.update_one(
        {'ticket_id': int(ticked_id)},
        {'$set': {
            'attached_file_name': filename,
            'attached_file_data': file_b64,
            'comment': comment
        }}
    )

    if update_result.modified_count == 0:
        return jsonify({'error': 'Support request not found or file not updated'}), 404

    support_request = mongo_client.vulnzoo_vuln.support_requests.find_one({'ticket_id': int(ticked_id)})
    processing_results = process_support_file(support_request)
    return jsonify({
        'message': 'File attached successfully to support request',
        'processing_results': processing_results
    }), 200


@app.route('/admin', methods=['GET','POST'])
@session_required_html
def admin_panel():
    if vuln == 1:
        if request.method == 'GET':
            return render_template('admin/admin_access.html')
        token = request.headers.get('X-Auth-Token')
        result = validate_jwt_token(token)
        
        if result.get('status') != 200:
            # Invalid token filtration
            return jsonify({'error': 'Invalid token'}), 401
        
        user_id = result.get('user_id')
        user = mongo_client.vulnzoo_vuln.users.find_one({'_id': ObjectId(user_id)})
        
        if not user or user.get('role') != 'admin':
            resp = make_response(jsonify({'error': 'Forbidden'}), 403)
            resp.set_cookie('admin_session', '', expires=0, path='/', samesite='Lax')
            return resp

        existing_session = mongo_client.vulnzoo_vuln.sessions.find_one({'user_id': user_id})
        if existing_session:
            session_id = str(existing_session['_id'])
        else:
            session_data = {
                'user_id': user_id,
                'username': user.get('username'),
                'role': user.get('role'),
                'status': 'active',
                'ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent'),
                'timestamp': datetime.now().isoformat()
            }
            result = mongo_client.vulnzoo_vuln.sessions.insert_one(session_data)
            session_id = str(result.inserted_id)

        resp = make_response(render_template('admin/admin.html', session_id=session_id))
        resp.set_cookie('admin_session', session_id, max_age=3600, samesite='Lax')
        return resp


# Admin user search endpoint for text-box search
@app.route('/admin/users/search', methods=['GET'])
# admin session omited so search can be done quickly
# @admin_required
def search_users():
    query = request.args.get('query', '')
    users = list(mongo_client.vulnzoo_vuln.users.find(
        {"username": {"$regex": query, "$options": "i"}},
        {"password": 0}
    ).limit(10))
    for user in users:
        user['_id'] = str(user['_id'])
        if 'cameras_access' in user:
            user.pop('cameras_access')  # Hide cameras_access for simplicity
    filtered_users = [user for user in users if query.lower() in user['username'].lower()]
    return jsonify({"users": filtered_users, "total": len(filtered_users)})


# @app.route('/admin/users/<user_id>', methods=['GET'])
# def get_user(user_id):
#     user = mongo_client.vulnzoo_vuln.users.find_one({'_id': ObjectId(user_id)})
#     if not user:
#         return jsonify({'error': 'User not found'}), 404
#     user['_id'] = str(user['_id'])
#     return jsonify(user)

@app.route('/admin/users', methods=['GET'])
@session_required_html
def delete_users_page():
    referer = request.headers.get('Referer', '')
    if '/admin' not in referer:
        return jsonify({'error': 'Access denied: Admins only'}), 403
    return render_template('admin/admin_deleteUsers.html')

@app.route('/admin/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    referer = request.headers.get('Referer', '')
    if '/admin' in referer:
        user = mongo_client.vulnzoo_vuln.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        mongo_client.vulnzoo_vuln.users.delete_one({'_id': ObjectId(user_id)})
        mongo_client.vulnzoo_vuln.cameras.delete_many({'owner': ObjectId(user_id)})
        return jsonify({'message': 'User deleted'})
    elif '/profile' in referer:
        token = request.headers.get('X-Auth-Token')
        result = validate_jwt_token(token)
        if result.get('status') != 200:
            return jsonify({'error': 'Unauthorized'}), 401
        user_id_token = result.get('user_id')
        if user_id_token != user_id:
            return jsonify({'error': 'Forbidden: cannot delete other users'}), 403
        user = mongo_client.vulnzoo_vuln.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        mongo_client.vulnzoo_vuln.users.delete_one({'_id': ObjectId(user_id)})
        mongo_client.vulnzoo_vuln.cameras.delete_many({'owner': ObjectId(user_id)})
        resp = make_response(jsonify({'message': 'User deleted'}))
        return resp
    else:
        return jsonify({'error': 'Access denied: bad referer '}), 403

@app.route('/admin/roles', methods=['GET', 'POST'])
@session_required_html
@admin_required
def list_roles():
    if request.method == 'GET':
        return render_template('admin/admin_roles.html'), 200
    else:
        referer = request.headers.get('Referer', '')
        if '/admin' not in referer:
            return jsonify({'error': 'Access denied: Admins only'}), 403
        
        if request.method == 'GET':
            username = request.args.get('user')
            new_role = request.args.get('role')
        else:
            username = request.form.get('user')
            new_role = request.form.get('role')
        
        if new_role not in ['user', 'viewer', 'admin']:
            return jsonify({'error': 'Invalid role'}), 400

        result = mongo_client.vulnzoo_vuln.users.update_one(
            {'username': username},
            {'$set': {'role': new_role}}
        )
        
        if result.modified_count == 1:
            return jsonify({'message': f'Role updated for {username} to {new_role}'}), 200
        else:
            return jsonify({'error': 'User not found or role unchanged'}), 404


@app.route('/admin/support', methods=['GET'])
@session_required_html
@admin_required
def admin_support_requests():
    requests_list = list(mongo_client.vulnzoo_vuln.support_requests.find().sort('timestamp', -1).limit(100))
    for req in requests_list:
        req['_id'] = str(req['_id'])
    return render_template('admin/admin_support.html', support_requests=requests_list)


def check_cameras_connection(camera_url):
    """
    Comprueba si el endpoint MJPEG HTTP responde y entrega al menos un frame JPEG válido.
    Devuelve True si se recibe un frame, False en caso contrario.
    """
    if not camera_url:
        return False
    try:
        resp = requests.get(camera_url, stream=True, timeout=5)
        if resp.status_code != 200:
            return False
        content_type = resp.headers.get('Content-Type', '')
        if 'multipart/x-mixed-replace' not in content_type:
            return False
        # Buscar el primer frame JPEG en el stream
        for chunk in resp.iter_content(chunk_size=4096):
            if b'\xff\xd8' in chunk:  # JPEG SOI marker
                return True
        return False
    except Exception as e:
        return False


@app.route('/admin/check_connection', methods=['POST'])
def check_cameras_connection_debug():
    camera_url = request.form.get('camera_url')
    if not camera_url:
        return jsonify({'error': 'Camera URL required'}), 400
    result = check_cameras_connection(camera_url)
    if result:
        return jsonify({'success': True, 'message': 'MJPEG stream reachable and frame received.'}), 200
    else:
        return jsonify({'error': 'Camera unreachable or no MJPEG frame received.'}), 503


@app.route('/firmware', methods=['GET'])
def firmware_list():
    """Devuelve la lista de archivos de firmware disponibles si no hay parámetros"""
    """Devuelve el contenido del firmware específico si se proporciona el parámetro 'file' y consta en el JWT que es rol admin"""
    file_param = request.args.get('file')
    if not file_param:
        files = os.listdir(UPLOAD_FOLDER)
        html = "<html><head><title>Index of /firmware</title></head><body>"
        html += "<h1>Index of /firmware</h1><hr><pre>"
        for fname in files:
            html += f'<a href="/firmware?file={fname}">{fname}</a>\n'
        html += "</pre><hr></body></html>"
        return html, 200, {'Content-Type': 'text/html'}
    else:
        signature = request.headers.get('X-Signature')
        
        if not signature:
            token = request.headers.get('X-Auth-Token')
            result = validate_jwt_token(token)
            if result.get('status') != 200:
                return jsonify({'error': 'Authentication failed, redirecting to login', 'login_error': 'Invalid token', 'signature': signature}), 401
        else:
            timestamp = request.headers.get('X-Timestamp')
            device = request.headers.get('X-Device')
            if not timestamp or not device:
                return jsonify({'error': 'Missing signature parameters'}), 400
            data_to_sign = f"{timestamp}{device}"
            expected_signature = hmac.new(Config.FIRMWARE_SECRET.encode(), data_to_sign.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected_signature, signature):
                return jsonify({'error': 'Invalid signature'}), 403
            return send_from_directory(UPLOAD_FOLDER, file_param)

        user_id = result.get('user_id')
        user = mongo_client.vulnzoo_vuln.users.find_one({'_id': ObjectId(user_id)})
        if not user or user.get('role') != 'admin':
            return jsonify({'error': 'Forbidden: Admins only'}), 403

        safe_filename = secure_filename(file_param)
        filepath = os.path.join(UPLOAD_FOLDER, safe_filename)
        if not os.path.exists(filepath):
            return jsonify({'error': 'File not found'}), 404

        with open(filepath, 'r') as f:
            content = f.read()
        return jsonify({"filename": safe_filename, "content": content}), 200


@app.route('/firmware/latest-version', methods=['GET'])
def get_latest_firmware_version():
    # Devuelve el nombre de la última versión de firmware disponible.
    files = sorted(os.listdir(UPLOAD_FOLDER), key=lambda x: os.path.getmtime(os.path.join(UPLOAD_FOLDER, x)), reverse=True)
    if not files:
        return jsonify({"error": "No firmware uploaded"}), 404

    import re
    # Captura solo la versión numérica después de la 'v', admite opcionalmente extensión
    version_pattern = re.compile(r'^firmware-v(\d+\.\d+\.\d+)(?:\..*)?$')

    for fname in files:
        match = version_pattern.match(fname)
        if match:
            return jsonify({"version": match.group(1), "filename": fname}), 200

    # Fallback: busca cualquier 'vX.Y.Z' dentro del nombre
    fallback_pattern = re.compile(r'v(\d+(?:\.\d+)*)')
    match = fallback_pattern.search(files[0])
    if match:
        return jsonify({"version": match.group(1), "filename": files[0]}), 200

    # Si no se encuentra formato de versión, devolver el nombre completo como antes
    return jsonify({"version": files[0], "filename": files[0]}), 200


@app.route('/firmware/latest', methods=['GET'])
def get_latest_firmware():
    # Sirve el último firmware subido
    files = sorted(os.listdir(UPLOAD_FOLDER), key=lambda x: os.path.getmtime(os.path.join(UPLOAD_FOLDER, x)), reverse=True)
    if not files:
        return "No firmware uploaded", 404
    return send_from_directory(UPLOAD_FOLDER, files[0])

@app.route('/firmware/upload', methods=['POST'])
def upload_firmware():
    # Permite subir cualquier archivo como "firmware"
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    return jsonify({"status": "uploaded", "filename": file.filename})


@app.route('/firmware/trigger_update', methods=['POST'])
def trigger_update():
    # Recibe la IP del dispositivo y la URL del firmware a instalar
    device_ip = request.form.get('device_ip')
    firmware_url = request.form.get('firmware_url')
    if not device_ip or not firmware_url:
        return "Missing parameters", 400
    # Ejecuta el comando remoto vía SSH (requiere SSH sin contraseña configurado)
    cmd = f"ssh root@{device_ip} '/etc/init.d/update-firmware {firmware_url}'"
    try:
        subprocess.Popen(cmd, shell=True)
        return jsonify({"status": "update triggered", "device": device_ip, "url": firmware_url})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


def get_user_cameras(user_id):
    """Devuelve la lista de cámaras asociadas al usuario por su ID"""
    user = mongo_client.vulnzoo_vuln.users.find_one({'_id': ObjectId(user_id)})
    if user['role'] == 'admin':
        return list(mongo_client.vulnzoo_vuln.cameras.find())
    if not user or 'cameras_access' not in user:
        return []
    camera_ids = user['cameras_access']
    cameras = list(mongo_client.vulnzoo_vuln.cameras.find({'_id': {'$in': camera_ids}}))
    return cameras


def update_cameras_availability(user_id):
    """Actualiza la disponibilidad solo de las cámaras del usuario"""
    cameras = get_user_cameras(user_id)
    for cam in cameras:
        camera_url = cam.get('camera_url')
        if camera_url:
            is_active = check_cameras_connection(camera_url)
            mongo_client.vulnzoo_vuln.cameras.update_one({'_id': cam['_id']}, {'$set': {'active': is_active}})


@app.route('/cameras')
@session_required_html
def cameras():
    return render_template('cameras.html')


@app.route('/api/cameras', methods=['GET'])
def cameras_api():
    if vuln == 1:
        # 1. Verifica el JWT
        token = request.headers.get('X-Auth-Token')
        result = validate_jwt_token(token)
        if result.get('status') != 200:
            return jsonify({'error': 'Authentication failed, redirecting to login', 'login_error': 'Invalid token'}), 401

        user_id = result.get('user_id')
        user = mongo_client.vulnzoo_vuln.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404

        role = user.get('role')
        username = user.get('username')

        # 2. Actualiza la disponibilidad de las cámaras del usuario
        update_cameras_availability(user_id)

        # 3. Obtiene solo las cámaras que le pertenecen al usuario
        cameras = get_user_cameras(user_id)

        # 4. Serializa los ObjectId y prepara la respuesta
        def serialize_camera(cam):
            cam['id'] = str(cam['_id'])
            cam.pop('_id')
            if 'owner' in cam and isinstance(cam['owner'], ObjectId):
                cam['owner'] = str(cam['owner'])
            return cam

        cameras_serialized = [serialize_camera(cam) for cam in cameras]

        return jsonify({
            "cameras": cameras_serialized,
            "user_role": role,
            "username": username
        }), 200


@app.route('/snapshot', methods=['GET', 'POST'])
@session_required_html
def snapshot():
    if vuln == 1:
        if request.method == 'GET':
            return render_template('snapshot.html')
        
        token = request.headers.get('X-Auth-Token')
        session_id = request.args.get('session') or request.form.get('session')
        camera_id = request.args.get('camera') or request.form.get('camera')
        
        # VULNERABILITY: Admin/viewer bypass con JWT válido
        if token:
            result = validate_jwt_token(token)
            
            if result.get('status') == 200:
                user_id = result.get('user_id')
                user = mongo_client.vulnzoo_vuln.users.find_one({'_id': ObjectId(user_id)})
                role = user.get('role') if user else None
                
                # Admin/viewer bypass
                if role in ['admin', 'viewer']:
                    print(f"{role.capitalize()} access granted to camera {camera_id}", flush=True)
                else:
                    return jsonify({'error': 'Insufficient permissions'}), 403
            else:
                if not session_id:
                    return jsonify(result), result.get('status', 401)
        
        elif session_id:
            # VULNERABILITY: Session bypass (si no hay token pero hay session_id)
            session = mongo_client.vulnzoo_vuln.sessions.find_one({'_id': ObjectId(session_id)})
            if not (session and session.get('status') == 'active'):
                return jsonify({'error': 'Invalid session'}), 403
        else:
            return jsonify({'error': 'Authentication required'}), 401

        camera = mongo_client.vulnzoo_vuln.cameras.find_one({'_id': ObjectId(camera_id), 'active': True})
        if not camera:
            return jsonify({'error': 'Camera not found'}), 404

        camera_url = camera.get('camera_url')
        cap = cv2.VideoCapture(camera_url)

        if not cap.isOpened():
            return jsonify({'error': 'Camera not available'}), 503
        
        success, frame = cap.read()
        cap.release()
        
        if not success:
            return jsonify({'error': 'Failed to capture frame'}), 503
        
        ret, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 80])
        if not ret:
            return jsonify({'error': 'Failed to encode frame'}), 500
        
        return Response(buffer.tobytes(), mimetype='image/jpeg')
    
    else:
        # SECURE MODE
        token = request.cookies.get('auth')
        camera_id = request.args.get('camera_id') or request.form.get('camera_id')
        image_bytes = snapshot_service.get_snapshot(token, Config.CAMERA_URLS.get(camera_id))
        return Response(image_bytes, mimetype='image/jpeg')

@app.route('/register', methods=['GET', 'POST'])
@session_required_html
def register():
    if request.method == 'GET':
        return render_template('register.html')
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if vuln == 1:
        if username and mongo_client.vulnzoo_vuln.users.find_one({'username': username}):
            return jsonify({'error': 'User already exists.'}), 409
        if not username or not password:
            return jsonify({'error': 'Username and password required.'}), 400
        user_data = {
            '_id': ObjectId(),
            'username': username,
            'password': password,
            'role': 'user'
        }
        result = mongo_client.vulnzoo_vuln.users.insert_one(user_data)
        user_id = str(result.inserted_id)
        return jsonify({
            'success': True,
            'message': f'User registered successfully! Your user ID is: {user_id}. Contact support for camera access.',
            'user_id': user_id,
            'username': username,
            'role': 'user'
        }), 201
    else:
        valid, msg = user_service.validate_registration(username, password)
        if not valid:
            return jsonify({'error': msg}), 400
        success, message = user_service.register_user(username, password)
        if not success:
            return jsonify({'error': message}), 409
        return jsonify({'success': True, 'message': message, 'username': username}), 201


@app.route('/sessions', methods=['GET'])
def list_sessions():
    try:
        sessions = list(mongo_client.vulnzoo_vuln.sessions.find({}, {"_id": 0}))
        return jsonify({"sessions": sessions})
    except OperationFailure as e:
        return jsonify({"error": "Authentication failed", "details": str(e)}), 401
    except Exception as e:
        return jsonify({"error": "Connection error", "details": str(e)}), 500


# VULNERABILITY: System logs endpoint that exposes admin activities
@app.route('/api/system/logs', methods=['GET'])
def system_logs():
    """Endpoint that exposes system logs including admin activities"""
    log_type = request.args.get('type', 'all')
    limit = int(request.args.get('limit', 10))
    
    # Get admin user for log entries
    admin_user = mongo_client.vulnzoo_vuln.users.find_one({'role': 'admin'})
    admin_id = str(admin_user['_id']) if admin_user else "unknown"
    admin_username = admin_user['username'] if admin_user else "admin"
    
    # Simulate recent system logs
    fake_logs = [
        {
            "timestamp": (datetime.now() - timedelta(minutes=5)).isoformat(),
            "level": "INFO",
            "message": f"Admin login successful for user_id={admin_id}",
            "module": "auth.login",
            "ip": "192.168.2.1"
        },
        {
            "timestamp": (datetime.now() - timedelta(minutes=15)).isoformat(), 
            "level": "DEBUG",
            "message": f"Session cleanup initiated by admin_id={admin_id}",
            "module": "session.cleanup"
        },
        {
            "timestamp": (datetime.now() - timedelta(minutes=30)).isoformat(),
            "level": "INFO", 
            "message": f"Camera access granted to viewer by admin={admin_username} (id:{admin_id})",
            "module": "camera.access"
        },
        {
            "timestamp": (datetime.now() - timedelta(hours=1)).isoformat(),
            "level": "WARN",
            "message": "Multiple failed login attempts detected",
            "module": "security.monitor"
        },
        {
            "timestamp": (datetime.now() - timedelta(hours=2)).isoformat(),
            "level": "INFO",
            "message": f"Database maintenance completed by user_id={admin_id}",
            "module": "db.maintenance"
        }
    ]
    
    # Filter logs based on type
    if log_type != 'all':
        fake_logs = [log for log in fake_logs if log['level'].lower() == log_type.lower()]
    
    # Limit results
    fake_logs = fake_logs[:limit]
    
    return jsonify({
        "logs": fake_logs,
        "total": len(fake_logs),
        "type_filter": log_type,
        "note": "System logs - last 24 hours",
        "timestamp": datetime.now().isoformat()
    })


# VULNERABILITY: Debug endpoint with weak authentication (only requires admin_id)
@app.route('/api/v1/debug/sessions', methods=['GET'])
def debug_sessions():
    """Debug endpoint that exposes session information with weak admin_id validation"""
    
    # Require admin_id parameter but don't validate if it's actually an admin
    admin_id = request.args.get('admin_id') or request.headers.get('X-Admin-ID')
    
    if not admin_id:
        return jsonify({
            "error": "Admin ID required", 
            "message": "This debug endpoint requires admin_id parameter",
            "example": "/api/v1/debug/sessions?admin_id=YOUR_ADMIN_ID"
        }), 401
    
    # VULNERABILITY: Only check if admin_id exists in users collection, 
    # but don't verify the request is actually from that admin
    try:
        admin_user = mongo_client.vulnzoo_vuln.users.find_one({'_id': ObjectId(admin_id)})
        if not admin_user or admin_user.get('role') != 'admin':
            return jsonify({
                "error": "Invalid admin ID",
                "message": "Provided admin_id does not exist or is not an administrator"
            }), 403
    except:
        return jsonify({
            "error": "Invalid admin ID format",
            "message": "Admin ID must be a valid ObjectId"
        }), 400
        
    try:
        # Get all active sessions with full details including ObjectId
        sessions = list(mongo_client.vulnzoo_vuln.sessions.find({}))
        
        # Convert ObjectId to string for JSON serialization
        for session in sessions:
            session['_id'] = str(session['_id'])
            
        # VULNERABILITY: Exposes sensitive session data with only admin_id validation
        debug_info = {
            "authorized_admin": admin_id,
            "admin_username": admin_user['username'],
            "total_sessions": len(sessions),
            "sessions": sessions,
            "cleanup_status": "executed",
            "timestamp": datetime.now().isoformat(),
            "note": "Active sessions after cleanup - Debug access granted"
        }
        
        return jsonify(debug_info)
        
    except Exception as e:
        return jsonify({"error": "Debug endpoint error", "details": str(e)}), 500


@app.route('/api/v1/userinfo', methods=['GET'])
def get_user_info():
    user_id = request.args.get('id')
    if not user_id:
        return jsonify({'error': 'Missing user ID'}), 400
    try:
        user = mongo_client.vulnzoo_vuln.users.find_one({'_id': ObjectId(user_id)})
    except Exception:
        return jsonify({'error': 'Invalid user ID format'}), 400
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    cameras_access = user.get('cameras_access', [])
    cameras_access_serialized = [str(cam_id) for cam_id in cameras_access]
    # Vulnerability: Expose sensitive user information
    return jsonify({
        'username': user.get('username'),
        'role': user.get('role'),
        'cameras_access': cameras_access_serialized
    }), 200


@app.route('/api/v2/userinfo', methods=['GET'])
def get_user_info_v2():
    """
    Secure version: Only allows access to own user info, or admin can query any user.
    """
    token = request.headers.get('X-Auth-Token')
    result = validate_jwt_token(token)
    if result.get('status') != 200:
        return jsonify({'error': 'Authentication required'}), 401

    requester_id = result.get('user_id')
    requester_role = mongo_client.vulnzoo_vuln.users.find_one({'_id': ObjectId(requester_id)}).get('role')

    user_id = request.args.get('id')
    if not user_id:
        user_id = requester_id  # Default: own info

    if user_id != requester_id and requester_role != 'admin':
        return jsonify({'error': 'Forbidden: Only admins can query other users'}), 403

    user = mongo_client.vulnzoo_vuln.users.find_one({'_id': ObjectId(user_id)})
    if not user:
        return jsonify({'error': 'User not found'}), 404

    cameras_access = user.get('cameras_access', [])
    cameras_access_serialized = [str(cam_id) for cam_id in cameras_access]

    return jsonify({
        'username': user.get('username', ''),
        'role': user.get('role', ''),
        'cameras_access': cameras_access_serialized
    }), 200


@app.route('/api/debug/camera_image/<image_id>', methods=['GET'])
def debug_camera_image(image_id):
    upload = mongo_client.vulnzoo_vuln.camera_uploads.find_one({'_id': ObjectId(image_id)})
    if not upload or 'image_data' not in upload:
        return jsonify({'error': 'Image not found'}), 404
    image_bytes = base64.b64decode(upload['image_data'])
    return Response(image_bytes, mimetype='image/jpeg')


@app.route('/api/v1/login', methods=['GET', 'POST'])
def login_api_deprecated():
    if vuln == 1:
        # VULNERABLE MODE - JWT
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        ip = request.remote_addr
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        user = mongo_client.vulnzoo_vuln.users.find_one({'username': username})
        if not user:
            user = {'_id': None, 'username': username, 'role': 'unknown'}
        result = mongo_client.vulnzoo_vuln.sessions.insert_one({
            'user_id': user['_id'],
            'username': user.get('username'),
            'role': user.get('role'),
            'status': 'active',
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'timestamp': datetime.now().isoformat()
        })
        existing_session = mongo_client.vulnzoo_vuln.sessions.find_one({'_id': result.inserted_id})

        user = mongo_client.vulnzoo_vuln.users.find_one({'username': username})

        if not user or user['password'] != password:
            return jsonify({
                'error': 'Invalid credentials',
                'existing_session': str(existing_session['_id']) if existing_session else None
            }), 401

        # Generate JWT token (VULNERABLE)
        token = JWTService.generate_token(user_id=str(user['_id']))

        return jsonify({
            "auth": token,
            "redirect": "/cameras",
            "role": user.get('role'),
            "username": user.get('username')
        }), 200
    else:
        return jsonify({'error': 'No access in here >:)'}), 404

@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')


@app.route('/api/v2/login', methods=['GET', 'POST'])
def login_api():
    if vuln == 1:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        ip = request.remote_addr
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        existing_session = mongo_client.vulnzoo_vuln.sessions.find_one({'username': username, 'ip': ip, 'user_agent': request.headers.get('User-Agent')})
        if existing_session:
            if existing_session['attempts'] >= 3:
                mongo_client.vulnzoo_vuln.users.update_one(
                    {'username': username},
                    {'$push': {'banned_ips': request.remote_addr}}
                )
                return jsonify({
                    'error': 'Too many failed login attempts. Please try again later.',
                    'existing_session': str(existing_session['_id']) or None
                }), 429
        else:
            user = mongo_client.vulnzoo_vuln.users.find_one({'username': username})
            if not user:
                user = {'_id': None, 'username': username, 'role': 'unknown'}
            result = mongo_client.vulnzoo_vuln.sessions.insert_one({
                'user_id': user['_id'],
                'username': user.get('username'),
                'role': user.get('role'),
                'status': 'active',
                'ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent'),
                'attempts': 0,
                'timestamp': datetime.now().isoformat()
            })
            existing_session = mongo_client.vulnzoo_vuln.sessions.find_one({'_id': result.inserted_id})

        user = mongo_client.vulnzoo_vuln.users.find_one({'username': username})

        if not user or user['password'] != password:
            existing_session['attempts'] += 1
            mongo_client.vulnzoo_vuln.sessions.update_one(
                {'_id': existing_session['_id']},
                {'$set': {'attempts': existing_session['attempts']}}
            )
            return jsonify({
                'error': 'Invalid credentials',
                'existing_session': str(existing_session['_id']) if existing_session else None
            }), 401

        token = JWTService.generate_token(user_id=str(user['_id']))

        return jsonify({
            "auth": token,
            "session_id": str(existing_session['_id']),
            "redirect": "/cameras",
            "role": user.get('role'),
            "username": user.get('username')
        }), 200
    else:
        if request.method == 'GET':
            return render_template('login.html')
        data = request.form if not request.is_json else request.get_json()
        username = data.get('username')
        password = data.get('password')
        result = user_service.login(username, password, request.remote_addr)
        if result['success']:
            return jsonify(result['data']), 200
        else:
            return jsonify({'error': result['error']}), result.get('status', 400)


# Plantear el uso del valor de la sesion para validar el logout en vez de usar el JWT
@app.route('/api/v2/logout', methods=['DELETE'])
def logout_api():
    token = request.headers.get('X-Auth-Token')
    result = validate_jwt_token(token)
    if result.get('status') != 200:
        return jsonify({'error': 'Authentication required'}), 401

    user_id = result.get('user_id')
    mongo_client.vulnzoo_vuln.sessions.delete_many({'user_id': user_id})

    return jsonify({'message': 'Logged out successfully'}), 200


@app.route('/profile', methods=['GET'])
@session_required_html
def profile():
    return render_template('profile.html')


@app.route('/api/profile', methods=['GET'])
def api_profile():
    token = request.headers.get('X-Auth-Token')
    result = validate_jwt_token(token)
    if result.get('status') != 200:
        return jsonify({'error': 'Authentication required'}), 401
    user_id = result.get('user_id')
    user = mongo_client.vulnzoo_vuln.users.find_one({'_id': ObjectId(user_id)})
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({
        'user_id': user.get('_id').__str__(),
        'username': user.get('username'),
        'role': user.get('role'),
        'profile_picture': user.get('profile_picture')
    })


@app.route('/profile/change_password', methods=['POST'])
def change_password():
    token = request.headers.get('X-Auth-Token')
    result = validate_jwt_token(token)
    if result.get('status') != 200:
        return jsonify({'error': 'Authentication required'}), 401

    user_id = result.get('user_id')
    data = request.get_json()
    old_password = data.get('current_password')
    new_password = data.get('new_password')

    user = mongo_client.vulnzoo_vuln.users.find_one({'_id': ObjectId(user_id)})
    if not user or user['password'] != old_password:
        return jsonify({'error': 'Old password is incorrect'}), 403

    mongo_client.vulnzoo_vuln.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'password': new_password}}
    )

    return jsonify({'message': 'Password changed successfully'}), 200


# ==================================================================================
# Endpoint to initialize database with default admin user (out of scope of analysis)
# ==================================================================================

@app.route('/camerasdb/init', methods=['GET'])
def init_cameras_db(): 
    """Endpoint to initialize the database with admin user and cameras data"""
    try:
        admin_user = mongo_client.vulnzoo_vuln.users.find_one({'username': Config.CAMERA_ADMIN_USERNAME})
        if not admin_user:
            admin_data = {
                '_id': ObjectId(os.urandom(12)),
                'username': os.getenv('CAMERA_ADMIN_USERNAME'),
                'password': os.getenv('CAMERA_ADMIN_PASSWORD'),
                'role': 'admin', # Full access and control
                'profile_picture': '/static/img/mrrobot.jpg'
            }

            elliot_data = {
                '_id': ObjectId(os.urandom(12)),
                'username': 'elliot',
                'password': 'elliot123',
                'role': 'viewer', # Some cameras access
                'profile_picture': '/static/img/elliot.jpg'
            }

            john_data = {
                '_id': ObjectId(os.urandom(12)),
                'username': 'john',
                'password': 'doe123',
                'role': 'user', # No cameras access, needs grant
                'profile_picture': '/static/img/default-profile.png'
            }

            mongo_client.vulnzoo_vuln.users.insert_one(admin_data)
            mongo_client.vulnzoo_vuln.users.insert_one(elliot_data)
            mongo_client.vulnzoo_vuln.users.insert_one(john_data)

            # Insert default cameras
            if mongo_client.vulnzoo_vuln.cameras.count_documents({}) == 0:
                cameras = [
                    {
                        "_id": ObjectId(os.urandom(12)),
                        "name": "Main Entrance",
                        "server_ip": Config.SERVER_IP,
                        "camera_url": Config.CAMERA_URLS.get("1"),
                        "active": check_cameras_connection(Config.CAMERA_URLS.get("1")),
                        "owner": mongo_client.vulnzoo_vuln.users.find_one({'username': 'elliot'})['_id'],
                        "firmware-version": Config.LATEST_FIRMWARE_VERSION,
                        "verified": True
                    },
                    {
                        "_id": ObjectId(os.urandom(12)),
                        "name": "Greenhouse",
                        "server_ip": Config.SERVER_IP,
                        "camera_url": Config.CAMERA_URLS.get("2"),
                        "active": check_cameras_connection(Config.CAMERA_URLS.get("2")),
                        "owner": mongo_client.vulnzoo_vuln.users.find_one({'username': 'john'})['_id'],
                        "firmware-version": Config.LATEST_FIRMWARE_VERSION,
                        "verified": True
                    },
                    {
                        "_id": ObjectId(os.urandom(12)),
                        "name": "Parking Lot",
                        "server_ip": Config.SERVER_IP,
                        "camera_url": Config.CAMERA_URLS.get("3"),
                        "active": check_cameras_connection(Config.CAMERA_URLS.get("3")),
                        "owner": mongo_client.vulnzoo_vuln.users.find_one({'username': 'john'})['_id'],
                        "firmware-version": Config.LATEST_FIRMWARE_VERSION,
                        "verified": False
                    } 
                    #{"name": "Warehouse", "url": Config.CAMERA_URLS.get("3"), "active": True}
                ]
                mongo_client.vulnzoo_vuln.cameras.insert_many(cameras)
                mongo_client.vulnzoo_vuln.users.update_one({'username': 'admin'}, {'$set': {'cameras_access': [cameras[0]['_id'], cameras[1]['_id'], cameras[2]['_id']]}})
                mongo_client.vulnzoo_vuln.users.update_one({'username': 'elliot'}, {'$set': {'cameras_access': [cameras[1]['_id']]}})
                mongo_client.vulnzoo_vuln.users.update_one({'username': 'john'}, {'$set': {'cameras_access': [cameras[2]['_id']]}})  
            if mongo_client.vulnzoo_vuln.sessions.count_documents({}) == 0:
                session_data = {
                    'user_id': admin_data['_id'],
                    'username': admin_data['username'],
                    'role': admin_data['role'],
                    'ip': '175.200.13.78',
                    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
                    'timestamp': datetime.now().isoformat()
                }
                mongo_client.vulnzoo_vuln.sessions.insert_one(session_data)
                mongo_client.vulnzoo_vuln.sessions.create_index("timestamp", expireAfterSeconds=3600)  # Sessions expire after 1 hour

                welcome_message = {
                    "sender_id": mongo_client.vulnzoo_vuln.users.find_one({'username': 'admin'})['_id'],  # VULNERABILITY: Admin ID expuesto
                    "sender_username": admin_data['username'],
                    "recipient_id": john_data['_id'],
                    "recipient_username": john_data['username'],
                    "subject": f"Welcome to VulnZoo Security Cameras",
                    "message": Config.WELCOME_SUPPORT_MESSAGE_TEMPLATE.format(
                        username=john_data['username']
                    ),
                    "timestamp": datetime.now(timezone.utc)
                }
                mongo_client.vulnzoo_vuln.messages.insert_one(welcome_message)

                support_message = {
                    "sender_id": mongo_client.vulnzoo_vuln.users.find_one({'username': 'admin'})['_id'],  # VULNERABILITY: Admin ID expuesto
                    "sender_username": admin_data['username'],
                    "recipient_id": john_data['_id'],
                    "recipient_username": john_data['username'],
                    "subject": f"Camera needs behavioural corrections",
                    "message": Config.SUPPORT_TEAM_MESSAGE_TEMPLATE.format(
                        username=john_data['username'],
                        issue_type="unverified camera",
                        ticket_id=str(ObjectId())
                    ),
                    "timestamp": datetime.now(timezone.utc)
                }
                mongo_client.vulnzoo_vuln.messages.insert_one(support_message)
                    
            return jsonify({'message': f"Security camera database created successfully"}), 201
        else:
            return jsonify({'message': f"Security camera database already exists"}), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': f"Error initializing database: {e}"}), 500


@app.route('/camerasdb/delete', methods=['GET'])
def delete_cameras_db():
    """Endpoint to delete the cameras database (for testing purposes)"""
    try:
        mongo_client.drop_database('vulnzoo_vuln')
        return jsonify({'message': 'Security camera database deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': f"Error deleting database: {e}"}), 500

@app.route('/camerasdb/restart', methods=['GET'])
def restart_cameras_db():
    """Endpoint to restart the cameras database (for testing purposes)"""
    try:
        delete_cameras_db()
        init_cameras_db()
        return jsonify({'message': 'Security camera database restarted successfully'}), 200
    except Exception as e:
        return jsonify({'error': f"Error restarting database: {e}"}), 500


if __name__ == '__main__':
    # Selecciona el puerto según el modo
    port = 5000 if vuln == 1 else 5001
    
    # NOTA: El servidor C2 ya no se inicia aquí.
    # Ahora opera como microservicio independiente en el contenedor c2-server.
    # La API Flask solo mantiene endpoints señuelo y redirige al C2 externo.
    
    app.run(host="0.0.0.0", port=port, debug=True, use_reloader=False)
