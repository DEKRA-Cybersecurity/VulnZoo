"""
decorators.py — Decoradores de autorización para endpoints CareOtter API

Proporciona @token_required para proteger rutas API y
@web_login_required / @web_admin_required / @web_patient_required
para proteger rutas HTML mediante cookie JWT.
"""

from functools import wraps
from flask import request, jsonify, redirect, url_for
from core.jwt_service import JWTService


def _get_token_from_request():
    """Extrae JWT del header Authorization o de la cookie careotter_token."""
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header.split(' ', 1)[1].strip()
    return request.cookies.get('careotter_token', '')


def _decode_and_validate():
    """Decodifica el token y retorna el payload si es válido, o None."""
    token = _get_token_from_request()
    if not token:
        return None
    result = JWTService.decode_token(token)
    return result.get('payload') if result['success'] else None


def token_required(f):
    """
    Decorador que exige un JWT válido en el header Authorization.

    Formato esperado: Authorization: Bearer <token>

    En caso de error retorna 401 con un campo 'detail' que incluye
    el hint del JWTService — descriptivo por diseño del desarrollador
    original para facilitar el debugging en campo.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')

        if not auth_header.startswith('Bearer '):
            return jsonify({
                'error':  'Token de autorización requerido',
                'code':   'MISSING_TOKEN',
                'detail': 'Incluir header: Authorization: Bearer <token>'
            }), 401

        token = auth_header.split(' ', 1)[1].strip()
        result = JWTService.decode_token(token)

        if not result['success']:
            # VULNERABILIDAD: expone detalles internos del error de validación
            return jsonify({
                'error':  result['error'],
                'code':   'INVALID_TOKEN',
                'detail': result.get('hint', '')
            }), 401

        return f(*args, **kwargs)

    return decorated


def web_login_required(f):
    """Requiere JWT válido en cookie para rutas HTML. Redirige a /patient/login si no."""
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = _decode_and_validate()
        if not payload:
            return redirect(url_for('patient_login'))
        return f(*args, **kwargs)
    return decorated


def web_admin_required(f):
    """Requiere JWT válido con rol 'admin'. Redirige a /admin/login si no."""
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = _decode_and_validate()
        if not payload or payload.get('role') != 'admin':
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated


def web_patient_required(f):
    """Requiere JWT válido con rol 'patient' o 'admin'. Redirige a /patient/login si no."""
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = _decode_and_validate()
        if not payload or payload.get('role') not in ('patient', 'admin'):
            return redirect(url_for('patient_login'))
        return f(*args, **kwargs)
    return decorated
