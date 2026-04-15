"""
decorators.py — Decoradores de autorización para endpoints CareOtter API

Proporciona @token_required para proteger rutas que requieren
un operador autenticado mediante JWT.
"""

from functools import wraps
from flask import request, jsonify
from core.jwt_service import JWTService


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
