"""
decorators.py — Authorization decorators for CareOtter API endpoints

Provides @token_required to protect API routes and
@web_login_required / @web_admin_required / @web_patient_required
to protect HTML routes via JWT cookie.
"""

from functools import wraps
from flask import request, jsonify, redirect, url_for, g
from core.jwt_service import JWTService


def _get_token_from_request():
    """Extracts the JWT from the Authorization header or the careotter_token cookie."""
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header.split(' ', 1)[1].strip()
    return request.cookies.get('careotter_token', '')


def _decode_and_validate():
    """Decodes the token and returns the payload if it is valid, or None."""
    token = _get_token_from_request()
    if not token:
        return None
    result = JWTService.decode_token(token)
    return result.get('payload') if result['success'] else None


def token_required(f):
    """
    Decorator that requires a valid JWT in the Authorization header.

    Expected format: Authorization: Bearer <token>

    On error, returns 401 with a 'detail' field that includes
    the JWTService hint — intentionally descriptive by the original
    developer's design to make field debugging easier.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')

        if not auth_header.startswith('Bearer '):
            return jsonify({
                'error':  'Authorization token required',
                'code':   'MISSING_TOKEN',
                'detail': 'Include header: Authorization: Bearer <token>'
            }), 401

        token = auth_header.split(' ', 1)[1].strip()
        result = JWTService.decode_token(token)

        if not result['success']:
            # VULNERABILITY: exposes internal validation error details
            return jsonify({
                'error':  result['error'],
                'code':   'INVALID_TOKEN',
                'detail': result.get('hint', '')
            }), 401

        g.current_user = result['payload']
        return f(*args, **kwargs)

    return decorated


def web_login_required(f):
    """Requires a valid JWT cookie for HTML routes. Redirects to /patient/login if not."""
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = _decode_and_validate()
        if not payload:
            return redirect(url_for('patient_login'))
        return f(*args, **kwargs)
    return decorated


def web_admin_required(f):
    """Requires a valid JWT with the 'admin' role. Redirects to /admin/login if not."""
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = _decode_and_validate()
        if not payload or payload.get('role') != 'admin':
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated


def web_patient_required(f):
    """Requires a valid JWT with the 'patient' or 'admin' role. Redirects to /patient/login if not."""
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = _decode_and_validate()
        if not payload or payload.get('role') not in ('patient', 'admin'):
            return redirect(url_for('patient_login'))
        return f(*args, **kwargs)
    return decorated


def web_caregiver_required(f):
    """Requires a valid JWT with the 'caregiver' role. Redirects to /patient/login if not."""
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = _decode_and_validate()
        if not payload or payload.get('role') != 'caregiver':
            return redirect(url_for('patient_login'))
        return f(*args, **kwargs)
    return decorated


def api_caregiver_required(f):
    """Requires a valid JWT with the 'caregiver' role. Returns JSON 403 for API routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({
                'error': 'Authorization token required',
                'code': 'MISSING_TOKEN',
                'detail': 'Include header: Authorization: Bearer <token>'
            }), 401

        token = auth_header.split(' ', 1)[1].strip()
        result = JWTService.decode_token(token)

        if not result['success']:
            return jsonify({
                'error': result['error'],
                'code': 'INVALID_TOKEN',
                'detail': result.get('hint', '')
            }), 401

        payload = result['payload']
        if payload.get('role') != 'caregiver':
            return jsonify({
                'error': 'Caregiver access required',
                'code': 'FORBIDDEN'
            }), 403

        g.current_user = payload
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Requires a valid JWT with the 'admin' role. Returns JSON 403 for API routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({
                'error': 'Authorization token required',
                'code': 'MISSING_TOKEN',
                'detail': 'Include header: Authorization: Bearer <token>'
            }), 401

        token = auth_header.split(' ', 1)[1].strip()
        result = JWTService.decode_token(token)

        if not result['success']:
            return jsonify({
                'error': result['error'],
                'code': 'INVALID_TOKEN',
                'detail': result.get('hint', '')
            }), 401

        payload = result['payload']
        if payload.get('role') != 'admin':
            return jsonify({
                'error': 'Admin access required',
                'code': 'FORBIDDEN'
            }), 403

        g.current_user = payload
        return f(*args, **kwargs)
    return decorated
