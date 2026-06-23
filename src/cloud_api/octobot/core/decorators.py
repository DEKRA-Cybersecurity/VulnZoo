"""
decorators.py — Authorization decorators for OctoBot Cloud API

Provides @login_required for both HTML and API routes, backed by the Flask
session cookie.
"""

from functools import wraps
from flask import request, jsonify, redirect, url_for, session


def login_required(f):
    """Requires a valid operator session. API paths return 401; HTML routes redirect to login."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('user'):
            if request.path.startswith('/api/'):
                return jsonify(error='authentication required'), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper
