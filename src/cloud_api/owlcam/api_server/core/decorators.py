from functools import wraps
import token
from config import mongo_client
from core.auth_utils import validate_jwt_token
from flask import request, redirect, url_for, jsonify
from bson.objectid import ObjectId

def session_required_html(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		session_id = request.cookies.get('session_id')
		if not session_id:
			return redirect(url_for('login'))
		session = mongo_client.vulnzoo_vuln.sessions.find_one({'_id': ObjectId(session_id)})
		if not session:
			return redirect(url_for('login'))
		return f(*args, **kwargs)
	return decorated_function

def admin_required(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		session_id = request.cookies.get('admin_session')
		if not session_id:
			return jsonify({'error': 'Admin session required'}), 401
		session = mongo_client.vulnzoo_vuln.sessions.find_one({'_id': ObjectId(session_id)})
		if not session or session.get('role') != 'admin':
			return jsonify({'error': 'Forbidden'}), 403
		return f(*args, **kwargs)
	return decorated_function

def tech_session_required_html(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		session_id = request.cookies.get('c2_auth')
		if not session_id:
			return redirect(url_for('c2_panel_page'))
		session = mongo_client.vulnzoo_vuln.sessions.find_one({'_id': ObjectId(session_id)})
		if not session or session.get('role') not in ['tech']:
			return jsonify({'error': 'Forbidden'}), 403
		return f(*args, **kwargs)
	return decorated_function
