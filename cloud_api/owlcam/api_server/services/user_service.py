import json
from cryptography.fernet import Fernet
from datetime import datetime, timezone, timedelta
import os
import bcrypt

class UserService:
    def __init__(self, user_repository):
        self.user_repository = user_repository

    def validate_registration(self, username, password):
        if not username or not password:
            return False, "Username and password required"
        if len(username) < 3:
            return False, "Username too short"
        if len(username) > 20:
            return False, "Username too long"
        if len(password) < 6:
            return False, "Password too short"
        if len(password) > 32:
            return False, "Password too long"
        if not username.isalnum():
            return False, "Username must be alphanumeric"
        return True, ""

    def register_user(self, username, password):
        exists = self.user_repository.find_by_username(username)
        if exists:
            return False, "Username already exists"
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user_data = {
            "username": username,
            "password": hashed.decode(),
            "role": "user"
        }
        self.user_repository.insert_user(user_data)
        return True, "User registered successfully"
    
    def verify_password(self, password, hashed):
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    # Need check
    def generate_token(self, user_id, ip_address):

        key = os.getenv('SECRET_KEY', Fernet.generate_key())
        fernet = Fernet(key)

        payload = json.dumps({
            "user_id": str(user_id),
            "ip_address": ip_address,
            # Expiration time is a way to secure the possibility of token reuse
            "exp": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        })
        token = fernet.encrypt(payload.encode()).decode()
        return token

    def login(self, username, password, ip):
        user = self.user_repository.find_by_username(username)
        if not user or not self.verify_password(password, user['password']):
            return {"success": False, "error": "Invalid username or password", "status": 401}
        """In a real app, token contains session info, and the logging mechanism
        is a business-critical component that should be robust and reliable, managed separately."""
        token = self.generate_token(user['_id'], ip)
        return {
            'success': True,
            'data': {
                'auth': token,
                'redirect': '/snapshot.html',
                'session_id': session_id
            }
        }