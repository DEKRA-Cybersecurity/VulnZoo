from services.jwt_service import JWTService

def validate_jwt_token(token):
    """
    Nueva función de validación JWT (VULNERABLE)
    
    VULNERABILITIES:
    1. Accepts tokens with 'none' algorithm
    2. Weak secret key (brute-forceable)
    3. Detailed error messages aid attackers
    4. No token revocation
    """
    if not token:
        return {
            'error': 'Token required',
            'status': 401,
        }
    
    result = JWTService.decode_token(token)
    
    if result['success']:
        payload = result['payload']
        return {
            'user_id': payload.get('user_id'),
            'status': 200
        }
    else:
        # VULNERABILITY: Detailed error responses
        return {
            'error': result['error'],
            'type': result.get('type'),
            'status': 401
        }
    
def contains_mongo_operators(obj):
    """
    Revisa recursivamente si alguna clave empieza por '$'.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and k.startswith('$'):
                return True
            if contains_mongo_operators(v):
                return True
    elif isinstance(obj, list):
        for item in obj:
            if contains_mongo_operators(item):
                return True
    return False