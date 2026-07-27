import jwt
from datetime import datetime, timedelta
from config import Config

class JWTService:
    """Servicio JWT con múltiples vulnerabilidades"""
    
    @staticmethod
    def generate_token(user_id):
        """
        VULNERABILITY 1: Weak secret key (brute-forceable)
        VULNERABILITY 2: Predictable secret based on environment
        VULNERABILITY 3: Algorithm confusion (accepts 'none' algorithm)
        """
        payload = {
            'user_id': str(user_id),
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=Config.JWT_EXPIRATION_HOURS)
        }
        
        # VULNERABILITY: Use weak secret
        token = jwt.encode(
            payload,
            Config.JWT_SECRET_KEY,
            algorithm=Config.JWT_ALGORITHM
        )
        return token
    
    @staticmethod
    def decode_token(token, verify=True):
        """
        VULNERABILITY 1: Accepts 'none' algorithm (bypass signature)
        VULNERABILITY 2: Weak error messages reveal token structure
        VULNERABILITY 3: No revocation mechanism (stolen tokens always valid)
        """
        try:
            # VULNERABILITY: Accept multiple algorithms including 'none'
            algorithms = [Config.JWT_ALGORITHM, 'none'] if Config.JWT_ALLOW_NONE_ALGORITHM else [Config.JWT_ALGORITHM]
            
            # VULNERABILITY: honor alg=none (algorithm confusion). PyJWT refuses to
            # decode an alg=none token when a key is supplied, so when the header
            # claims 'none' we decode with signature verification disabled, which
            # accepts any unsigned token as valid.
            if Config.JWT_ALLOW_NONE_ALGORITHM and jwt.get_unverified_header(token).get('alg', '').lower() == 'none':
                payload = jwt.decode(token, options={'verify_signature': False})
            else:
                payload = jwt.decode(
                    token,
                    Config.JWT_SECRET_KEY,
                    algorithms=algorithms)
            return {'success': True, 'payload': payload}
        
        except jwt.ExpiredSignatureError:
            # VULNERABILITY: Detailed error messages
            return {
                'success': False,
                'error': 'Token expired',
                'type': 'expired',
                'hint': 'Token structure valid but expired'
            }
        
        except jwt.InvalidSignatureError:
            # VULNERABILITY: Reveals that token structure is valid
            return {
                'success': False,
                'error': 'Invalid signature',
                'type': 'signature',
                'hint': 'Token payload valid but signature invalid'
            }
        
        except jwt.DecodeError:
            # VULNERABILITY: Reveals token format issues
            return {
                'success': False,
                'error': 'Malformed token',
                'type': 'decode',
                'hint': 'Token format invalid'
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'type': 'unknown'
            }
    
    @staticmethod
    def decode_without_verification(token):
        """
        VULNERABILITY: Permite decodificar tokens sin verificar firma
        Útil para atacantes que quieren ver el contenido
        """
        try:
            payload = jwt.decode(
                token,
                options={'verify_signature': False}
            )
            return {'success': True, 'payload': payload}
        except Exception as e:
            return {'success': False, 'error': str(e)}