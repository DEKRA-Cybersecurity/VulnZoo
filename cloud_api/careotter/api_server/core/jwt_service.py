"""
jwt_service.py — JWT token management for CareOtter operators

Emits session tokens after a successful authentication against the device.
The token is used in the protected API endpoints.

INTENTIONAL VULNERABILITY: weak default JWT secret ('careotter_jwt_2026').
In a real environment this value would come from a secrets manager, not from a
hardcoded default in a .env file. The error messages are also too descriptive,
revealing whether the token is expired vs. has an incorrect signature.
"""

import jwt
from datetime import datetime, timedelta, timezone
from config import Config


class JWTService:

    @staticmethod
    def generate_token(username: str, role: str = 'user') -> str:
        """
        Generates an HS256 JWT with configurable expiration.
        The 'sub' contains the authenticated operator's username.
        The 'role' is included in the payload for later validation.
        """
        payload = {
            'sub':  username,
            'role': role,
            'iat':  datetime.now(timezone.utc),
            'exp':  datetime.now(timezone.utc) + timedelta(
                hours=Config.JWT_EXPIRATION_HOURS
            ),
        }
        token = jwt.encode(
            payload,
            Config.JWT_SECRET,
            algorithm=Config.JWT_ALGORITHM
        )
        # PyJWT 1.x returns bytes; 2.x returns str.
        # Force str so jsonify does not serialize it as an array of integers.
        if isinstance(token, bytes):
            token = token.decode('utf-8')
        return token

    @staticmethod
    def decode_token(token: str) -> dict:
        """
        Decodes and validates the JWT.

        Returns:
            {'success': True,  'payload': {...}}
            {'success': False, 'error': '...', 'hint': '...'}

        VULNERABILITY: the 'hint' field distinguishes between an expired token
        and an incorrect signature — information useful to an attacker trying
        to forge or extend tokens.
        """
        try:
            payload = jwt.decode(
                token,
                Config.JWT_SECRET,
                algorithms=[Config.JWT_ALGORITHM]
            )
            return {'success': True, 'payload': payload}

        except jwt.ExpiredSignatureError:
            return {
                'success': False,
                'error':   'Token expired',
                'hint':    'Valid structure, correct signature, but the token has expired'
            }
        except jwt.InvalidSignatureError:
            return {
                'success': False,
                'error':   'Invalid signature',
                'hint':    'Payload is decodable but the signature does not match the secret'
            }
        except jwt.DecodeError:
            return {
                'success': False,
                'error':   'Malformed token',
                'hint':    'The base64 structure cannot be decoded'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
