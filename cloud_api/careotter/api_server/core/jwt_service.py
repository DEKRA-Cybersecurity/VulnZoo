"""
jwt_service.py — Gestión de tokens JWT para operadores CareOtter

Emite tokens de sesión tras una autenticación exitosa contra el dispositivo.
El token se usa en los endpoints protegidos de la API.

VULNERABILIDAD INTENCIONAL: secreto JWT débil por defecto ('careotter_jwt_2026').
En un entorno real este valor vendría de un gestor de secretos, no de un .env
con valor por defecto hardcodeado. Los mensajes de error también son demasiado
descriptivos, revelando si el token está expirado vs. tiene firma incorrecta.
"""

import jwt
from datetime import datetime, timedelta, timezone
from config import Config


class JWTService:

    @staticmethod
    def generate_token(username: str) -> str:
        """
        Genera un JWT HS256 con expiración configurable.
        El 'sub' contiene el nombre de usuario del operador autenticado.
        """
        payload = {
            'sub': username,
            'iat': datetime.now(timezone.utc),
            'exp': datetime.now(timezone.utc) + timedelta(
                hours=Config.JWT_EXPIRATION_HOURS
            ),
        }
        return jwt.encode(
            payload,
            Config.JWT_SECRET,
            algorithm=Config.JWT_ALGORITHM
        )

    @staticmethod
    def decode_token(token: str) -> dict:
        """
        Decodifica y valida el token JWT.

        Retorna:
            {'success': True,  'payload': {...}}
            {'success': False, 'error': '...', 'hint': '...'}

        VULNERABILIDAD: el campo 'hint' diferencia entre token expirado
        y firma incorrecta — información útil para un atacante que intenta
        falsificar o extender tokens.
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
                'error':   'Token expirado',
                'hint':    'Estructura válida, firma correcta, pero el token ha caducado'
            }
        except jwt.InvalidSignatureError:
            return {
                'success': False,
                'error':   'Firma inválida',
                'hint':    'Payload decodificable pero la firma no coincide con el secreto'
            }
        except jwt.DecodeError:
            return {
                'success': False,
                'error':   'Token malformado',
                'hint':    'No se puede decodificar la estructura base64'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
