"""
Módulo C2 - Sistema de "Diagnóstico Remoto"
Versión HTTP/SSE - Validación de tokens y proxy al servidor C2 independiente

Este módulo ahora solo proporciona:
- Validación de tokens con algoritmo débil (suma hexadecimal módulo 7)
- Proxy/redirección al servidor C2 separado
- Funciones de utilidad para endpoints señuelo

La infraestructura C2 real (conexiones persistentes, shell interactiva)
se ha movido al contenedor c2-server que opera en puerto 4999.
"""

import requests
import logging
from cloud_api.owlcam.api_server.config import Config

logger = logging.getLogger('diag_sys_c2')


class DiagSysC2:
    """
    Cliente del servidor de diagnóstico C2 externo.
    Ya no mantiene conexiones TCP/WebSocket directas.
    """

    def __init__(self):
        self.c2_server_url = Config.C2_SERVER_URL
        self.panel_password = Config.C2_PANEL_PASSWORD
        logger.info(f"[DIAG] C2 proxy initialized, server: {self.c2_server_url}")

    def validate_token(self, token):
        """
        Validación débil del token - algoritmo vulnerable intencionalmente.
        Suma hexadecimal módulo 7 == 0
        
        Ejemplo de tokens válidos: 000000, 000007, 000016, 000025, ...
        """
        token = token.upper()
        if len(token) != 6:
            return False
        try:
            total = sum(int(c, 16) for c in token)
            return total % 7 == 0
        except ValueError:
            return False

    def proxy_to_c2(self, endpoint, data=None, headers=None, method='POST'):
        """
        Redirige peticiones al servidor C2 independiente.
        Usado por endpoints señuelo para mantener compatibilidad.
        """
        try:
            url = f"{self.c2_server_url}{endpoint}"
            timeout = 5
            
            if method.upper() == 'POST':
                resp = requests.post(url, json=data, headers=headers, timeout=timeout)
            else:
                resp = requests.get(url, headers=headers, timeout=timeout)
            
            return resp.json(), resp.status_code
        except requests.exceptions.ConnectionError:
            logger.error(f"[DIAG] Cannot connect to C2 server at {self.c2_server_url}")
            return {'error': 'Diagnostic service temporarily unavailable'}, 503
        except Exception as e:
            logger.error(f"[DIAG] Proxy error: {e}")
            return {'error': 'Internal error'}, 500

    def get_c2_health(self):
        """Verifica si el servidor C2 está disponible"""
        try:
            resp = requests.get(f"{self.c2_server_url}/health", timeout=3)
            return resp.status_code == 200
        except:
            return False


# Instancia singleton
c2_server = DiagSysC2()
