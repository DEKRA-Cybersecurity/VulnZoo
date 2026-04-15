"""
vitals_service.py — Acceso directo al servicio de sensor médico (puerto 8081)

Consulta el servicio HTTP del oxímetro de pulso en el dispositivo sin pasar
por el protocolo IGP. Esta ruta directa existe porque los datos de vitales
son datos de lectura no privilegiados que no requieren autenticación de admin.
"""

import requests
from config import Config


class VitalsService:

    def __init__(self):
        self._base = f"http://{Config.DEVICE_IP}:{Config.HTTP_PORT}"
        self._timeout = Config.HTTP_TIMEOUT

    def get_current(self) -> dict:
        """
        Obtiene BPM y SpO2 actuales desde GET /vitals.

        Respuesta del dispositivo:
            {"bpm": 72, "spo2": 98, "red_raw": 61085,
             "ir_raw": 61036, "timestamp": 1773738799.89, "source": "simulator"}
        """
        try:
            r = requests.get(f"{self._base}/vitals", timeout=self._timeout)
            r.raise_for_status()
            return {'success': True, 'data': r.json()}
        except requests.Timeout:
            return {'success': False, 'error': 'Timeout conectando al sensor'}
        except requests.ConnectionError as e:
            return {'success': False, 'error': f'Error de conexión al sensor: {e}'}
        except requests.HTTPError as e:
            return {'success': False, 'error': f'HTTP {e.response.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_history(self) -> dict:
        """
        Obtiene el historial de resúmenes de vitales desde GET /log.
        El dispositivo mantiene un buffer circular de hasta 1440 entradas (24h).

        Cada entrada contiene bpm_avg/min/max y spo2_avg/min para un intervalo.
        """
        try:
            r = requests.get(f"{self._base}/log", timeout=self._timeout)
            r.raise_for_status()
            return {'success': True, 'history': r.json()}
        except requests.Timeout:
            return {'success': False, 'error': 'Timeout obteniendo historial'}
        except requests.ConnectionError as e:
            return {'success': False, 'error': f'Error de conexión: {e}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_health(self) -> dict:
        """Verifica que el servicio sensor está activo via GET /health."""
        try:
            r = requests.get(f"{self._base}/health", timeout=self._timeout)
            return {'success': r.status_code == 200, 'status': r.text.strip()}
        except Exception as e:
            return {'success': False, 'error': str(e)}
