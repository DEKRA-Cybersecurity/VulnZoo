"""
vitals_service.py — Direct access to the medical sensor service (port 8081)

Queries the pulse oximeter HTTP service on the device without going through
the IGP protocol. This direct path exists because vital data is unprivileged
read-only data that does not require admin authentication.
"""

import requests
from config import Config


class VitalsService:

    # VULNERABILITY: hardcoded sensor token — identical across all deployments
    _SENSOR_API_KEY = "careotter-2024-lab"

    def __init__(self):
        self._timeout = Config.HTTP_TIMEOUT

    def _base(self) -> str:
        """Return the current device base URL. Reads Config.DEVICE_IP dynamically
        so the Cloud API can switch from unprovisioned → WiFi after registration."""
        ip = Config.DEVICE_IP
        if not ip:
            return ''
        return f"http://{ip}:{Config.HTTP_PORT}"

    def _headers(self) -> dict:
        """Return headers including the sensor auth token.
        The sensor_service.py requires X-API-Key on all endpoints except /health."""
        return {'X-API-Key': self._SENSOR_API_KEY}

    def get_current(self) -> dict:
        """
        Gets current BPM and SpO2 from GET /vitals.

        Device response:
            {"bpm": 72, "spo2": 98, "red_raw": 61085,
             "ir_raw": 61036, "timestamp": 1773738799.89, "source": "simulator"}
        """
        base = self._base()
        if not base:
            return {'success': False, 'error': 'Device not registered — no IP configured'}
        try:
            r = requests.get(f"{base}/vitals", headers=self._headers(), timeout=self._timeout)
            r.raise_for_status()
            return {'success': True, 'data': r.json()}
        except requests.Timeout:
            return {'success': False, 'error': 'Timeout connecting to the sensor'}
        except requests.ConnectionError as e:
            return {'success': False, 'error': f'Connection error to the sensor: {e}'}
        except requests.HTTPError as e:
            return {'success': False, 'error': f'HTTP {e.response.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_history(self) -> dict:
        """
        Gets the history of vital summaries from GET /log.
        The device keeps a circular buffer of up to 1440 entries (24h).

        Each entry contains bpm_avg/min/max and spo2_avg/min for an interval.
        """
        base = self._base()
        if not base:
            return {'success': False, 'error': 'Device not registered — no IP configured'}
        try:
            r = requests.get(f"{base}/log", headers=self._headers(), timeout=self._timeout)
            r.raise_for_status()
            return {'success': True, 'history': r.json()}
        except requests.Timeout:
            return {'success': False, 'error': 'Timeout retrieving history'}
        except requests.ConnectionError as e:
            return {'success': False, 'error': f'Connection error: {e}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_alerts(self, since: float = 0.0) -> dict:
        """
        Pull alert events from sensor's GET /alerts/history?since=<ts>.

        The sensor emits one event per healthy↔fired transition (edge-triggered),
        so the cloud collector polls with a watermark and only ingests new rows.
        """
        base = self._base()
        if not base:
            return {'success': False, 'error': 'Device not registered — no IP configured'}
        try:
            r = requests.get(
                f"{base}/alerts/history",
                headers=self._headers(),
                params={'since': since},
                timeout=self._timeout
            )
            r.raise_for_status()
            payload = r.json()
            return {'success': True, 'alerts': payload.get('alerts', [])}
        except requests.Timeout:
            return {'success': False, 'error': 'Timeout retrieving alerts'}
        except requests.ConnectionError as e:
            return {'success': False, 'error': f'Connection error: {e}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_health(self) -> dict:
        """Verifies that the sensor service is running via GET /health."""
        base = self._base()
        if not base:
            return {'success': False, 'error': 'Device not registered — no IP configured'}
        try:
            r = requests.get(f"{base}/health", timeout=self._timeout)
            return {'success': r.status_code == 200, 'status': r.text.strip()}
        except Exception as e:
            return {'success': False, 'error': str(e)}
