"""
device_service.py — Operaciones de administración del dispositivo CareOtter

Capa de negocio sobre IGPClient. Traduce respuestas binarias/texto del
protocolo IGP a estructuras Python y construye los payloads TLV necesarios.

Patrón de autenticación IGP:
    Cada operación protegida sigue el ciclo auth → cmd → deauth mediante
    _exec_protected(), que serializa la secuencia completa con un Lock de clase.
    Esto garantiza que ninguna otra petición de la Cloud API interleave sus
    propias conexiones TCP entre las tres de este bloque.

    LIMITACIÓN: el Lock solo serializa peticiones de la Cloud API. Un atacante
    con acceso directo a :9999 puede insertar comandos en la ventana entre las
    conexiones TCP independientes (auth/cmd/deauth). La causa raíz es el estado
    global en careservice.c — la corrección completa requiere vincular
    'authenticated' al descriptor de socket, no al proceso.
"""

import struct
import threading
from core.igp_client import IGPClient, IGPError


class DeviceService:

    # Token de administrador IGP hardcodeado en el dispositivo (vulnerabilidad intencional)
    _ADMIN_TOKEN = "OtterMobile2026"

    # Serializa los bloques auth→cmd→deauth de las peticiones de la Cloud API.
    # Atributo de clase — compartido por todas las instancias.
    _igp_lock = threading.Lock()

    def __init__(self):
        self._igp = IGPClient()

    def _exec_protected(self, cmd_fn, *args, **kwargs):
        """
        Ejecuta cmd_fn dentro del ciclo IGP auth → cmd → deauth.

        Adquiere _igp_lock para que ninguna otra petición de la Cloud API
        interleave sus propias conexiones TCP entre las tres de este bloque.
        La des-autenticación se ejecuta en el bloque finally para garantizar
        que authenticated=0 incluso si cmd_fn lanza una excepción.

        Flujo de conexiones TCP generadas:
            1. IGP 0x02 AUTHENTICATE  → authenticated=1
            2. cmd_fn()               → operación protegida
            3. IGP 0x0D DEAUTHENTICATE → authenticated=0
        """
        with self._igp_lock:
            self._igp.authenticate(self._ADMIN_TOKEN)
            try:
                return cmd_fn(*args, **kwargs)
            finally:
                try:
                    self._igp.deauthenticate()
                except IGPError:
                    pass  # deauth best-effort — no propagar si el dispositivo no responde

    # ── Información del sistema ─────────────────────────────────────────────

    def get_sys_info(self) -> dict:
        """
        IGP 0x01 — Info del sistema sin autenticación.
        Parsea la respuesta 'v:<kernel>|m:<arch>' a un dict estructurado.
        """
        raw  = self._igp.sys_info()
        text = raw.decode('utf-8', errors='replace').strip()
        parts = {}
        for segment in text.split('|'):
            if ':' in segment:
                k, v = segment.split(':', 1)
                parts[k] = v
        return {
            'kernel': parts.get('v', 'unknown'),
            'arch':   parts.get('m', 'unknown'),
            'raw':    text
        }

    # ── Autenticación ───────────────────────────────────────────────────────

    def authenticate(self, token: str) -> dict:
        """
        IGP 0x02 — Login con token de administrador.
        El token se transmite en texto plano al dispositivo.
        """
        raw  = self._igp.authenticate(token)
        text = raw.decode('utf-8', errors='replace').strip()
        return {
            'success':         text == 'AUTH_SUCCESS',
            'device_response': text
        }

    # ── Red ─────────────────────────────────────────────────────────────────

    def get_network_config(self) -> dict:
        """
        IGP 0x03 — Configuración de red activa (requiere auth).

        VULNERABILIDAD: el dispositivo retorna el contenido completo de
        /etc/config/wireless incluyendo la clave PSK en texto plano.
        El campo 'raw' de la respuesta expone estos datos directamente.
        """
        raw  = self._exec_protected(self._igp.get_network)
        text = raw.decode('utf-8', errors='replace').strip()
        return {
            'config': text,
            'raw':    text
        }

    def set_wifi(self, ssid: str, password: str) -> dict:
        """IGP 0x06 — Configura SSID y contraseña WiFi (requiere auth)."""
        raw  = self._exec_protected(self._igp.set_wifi, ssid, password)
        text = raw.decode('utf-8', errors='replace').strip()
        return {
            'result':  text,
            'success': text == 'WIFI_UPDATED'
        }

    # ── Diagnóstico ─────────────────────────────────────────────────────────

    def get_status(self, module: str = 'CareOtter') -> dict:
        """
        IGP 0x05 — Diagnóstico de subsistema (sin auth).
        Módulos válidos en el dispositivo: CareOtter, BLE, Sensor, Network.
        """
        raw  = self._igp.verify_status(module)
        text = raw.decode('utf-8', errors='replace').strip()
        return {
            'module': module,
            'status': text
        }

    # ── Configuración ───────────────────────────────────────────────────────

    def set_preferences(self, tlv_payload: bytes) -> dict:
        """
        IGP 0x04 — Preferencias de la app en formato TLV (requiere auth).
        Tipos: 0xAA=tema, 0xAB=idioma, 0xAC=modo pantalla.
        """
        raw  = self._exec_protected(self._igp.set_prefs, tlv_payload)
        text = raw.decode('utf-8', errors='replace').strip()
        return {'status': text}

    def set_thresholds(self, bpm_min: int, bpm_max: int, spo2_min: int) -> dict:
        """
        IGP 0x08 — Umbrales de alerta clínica (requiere auth).

        Construye el payload TLV:
            [0xBB][0x04][bpm_min_hi][bpm_min_lo][bpm_max_hi][bpm_max_lo]
            [0xCC][0x01][spo2_min]
        Total: 9 bytes
        """
        tlv  = struct.pack('>BBHH', 0xBB, 4, bpm_min, bpm_max)
        tlv += struct.pack('>BBB',  0xCC, 1, spo2_min)
        raw  = self._exec_protected(self._igp.set_threshold, tlv)
        text = raw.decode('utf-8', errors='replace').strip()
        return {
            'result': text,
            'thresholds': {
                'bpm_min':  bpm_min,
                'bpm_max':  bpm_max,
                'spo2_min': spo2_min
            }
        }

    # ── Servicios del sistema ───────────────────────────────────────────────

    def restart_service(self, service_name: str) -> dict:
        """
        IGP 0x09 — Reinicia un servicio init.d del dispositivo (requiere auth).
        Nombres válidos: medical-sensor, careservice, ble-server, etc.
        """
        raw  = self._exec_protected(self._igp.reboot_service, service_name)
        text = raw.decode('utf-8', errors='replace').strip()
        return {
            'result':  text,
            'service': service_name
        }

    def get_log(self) -> dict:
        """IGP 0x0A — Últimos 512 bytes del log del servicio (requiere auth)."""
        raw  = self._exec_protected(self._igp.get_log)
        text = raw.decode('utf-8', errors='replace')
        return {'log': text}
