"""
igp_client.py — Cliente del protocolo IGP v4 (IoT Gateway Protocol)

El dispositivo CareOtter expone un servicio de administración binario en el
puerto 9999. Este módulo implementa la capa de transporte del protocolo:

    Header (8 bytes, Big Endian):
    ┌─────────────────┬──────┬────────┬──────────┐
    │  Magic (4)      │ Cmd  │ Status │  Len (2) │
    │  0x474F4154     │ (1)  │  (1)   │          │
    │    "GOAT"       │      │ 0x00   │ payload  │
    └─────────────────┴──────┴────────┴──────────┘

Cada comando abre y cierra una conexión TCP independiente. El servidor
cierra la conexión tras enviar la respuesta, por lo que el cliente lee
hasta recibir EOF (no hay longitud en el header de respuesta).

NOTA DE SEGURIDAD: el servidor mantiene un flag `authenticated` global
que persiste entre conexiones — una autenticación exitosa en cualquier
conexión previa habilita los comandos protegidos para todas las conexiones
posteriores hasta que el proceso se reinicie.
"""

import socket
import struct
from config import Config

# Magic number del protocolo: "GOAT" en ASCII
MAGIC            = 0x474F4154
IGP_HEADER_FMT   = '>IBBH'   # big-endian: uint32 + uint8 + uint8 + uint16
IGP_HEADER_SIZE  = 8


class IGPError(Exception):
    """Error de comunicación con el servicio CareOtter (puerto 9999)."""
    pass


class IGPClient:
    """
    Cliente de bajo nivel para el protocolo IGP v4.

    Cada método abre una conexión TCP, envía el comando y retorna
    la respuesta en bytes raw. El caller es responsable de decodificar.
    """

    def __init__(self, host: str = None, port: int = None, timeout: int = None):
        self.host    = host    or Config.DEVICE_IP
        self.port    = port    or Config.IGP_PORT
        self.timeout = timeout or Config.IGP_TIMEOUT

    def _build_header(self, cmd: int, payload_len: int) -> bytes:
        """
        Construye el header IGP de 8 bytes.
        Formato: [Magic(4)|Cmd(1)|Status(1)|Len(2)] en big-endian.
        """
        return struct.pack(IGP_HEADER_FMT, MAGIC, cmd, 0x00, payload_len)

    def send_command(self, cmd: int, payload: bytes = None) -> bytes:
        """
        Envía un comando IGP al dispositivo y retorna la respuesta raw.

        El servidor cierra la conexión tras responder, por lo que se lee
        hasta recibir un chunk vacío (EOF). No hay framing de longitud
        en la respuesta — la conexión cerrada es el delimitador.
        """
        payload = payload or b''
        header  = self._build_header(cmd, len(payload))

        try:
            with socket.create_connection(
                (self.host, self.port), timeout=self.timeout
            ) as sock:
                sock.sendall(header + payload)

                response = b''
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                return response

        except socket.timeout:
            raise IGPError(
                f"Timeout ({self.timeout}s) conectando a {self.host}:{self.port}"
            )
        except ConnectionRefusedError:
            raise IGPError(
                f"Conexión rechazada — careservice no responde en "
                f"{self.host}:{self.port}"
            )
        except OSError as e:
            raise IGPError(f"Error de red: {e}")

    # ── Comandos mapeados ───────────────────────────────────────────────────

    def sys_info(self) -> bytes:
        """
        0x01 SYS_INFO — información pública del sistema.
        Respuesta: 'v:<kernel>|m:<arch>'  (sin autenticación)
        """
        return self.send_command(0x01)

    def authenticate(self, token: str) -> bytes:
        """
        0x02 AUTHENTICATE — login con token de administrador.
        Respuesta: 'AUTH_SUCCESS' o 'AUTH_FAIL'
        """
        return self.send_command(0x02, token.encode('utf-8'))

    def get_network(self) -> bytes:
        """
        0x03 GET_NETWORK — configuración de red activa.
        Respuesta: contenido de /etc/config/wireless (requiere auth).
        """
        return self.send_command(0x03)

    def set_prefs(self, tlv_payload: bytes) -> bytes:
        """
        0x04 SET_PREFS — preferencias de la app en formato TLV.
        Tipos: 0xAA=tema, 0xAB=idioma, 0xAC=modo pantalla (requiere auth).
        """
        return self.send_command(0x04, tlv_payload)

    def verify_status(self, module_name: str) -> bytes:
        """
        0x05 VERIFY_STATUS — diagnóstico de subsistema nombrado.
        Módulos: 'CareOtter', 'BLE', 'Sensor', 'Network' (sin auth).
        """
        return self.send_command(0x05, module_name.encode('utf-8'))

    def set_wifi(self, ssid: str, psk: str) -> bytes:
        """
        0x06 SET_WIFI — configura SSID y contraseña WiFi via UCI.
        Payload: 'SSID|PSK' (requiere auth).
        Respuesta: 'WIFI_UPDATED' o 'WIFI_ERR' / 'ERR_PSK_SHORT' / 'ERR_FORMAT'.
        """
        payload = f"{ssid}|{psk}".encode('utf-8')
        return self.send_command(0x06, payload)

    def get_vitals(self) -> bytes:
        """
        0x07 GET_VITALS — BPM/SpO2 actuales desde el servicio sensor (sin auth).
        El dispositivo proxea la respuesta HTTP del sensor en :8081/vitals.
        """
        return self.send_command(0x07)

    def set_threshold(self, tlv_payload: bytes) -> bytes:
        """
        0x08 SET_THRESHOLD — umbrales de alerta clínica en formato TLV.
        Tipos: 0xBB=BPM(min+max, 4 bytes), 0xCC=SpO2_min(1 byte) (requiere auth).
        """
        return self.send_command(0x08, tlv_payload)

    def reboot_service(self, service_name: str) -> bytes:
        """
        0x09 REBOOT_SERVICE — reinicia un servicio init.d del dispositivo.
        Payload: nombre del servicio ej. 'medical-sensor' (requiere auth).
        """
        return self.send_command(0x09, service_name.encode('utf-8'))

    def get_log(self) -> bytes:
        """
        0x0A GET_LOG — últimos 512 bytes del log del servicio (requiere auth).
        """
        return self.send_command(0x0A)
