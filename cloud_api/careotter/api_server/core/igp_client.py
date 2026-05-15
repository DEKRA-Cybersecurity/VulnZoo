"""
igp_client.py — IGP v4 protocol client (IoT Gateway Protocol)

The CareOtter device exposes a binary management service on port 9999.
This module implements the protocol transport layer:

    Header (8 bytes, Big Endian):
    ┌─────────────────┬──────┬────────┬──────────┐
    │  Magic (4)      │ Cmd  │ Status │  Len (2) │
    │  0x43415245     │ (1)  │  (1)   │          │
    │    "CARE"       │      │ 0x00   │ payload  │
    └─────────────────┴──────┴────────┴──────────┘

Each command opens and closes an independent TCP connection. The server
closes the connection after sending the response, so the client reads
until EOF is received (there is no length in the response header).

SECURITY NOTE: the server keeps a global `authenticated` flag that
persists across connections — a successful authentication on any
previous connection enables protected commands for all subsequent
connections until the process is restarted.
"""

import socket
import struct
from config import Config

# Protocol magic number: "CARE" in ASCII
MAGIC            = 0x43415245
IGP_HEADER_FMT   = '>IBBH'   # big-endian: uint32 + uint8 + uint8 + uint16
IGP_HEADER_SIZE  = 8


class IGPError(Exception):
    """Communication error with the CareOtter service (port 9999)."""
    pass


class IGPClient:
    """
    Low-level client for the IGP v4 protocol.

    Each method opens a TCP connection, sends the command, and returns
    the response as raw bytes. The caller is responsible for decoding it.
    """

    def __init__(self, host: str = None, port: int = None, timeout: int = None):
        self.host    = host    or Config.DEVICE_IP
        self.port    = port    or Config.IGP_PORT
        self.timeout = timeout or Config.IGP_TIMEOUT

    def _build_header(self, cmd: int, payload_len: int) -> bytes:
        """
        Builds the 8-byte IGP header.
        Format: [Magic(4)|Cmd(1)|Status(1)|Len(2)] in big-endian.
        """
        return struct.pack(IGP_HEADER_FMT, MAGIC, cmd, 0x00, payload_len)

    def send_command(self, cmd: int, payload: bytes = None) -> bytes:
        """
        Sends an IGP command to the device and returns the raw response.

        The server closes the connection after responding, so the client reads
        until an empty chunk (EOF) is received. There is no length framing
        in the response — the closed connection is the delimiter.
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
                f"Timeout ({self.timeout}s) connecting to {self.host}:{self.port}. "
                f"Possible causes: (1) Docker bridge mode has no route to the WiFi subnet — "
                f"try network_mode: host. (2) OpenWRT firewall blocks port 9999 on WAN. "
                f"(3) careservice is not running. Use /api/device/ping for diagnostics."
            )
        except ConnectionRefusedError:
            raise IGPError(
                f"Connection refused — careservice is not responding on "
                f"{self.host}:{self.port}"
            )
        except OSError as e:
            raise IGPError(f"Network error: {e}")

    # ── Mapped commands ───────────────────────────────────────────────────

    def sys_info(self) -> bytes:
        """
        0x01 SYS_INFO — public system information.
        Response: 'v:<kernel>|m:<arch>'  (no authentication)
        """
        return self.send_command(0x01)

    def authenticate(self, token: str) -> bytes:
        """
        0x02 AUTHENTICATE — admin token login.
        Response: 'AUTH_SUCCESS' or 'AUTH_FAIL'
        """
        return self.send_command(0x02, token.encode('utf-8'))

    def get_network(self) -> bytes:
        """
        0x03 GET_NETWORK — active network configuration.
        Response: contents of /etc/config/wireless (requires auth).
        """
        return self.send_command(0x03)

    def set_prefs(self, tlv_payload: bytes) -> bytes:
        """
        0x04 SET_PREFS — app preferences in TLV format.
        Types: 0xAA=theme, 0xAB=language, 0xAC=display mode (requires auth).
        """
        return self.send_command(0x04, tlv_payload)

    def verify_status(self, module_name: str) -> bytes:
        """
        0x05 VERIFY_STATUS — named subsystem diagnostics.
        Modules: 'CareOtter', 'BLE', 'Sensor', 'Network' (no auth).
        """
        return self.send_command(0x05, module_name.encode('utf-8'))

    def set_wifi(self, ssid: str, psk: str) -> bytes:
        """
        0x06 SET_WIFI — configures the WiFi SSID and password via UCI.
        Payload: 'SSID|PSK' (requires auth).
        Response: 'WIFI_UPDATED' or 'WIFI_ERR' / 'ERR_PSK_SHORT' / 'ERR_FORMAT'.
        """
        payload = f"{ssid}|{psk}".encode('utf-8')
        return self.send_command(0x06, payload)

    def get_vitals(self) -> bytes:
        """
        0x07 GET_VITALS — current BPM/SpO2 from the sensor service (no auth).
        The device proxies the sensor HTTP response at :8081/vitals.
        """
        return self.send_command(0x07)

    def set_threshold(self, tlv_payload: bytes) -> bytes:
        """
        0x08 SET_THRESHOLD — clinical alert thresholds in TLV format.
        Types: 0xBB=BPM(min+max, 4 bytes), 0xCC=SpO2_min(1 byte) (requires auth).
        """
        return self.send_command(0x08, tlv_payload)

    def reboot_service(self, service_name: str) -> bytes:
        """
        0x09 REBOOT_SERVICE — restarts a device init.d service.
        Payload: service name e.g. 'medical-sensor' (requires auth).
        """
        return self.send_command(0x09, service_name.encode('utf-8'))

    def get_log(self) -> bytes:
        """
        0x0A GET_LOG — last 512 bytes of the service log (requires auth).
        """
        return self.send_command(0x0A)

    def deauthenticate(self) -> bytes:
        """
        0x0D DEAUTHENTICATE — resets authenticated=0 in the careservice process.

        It should be called after each protected operation to minimize the
        window in which the global authenticated=1 state can be exploited by
        external TCP clients connecting directly to port 9999.

        LIMITATION: it does not completely eliminate the risk window — there
        is an interval between the protected command connection and this
        deauth connection during which an external attacker could inject commands.
        """
        return self.send_command(0x0D)
