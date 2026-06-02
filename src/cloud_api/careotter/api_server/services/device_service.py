"""
device_service.py — CareOtter device administration operations

Business layer on top of IGPClient. Translates the IGP protocol's binary/text
responses into Python structures and builds the required TLV payloads.

IGP authentication pattern:
    Each protected operation follows the auth → cmd → deauth cycle via
    _exec_protected(), which serializes the full sequence with a class Lock.
    This ensures that no other Cloud API request can interleave its own TCP
    connections between the three calls in this block.

    LIMITATION: the Lock only serializes Cloud API requests. An attacker with
    direct access to :9999 can inject commands in the window between the
    independent TCP connections (auth/cmd/deauth). The root cause is the global
    state in careservice.c — the full fix requires binding 'authenticated' to
    the socket descriptor, not to the process.
"""

import struct
import threading
from config import Config
from core.igp_client import IGPClient, IGPError, MAGIC, IGP_HEADER_FMT


class DeviceService:

    # Hardcoded IGP admin token on the device (intentional vulnerability)
    _ADMIN_TOKEN = "OtterMobile2026"

    def __init__(self, host: str = None, port: int = None):
        """
        Create a DeviceService bound to a specific IGP endpoint.

        If ``host`` is None, falls back to ``Config.DEVICE_IP`` for backward
        compatibility with code that still relies on the global default.
        In the multi-device architecture every caller should supply the
        patient's device IP explicitly.
        """
        self._host = host
        self._port = port
        self._igp = None
        self._last_host = None
        self._igp_lock = threading.Lock()

    def _ensure_igp(self):
        """Recreate IGPClient if the bound host/port has changed."""
        target_host = self._host or Config.DEVICE_IP
        target_port = self._port or Config.IGP_PORT
        if self._igp is None or self._last_host != target_host or self._igp.port != target_port:
            self._igp = IGPClient(host=target_host, port=target_port)
            self._last_host = target_host

    def _exec_protected(self, method_name: str, *args, **kwargs):
        """
        Executes an IGPClient method within the auth → cmd → deauth cycle.

        Acquires _igp_lock so that no other Cloud API request can interleave
        its own TCP connections between the three calls in this block.
        Deauthentication runs in the finally block to guarantee authenticated=0
        even if the command raises an exception.

        Generated TCP connection flow:
            1. IGP 0x02 AUTHENTICATE   → authenticated=1
            2. getattr(self._igp, method_name)() → protected operation
            3. IGP 0x0D DEAUTHENTICATE → authenticated=0
        """
        self._ensure_igp()
        with self._igp_lock:
            self._igp.authenticate(self._ADMIN_TOKEN)
            try:
                return getattr(self._igp, method_name)(*args, **kwargs)
            finally:
                try:
                    self._igp.deauthenticate()
                except IGPError:
                    pass  # best-effort deauth — do not propagate if the device does not respond

    # ── System information ──────────────────────────────────────────────────

    def get_sys_info(self) -> dict:
        """
        IGP 0x01 — system info without authentication.
        Parses the response 'v:<kernel>|m:<arch>' into a structured dict.
        """
        self._ensure_igp()
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

    # ── Authentication ──────────────────────────────────────────────────────

    def authenticate(self, token: str) -> dict:
        """
        IGP 0x02 — Admin token login.
        The token is transmitted in plaintext to the device.
        """
        self._ensure_igp()
        raw  = self._igp.authenticate(token)
        text = raw.decode('utf-8', errors='replace').strip()
        return {
            'success':         text == 'AUTH_SUCCESS',
            'device_response': text
        }

    # ── Network ─────────────────────────────────────────────────────────────

    def get_network_config(self) -> dict:
        """
        IGP 0x03 — Active network configuration (requires auth).

        VULNERABILITY: the device returns the full contents of
        /etc/config/wireless including the PSK key in plaintext.
        The response 'raw' field exposes this data directly.
        """
        raw  = self._exec_protected('get_network')
        text = raw.decode('utf-8', errors='replace').strip()
        return {
            'config': text,
            'raw':    text
        }

    # SET_WIFI on the Pi runs `sleep(5)` after `wifi reload` to wait for STA
    # association, then a second `system()` to verify the link with `iw`.
    # Pi-side wall-clock is ~6–8 s — well above the default IGP_TIMEOUT (5 s),
    # which made every successful reconfig surface as a generic socket timeout
    # in the cloud even though the radio had associated and acquired an IP.
    # Per-call override; the default stays tight for every other command.
    _SET_WIFI_TIMEOUT = 15

    def set_wifi(self, ssid: str, password: str) -> dict:
        """IGP 0x06 — Configures the WiFi SSID and password (requires auth)."""
        self._ensure_igp()
        original_timeout = self._igp.timeout
        self._igp.timeout = self._SET_WIFI_TIMEOUT
        try:
            raw = self._exec_protected('set_wifi', ssid, password)
        finally:
            self._igp.timeout = original_timeout
        text = raw.decode('utf-8', errors='replace').strip()
        return {
            'result':  text,
            'success': text.startswith('WIFI_UPDATED')
        }

    # ── Diagnostics ─────────────────────────────────────────────────────────

    def get_status(self, module: str = 'CareOtter') -> dict:
        """
        IGP 0x05 — Subsystem diagnostics (no auth).
        Valid modules on the device: CareOtter, BLE, Sensor, Network.
        """
        self._ensure_igp()
        raw  = self._igp.verify_status(module)
        text = raw.decode('utf-8', errors='replace').strip()
        return {
            'module': module,
            'status': text
        }

    # ── Configuration ──────────────────────────────────────────────────────

    def set_preferences(self, tlv_payload: bytes) -> dict:
        """
        IGP 0x04 — App preferences in TLV format (requires auth).
        Types: 0xAA=theme, 0xAB=language, 0xAC=display mode.
        """
        raw  = self._exec_protected('set_prefs', tlv_payload)
        text = raw.decode('utf-8', errors='replace').strip()
        return {'status': text}

    def set_thresholds(self, bpm_min: int, bpm_max: int, spo2_min: int) -> dict:
        """
        IGP 0x08 — Clinical alert thresholds (requires auth).

        Builds the TLV payload:
            [0xBB][0x04][bpm_min_hi][bpm_min_lo][bpm_max_hi][bpm_max_lo]
            [0xCC][0x01][spo2_min]
        Total: 9 bytes
        """
        tlv  = struct.pack('>BBHH', 0xBB, 4, bpm_min, bpm_max)
        tlv += struct.pack('>BBB',  0xCC, 1, spo2_min)
        raw  = self._exec_protected('set_threshold', tlv)
        text = raw.decode('utf-8', errors='replace').strip()
        # The exact IGP request frame IGPClient._build_header() sends for 0x08:
        # 8-byte header (begins with MAGIC 0x43415245 = "CARE") + the TLV.
        igp_frame = struct.pack(IGP_HEADER_FMT, MAGIC, 0x08, 0x00, len(tlv)) + tlv
        return {
            'result': text,
            'thresholds': {
                'bpm_min':  bpm_min,
                'bpm_max':  bpm_max,
                'spo2_min': spo2_min
            },
            # INFO DISCLOSURE (stripped by the endpoint unless VULNERABLE=1):
            # leaks the raw IGP request frame. Chains API6 BFLA → API4 — the first
            # 4 bytes reveal the protocol MAGIC needed to craft valid frames.
            'igp_request': igp_frame.hex()
        }

    def get_thresholds(self) -> dict:
        """
        IGP 0x0E — Read current clinical alert thresholds (no auth required).
        Parses response 'bpm_min=50\nbpm_max=120\nspo2_min=90' into a dict.
        Falls back to defaults if the device does not respond or the file is missing.
        """
        self._ensure_igp()
        raw  = self._igp.get_thresholds()
        text = raw.decode('utf-8', errors='replace').strip()
        result = {'bpm_min': 60, 'bpm_max': 100, 'spo2_min': 95, 'raw': text}
        for line in text.split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                k = k.strip()
                v = v.strip()
                if k in ('bpm_min', 'bpm_max', 'spo2_min'):
                    try:
                        result[k] = int(v)
                    except ValueError:
                        pass
        return result

    # ── System services ────────────────────────────────────────────────────

    def restart_service(self, service_name: str) -> dict:
        """
        IGP 0x09 — Restarts a device init.d service (requires auth).
        Valid names: medical-sensor, careservice, ble-server, etc.
        """
        raw  = self._exec_protected('reboot_service', service_name)
        text = raw.decode('utf-8', errors='replace').strip()
        return {
            'result':  text,
            'service': service_name
        }

    def get_log(self) -> dict:
        """IGP 0x0A — Last 512 bytes of the service log (requires auth)."""
        raw  = self._exec_protected('get_log')
        text = raw.decode('utf-8', errors='replace')
        return {'log': text}
