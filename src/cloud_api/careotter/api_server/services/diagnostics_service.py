"""
diagnostics_service.py — CareOtter "Device Diagnostics" probe.

Backs OWASP API7:2023 (Server-Side Request Forgery). A patient asks the cloud to fetch a live
diagnostics snapshot from a device URL; the cloud fetches it server-side and reflects the
upstream status + body (the reflection is the SSRF oracle).

The probe host is validated against a PER-USER whitelist: ONLY the device(s) registered to the
requesting patient (`device_ip` where `patient_username` == them). A patient with no registered
device cannot diagnose anything (`no_device`).

Secure (`VULNERABLE=0`): the URL host is parsed with `urllib.parse.urlparse` — the SAME parser
the HTTP client effectively uses — checked against that exact per-user whitelist, and rejected if
it is a loopback / link-local / `localhost` target. Validation and fetch agree, so there is no
parser differential to exploit.

Vulnerable (`VULNERABLE=1`): the host is extracted with a naive hand-rolled parser that takes
the FIRST authority token, stripping credentials the wrong way. Embedded credentials fool it:
for `http://<device-ip>@127.0.0.1:5002/api/users/delete` (where `<device-ip>` is the patient's
OWN registered device) the validator sees `<device-ip>` (whitelisted) while `requests`/urllib3
connect to `127.0.0.1` with the path preserved. The loopback-only `/api/users/*` endpoints trust
the origin → SSRF → privilege escalation.

The vulnerability is intentional. Do NOT "fix" the naive parser unless explicitly asked.
"""

import re
import ipaddress
import logging
from urllib.parse import urlparse

import requests as http_requests

from config import Config

logger = logging.getLogger(__name__)


class DiagnosticsService:
    REQUEST_TIMEOUT = 3   # seconds
    MAX_BODY = 4096       # chars of upstream body reflected back

    def __init__(self, db):
        self.db = db

    # ── Per-patient whitelist: ONLY the requester's own registered device(s) ──
    def _patient_device_hosts(self, username):
        """Hosts (`device_ip`) of devices OWNED BY this patient. A patient may only
        diagnose a device registered to them, so the whitelist is per-user — not a
        global set of every device. Empty set when the patient has no device."""
        hosts = set()
        if not username:
            return hosts
        for d in self.db.get_devices_for_patient(username):
            ip = (d.get('device_ip') or '').strip().lower()
            if ip:
                hosts.add(ip)
        return hosts

    # ── Host extraction: naive (vuln) vs urlparse (secure) ───────────────────
    @staticmethod
    def _naive_host(url):
        """BUG (API7): 'the host is the first authority token'. Everything up to the first
        @ : or / is treated as the host, so userinfo (the embedded credentials) wins."""
        try:
            authority = url.split('//', 1)[1].split('/', 1)[0]
            return re.split(r'[@:/]', authority)[0].lower()
        except (IndexError, AttributeError):
            return None

    @staticmethod
    def _is_dangerous_host(host):
        """Defense-in-depth: block loopback / link-local / localhost. Note it does NOT block
        general private ranges — real devices live on 192.168/10/172 subnets, so the exact
        whitelist (not a broad private-IP ban) is the primary control."""
        h = (host or '').lower()
        if h in ('localhost', 'localhost.localdomain', ''):
            return True
        try:
            ip = ipaddress.ip_address(h)
            return ip.is_loopback or ip.is_link_local
        except ValueError:
            return False

    def _validate(self, probe_url, username):
        """Return (ok, reason). Reads Config.VULNERABLE per call (toggle lives here).
        The whitelist is the requesting patient's OWN device(s) only."""
        if not isinstance(probe_url, str) or not probe_url.lower().startswith(('http://', 'https://')):
            return False, 'invalid_url'
        whitelist = self._patient_device_hosts(username)
        if not whitelist:
            # Protection: a patient with no registered device cannot diagnose anything.
            return False, 'no_device'

        if Config.VULNERABLE == 1:
            # VULNERABLE: naive parser — fooled by `<own-device-ip>@127.0.0.1`.
            host = self._naive_host(probe_url)
            if host not in whitelist:
                return False, 'host_not_allowed'
            return True, None

        # SECURE: parse the host the same way the HTTP client connects, exact per-user
        # whitelist, and block loopback/link-local. No parser differential.
        host = (urlparse(probe_url).hostname or '').lower()
        if host not in whitelist:
            return False, 'host_not_allowed'
        if self._is_dangerous_host(host):
            return False, 'host_not_allowed'
        return True, None

    # ── Public API ───────────────────────────────────────────────────────────
    def probe(self, probe_url, username):
        ok, reason = self._validate(probe_url, username)
        if not ok:
            return {'ok': False, 'error': reason}
        try:
            resp = http_requests.get(probe_url, timeout=self.REQUEST_TIMEOUT,
                                     allow_redirects=False)
            body = resp.text or ''
            if len(body) > self.MAX_BODY:
                body = body[:self.MAX_BODY] + '…[truncated]'
            # Oracle (discovery model B): reflect upstream status + body verbatim.
            return {'ok': True, 'status': resp.status_code, 'body': body,
                    'fetched': probe_url}
        except http_requests.RequestException as e:
            return {'ok': False, 'error': 'fetch_failed', 'detail': str(e)}
