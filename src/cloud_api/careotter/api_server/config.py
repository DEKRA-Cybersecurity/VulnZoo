"""
config.py — CareOtter Cloud API configuration

Environment variables allow adapting the API to different environments
(development, lab, production). The device address is learned dynamically
via POST /admin/device/register or the sensor /health endpoint — there is
no fixed default address.

INTENTIONAL VULNERABILITY:
    JWT_SECRET has a weak hardcoded default value.
    In production it should come exclusively from a secret manager,
    but the visible fallback in code facilitates static analysis.
"""

import os


class Config:
    # ── CareOtter device ───────────────────────────────────────────────────
    # Device IP: empty by default. The device registers dynamically via
    # POST /admin/device/register sending its WiFi IP, or the Cloud API
    # resolves it from the sensor /health endpoint. Per-device IPs are
    # stored in the SQLite devices table (device_ip + igp_port columns).
    DEVICE_IP   = os.getenv('DEVICE_IP',   '')
    IGP_PORT    = int(os.getenv('IGP_PORT',  '9999'))
    HTTP_PORT   = int(os.getenv('HTTP_PORT', '8081'))

    # Network timeouts (seconds)
    IGP_TIMEOUT  = int(os.getenv('IGP_TIMEOUT',  '5'))
    HTTP_TIMEOUT = int(os.getenv('HTTP_TIMEOUT', '3'))

    # ── JWT ─────────────────────────────────────────────────────────────────
    # Weak default secret — intentional vulnerability for the lab
    JWT_SECRET           = os.environ['JWT_SECRET']
    JWT_ALGORITHM        = 'HS256'
    JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', '8'))

    # ── Database ───────────────────────────────────────────────────────────
    # Path to the SQLite database (persisted via Docker volume)
    DB_PATH = os.getenv('DB_PATH', '/app/data/careotter.db')

    # ── Uploads (user content on disk, not inline in the DB) ────────────────
    # Profile photos are written here as files; the users.profile_photo column
    # keeps only a short URL path. Placed beside the SQLite DB so the same
    # mounted volume persists both.
    UPLOAD_DIR = os.getenv('UPLOAD_DIR', os.path.join(os.path.dirname(DB_PATH) or '.', 'uploads'))

    # ── Operation mode ─────────────────────────────────────────────────────
    # VULNERABLE=1 exposes raw fields, debug mode and detailed errors
    # VULNERABLE=0 enables additional security controls
    VULNERABLE = int(os.getenv('VULNERABLE', '1'))
