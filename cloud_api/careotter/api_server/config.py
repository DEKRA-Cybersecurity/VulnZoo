"""
config.py — CareOtter Cloud API configuration

Environment variables allow adapting the API to different environments
(development, lab, production). Default values point to the fixed device
address used in the lab network (192.168.2.1).

INTENTIONAL VULNERABILITY:
    JWT_SECRET has a weak hardcoded default value.
    In production it should come exclusively from a secret manager,
    but the visible fallback in code facilitates static analysis.
"""

import os


class Config:
    # ── CareOtter device ───────────────────────────────────────────────────
    # Device IP: empty by default. The device registers dynamically via
    # POST /admin/device/register sending its WiFi IP. The Cloud API learns
    # the IP in real time instead of relying on a fixed Ethernet address
    # (192.168.2.1).
    DEVICE_IP   = os.getenv('DEVICE_IP',   '')
    IGP_PORT    = int(os.getenv('IGP_PORT',  '9999'))
    HTTP_PORT   = int(os.getenv('HTTP_PORT', '8081'))

    # Network timeouts (seconds)
    IGP_TIMEOUT  = int(os.getenv('IGP_TIMEOUT',  '5'))
    HTTP_TIMEOUT = int(os.getenv('HTTP_TIMEOUT', '3'))

    # ── JWT ─────────────────────────────────────────────────────────────────
    # Weak default secret — intentional vulnerability for the lab
    JWT_SECRET           = os.getenv('JWT_SECRET', 'careotter_jwt_2026')
    JWT_ALGORITHM        = 'HS256'
    JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', '8'))

    # ── Database ───────────────────────────────────────────────────────────
    # Path to the SQLite database (persisted via Docker volume)
    DB_PATH = os.getenv('DB_PATH', '/app/data/careotter.db')
    
    # ── Operation mode ─────────────────────────────────────────────────────
    # VULNERABLE=1 exposes raw fields, debug mode and detailed errors
    # VULNERABLE=0 enables additional security controls
    VULNERABLE = int(os.getenv('VULNERABLE', '1'))
