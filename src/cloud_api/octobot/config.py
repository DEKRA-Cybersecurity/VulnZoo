"""
config.py — OctoBot Cloud API configuration

Environment variables allow adapting the API to different environments
(development, lab, production).
"""

import os


class Config:
    # ── Modbus / Pi gateway ───────────────────────────────────────────────────
    MODBUS_HOST = os.getenv('MODBUS_HOST', '192.168.2.1')
    MODBUS_PORT = int(os.getenv('MODBUS_PORT', '502'))

    # ── HTTP ──────────────────────────────────────────────────────────────────
    HTTP_PORT = int(os.getenv('HTTP_PORT', '5003'))

    # ── Operator account ──────────────────────────────────────────────────────
    OPERATOR_USER = os.getenv('OPERATOR_USER', 'operator')
    OPERATOR_PASSWORD = os.getenv('OPERATOR_PASSWORD', 'octobot')

    # ── Database ──────────────────────────────────────────────────────────────
    DB_PATH = os.getenv('DB_PATH', '/app/data/octobot.db')

    # ── Flask session ─────────────────────────────────────────────────────────
    # Functional auth, not a vuln target. The OctoBot IoT vulnerabilities live on
    # the Pi and remain reachable directly regardless of this console.
    SECRET_KEY = os.getenv('SECRET_KEY', 'octobot-cloud-secret-2026')

    # ── Firmware storage ──────────────────────────────────────────────────────
    FIRMWARE_DIR = os.getenv('FIRMWARE_DIR', '/app/firmware')
    FIRMWARE_FILENAME = os.getenv('FIRMWARE_FILENAME', 'robot_arm.hex')

    # ── Pi SSH push ───────────────────────────────────────────────────────────
    PI_HOST = os.getenv('PI_HOST', MODBUS_HOST)
    PI_USER = os.getenv('PI_USER', 'root')
    PI_FIRMWARE_PATH = os.getenv('PI_FIRMWARE_PATH', '/opt/octobot/firmware/robot_arm.hex')
