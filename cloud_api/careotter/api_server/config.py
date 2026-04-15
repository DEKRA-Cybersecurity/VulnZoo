"""
config.py — Configuración de la CareOtter Cloud API

Las variables de entorno permiten adaptar la API a distintos entornos
(desarrollo, laboratorio, producción). Los valores por defecto apuntan
a la dirección fija del dispositivo en la red de laboratorio (192.168.2.1).

VULNERABILIDAD INTENCIONAL:
    JWT_SECRET tiene un valor por defecto hardcodeado débil.
    En producción debería venir exclusivamente de un gestor de secretos,
    pero el fallback visible en código facilita el análisis estático.
"""

import os


class Config:
    # ── Dispositivo CareOtter ───────────────────────────────────────────────
    # IP fija del dispositivo en la red de laboratorio
    DEVICE_IP   = os.getenv('DEVICE_IP',   '192.168.2.1')
    IGP_PORT    = int(os.getenv('IGP_PORT',  '9999'))
    HTTP_PORT   = int(os.getenv('HTTP_PORT', '8081'))

    # Timeouts de red (segundos)
    IGP_TIMEOUT  = int(os.getenv('IGP_TIMEOUT',  '5'))
    HTTP_TIMEOUT = int(os.getenv('HTTP_TIMEOUT', '3'))

    # ── JWT ─────────────────────────────────────────────────────────────────
    # Secreto débil por defecto — vulnerabilidad intencional para el laboratorio
    JWT_SECRET           = os.getenv('JWT_SECRET', 'careotter_jwt_2026')
    JWT_ALGORITHM        = 'HS256'
    JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', '8'))

    # ── Base de datos ───────────────────────────────────────────────────────
    # Ruta a la base de datos SQLite (persistente via volumen Docker)
    DB_PATH = os.getenv('DB_PATH', '/app/data/careotter.db')
    
    # ── Modo de operación ───────────────────────────────────────────────────
    # VULNERABLE=1 expone campos raw, debug mode y errores detallados
    # VULNERABLE=0 activa controles de seguridad adicionales
    VULNERABLE = int(os.getenv('VULNERABLE', '1'))
