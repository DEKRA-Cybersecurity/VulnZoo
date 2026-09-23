"""config.py - BulbBee cloud API configuration.

Environment variables adapt the API to the lab. The `secure` toggle mirrors the
device's `secure` flag: off by default, so the shipped posture keeps the
intentional findings (BOLA, weak/keyless JWT, password ignored, plaintext MQTT,
unenforced binding). Set BULBBEE_SECURE=1 to enable the robust branches.

INTENTIONAL VULNERABILITY (API2): JWT_SECRET has a weak hardcoded default.
"""

import os


class Config:
    # ── JWT (API2: weak, hardcoded default secret) ──────────────────────────
    JWT_SECRET = os.getenv("JWT_SECRET", "bulbbee-secret")
    JWT_ALGORITHM = "HS256"

    # ── secure toggle (mirrors the device `secure` flag) ────────────────────
    # Off by default: BOLA + plaintext MQTT + password ignored (the findings).
    SECURE = os.getenv("BULBBEE_SECURE") == "1"

    # ── MQTT broker / relay ─────────────────────────────────────────────────
    BROKER_HOST = os.getenv("BULBBEE_BROKER_HOST", "bulbbee-broker")
    BROKER_PORT = int(os.getenv("BULBBEE_BROKER_PORT", "1883"))
    BROKER_TLS_PORT = int(os.getenv("BULBBEE_BROKER_TLS_PORT", "8883"))

    # ── Claim tokens (BULB-R6) ──────────────────────────────────────────────
    CLAIM_TTL = int(os.getenv("BULBBEE_CLAIM_TTL", "300"))

    # ── Database (SQLite via SQLAlchemy, persisted on the Docker volume) ─────
    DB_PATH = os.getenv("DB_PATH", "/app/data/bulbbee.db")
    DB_URL = os.getenv("BULBBEE_DB_URL", "sqlite:///" + DB_PATH)

    PORT = int(os.getenv("PORT", "5004"))
    LIGHT_KEYS = ("power", "brightness", "color", "scene")
