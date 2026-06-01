"""
wsgi.py — Gunicorn entrypoint for CareOtter Cloud API.

Usage (production / container):
    gunicorn --bind 0.0.0.0:5002 --workers 1 --threads 4 --timeout 60 wsgi:app

Why ``workers 1``:
    Background threads (_cloud_simulator_loop, _vitals_aggregator_loop,
    _fetch_device_mac) must run in a single process to avoid duplicate inserts
    and race conditions on the SQLite database.

Why ``threads 4``:
    Werkzeug's dev server handles one request at a time (or very few).
    Gunicorn's threaded worker lets the same process serve multiple requests
    concurrently, eliminating the connection-backlog drops observed under
    brute-force load.
"""

from app import app, init_app

# Run startup logic (DB auto-init, background threads) once per process.
init_app()
