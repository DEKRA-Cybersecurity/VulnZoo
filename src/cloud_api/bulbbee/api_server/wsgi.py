"""wsgi.py - Gunicorn entrypoint for the BulbBee cloud API.

    gunicorn --bind 0.0.0.0:5004 --workers 1 --threads 4 wsgi:app

workers 1: the MQTT subscriber background thread (state + activation) must run in
a single process to avoid duplicate binds on the SQLite database.
"""

from app import app, init_app

# Run startup logic (DB seed + background subscriber) once per process.
init_app()
