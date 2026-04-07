#!/usr/bin/env python3
# /opt/medical-sensor/sensor_service.py
# Medical sensor service with log rotation support (SIGUSR1) and summary logging

import time
import json
import math
import signal
import sys
import threading
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from simulator import get_bus

# ── Configuración ─────────────────────────────────────────
CONFIG_FILE = "/opt/medical-sensor/config.json"

def load_config():
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

cfg = load_config()
USE_REAL_HW = cfg.get("use_real_hardware", False)
BPM_BASE = cfg.get("bpm", 72)
SPO2_BASE = cfg.get("spo2", 98)
HTTP_PORT = cfg.get("http_port", 8081)
LOG_FILE = cfg.get("log_file", "/tmp/medical-logs/vitals.log")
SAMPLE_RATE_HZ = cfg.get("sample_rate", 10)
SUMMARY_EVERY = cfg.get("summary_every_s", 60)  # Segundos entre resúmenes
LOG_BUFFER_MAX = cfg.get("log_buffer_max", 1440)  # Máximo entradas en buffer

# ── Estado compartido ──────────────────────────────────────
latest = {
    "bpm": BPM_BASE,
    "spo2": SPO2_BASE,
    "red_raw": 0,
    "ir_raw": 0,
    "timestamp": 0,
    "source": "simulator" if not USE_REAL_HW else "hardware",
}
lock = threading.Lock()
log_lock = threading.Lock()
log_buffer = []  # Buffer circular de logs

# ── Log rotación support ───────────────────────────────────
class LogReopener:
    """Maneja la reapertura de logs ante señal SIGUSR1"""
    def __init__(self, log_path):
        self.log_path = log_path
        self._file = None
        self._open()
    
    def _open(self):
        """Abre el archivo de log"""
        try:
            if self._file:
                self._file.close()
            # Asegurar que el directorio existe
            if self.log_path:
                os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
            self._file = open(self.log_path, "a") if self.log_path else None
        except Exception as e:
            sys.stderr.write(f"[medical-sensor] Error opening log: {e}\n")
    
    def reopen(self):
        """Reabre el archivo (llamado por SIGUSR1)"""
        sys.stdout.write("[medical-sensor] Reopening log file (SIGUSR1)\n")
        self._open()
    
    def write(self, data):
        """Escribe datos al log"""
        if self._file:
            try:
                self._file.write(data)
                self._file.flush()
            except Exception as e:
                sys.stderr.write(f"[medical-sensor] Error writing log: {e}\n")
    
    def close(self):
        if self._file:
            self._file.close()

# Instancia global del logger
logger = LogReopener(LOG_FILE)

# ── Función de logging con buffer ─────────────────────────
def append_log(entry):
    """Añade entrada al buffer y opcionalmente a archivo"""
    with log_lock:
        log_buffer.append(entry)
        if len(log_buffer) > LOG_BUFFER_MAX:
            log_buffer.pop(0)
    
    # Escribir a archivo fuera del lock (si está configurado)
    if LOG_FILE:
        try:
            logger.write(json.dumps(entry) + "\n")
        except Exception as e:
            sys.stderr.write(f"[medical-sensor] Error writing to log file: {e}\n")

# ── Manejo de señales ─────────────────────────────────────
def handle_sigusr1(signum, frame):
    """Manejador de SIGUSR1 para log rotation"""
    logger.reopen()

def handle_shutdown(signum, frame):
    """Manejador de SIGTERM/SIGINT"""
    sys.stdout.write("[medical-sensor] Shutting down...\n")
    logger.close()
    sys.exit(0)

# ── Cálculo BPM desde señal PPG ───────────────────────────
def calculate_bpm(red_samples, sample_rate):
    """Detección de picos simple sobre buffer de muestras."""
    if len(red_samples) < 4:
        return BPM_BASE
    mean = sum(red_samples) / len(red_samples)
    peaks = 0
    for i in range(1, len(red_samples) - 1):
        if red_samples[i] > mean * 1.02 and \
           red_samples[i] > red_samples[i-1] and \
           red_samples[i] > red_samples[i+1]:
            peaks += 1
    duration = len(red_samples) / sample_rate
    return int((peaks / duration) * 60) if duration > 0 else BPM_BASE

# ── Loop de lectura del sensor ─────────────────────────────
def sensor_loop():
    bus = get_bus(real=USE_REAL_HW, bpm=BPM_BASE, spo2=SPO2_BASE)
    red_buffer = []
    interval = 1.0 / SAMPLE_RATE_HZ
    
    # Acumuladores para resúmenes
    bpm_accum = []
    spo2_accum = []
    sample_count = 0
    samples_per_summary = SUMMARY_EVERY * SAMPLE_RATE_HZ

    while True:
        try:
            raw = bus.read_i2c_block_data(0x57, 0x07, 6)
            red = (raw[0] << 16 | raw[1] << 8 | raw[2]) & 0x3FFFF
            ir = (raw[3] << 16 | raw[4] << 8 | raw[5]) & 0x3FFFF

            red_buffer.append(red)
            # Buffer de 60 segundos para tener suficientes muestras a cualquier sample_rate
            if len(red_buffer) > SAMPLE_RATE_HZ * 60:
                red_buffer.pop(0)

            # En modo simulado, usar valores base saludables; en hardware real, calcular de la señal
            if USE_REAL_HW:
                bpm = calculate_bpm(red_buffer, SAMPLE_RATE_HZ)
                # SpO2 desde ratio IR/RED (solo hardware real)
                spo2 = min(100, int(110 - 25 * (red / max(ir, 1))))
            else:
                # Simulación: valores saludables constantes
                import random
                # BPM: variación pequeña alrededor del valor base (60-100 es normal en reposo)
                bpm = max(60, min(100, BPM_BASE + random.randint(-3, 3)))
                # SpO2: constante en 98% (rango saludable normal: 95-100%)
                spo2 = 98

            with lock:
                latest.update({
                    "bpm": bpm,
                    "spo2": spo2,
                    "red_raw": red,
                    "ir_raw": ir,
                    "timestamp": time.time(),
                })

            # Acumular para resumen
            bpm_accum.append(bpm)
            spo2_accum.append(spo2)
            sample_count += 1
            
            # Generar resumen cuando toque
            if sample_count >= samples_per_summary:
                summary = {
                    "bpm_avg": round(sum(bpm_accum) / len(bpm_accum), 1),
                    "bpm_min": min(bpm_accum),
                    "bpm_max": max(bpm_accum),
                    "spo2_avg": round(sum(spo2_accum) / len(spo2_accum), 1),
                    "spo2_min": min(spo2_accum),
                    "spo2_max": max(spo2_accum),
                    "samples": sample_count,
                    "timestamp": time.time(),
                    "source": "simulator" if not USE_REAL_HW else "hardware",
                }
                append_log(summary)
                
                # Resetear acumuladores
                bpm_accum = []
                spo2_accum = []
                sample_count = 0

        except Exception as e:
            sys.stderr.write(f"[sensor] Error: {e}\n")

        time.sleep(interval)

# ── Servidor HTTP ──────────────────────────────────────────
class VitalsHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Silenciar log HTTP por defecto

    def do_GET(self):
        if self.path == "/vitals":
            with lock:
                data = dict(latest)
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        elif self.path == "/reload":
            """Endpoint para forzar reopen de logs (alternativa a SIGUSR1)"""
            logger.reopen()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"log reopened")
        
        elif self.path == "/log":
            """Devuelve el buffer completo de logs"""
            with log_lock:
                data = list(log_buffer)  # Copia para evitar race conditions
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        
        elif self.path == "/log/last":
            """Devuelve solo el último log"""
            with log_lock:
                data = log_buffer[-1] if log_buffer else {}
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        
        elif self.path == "/config":
            """Devuelve los parámetros activos del servicio"""
            config = {
                "use_real_hardware": USE_REAL_HW,
                "bpm": BPM_BASE,
                "spo2": SPO2_BASE,
                "http_port": HTTP_PORT,
                "log_file": LOG_FILE,
                "sample_rate": SAMPLE_RATE_HZ,
                "summary_every_s": SUMMARY_EVERY,
                "log_buffer_max": LOG_BUFFER_MAX,
            }
            body = json.dumps(config).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self.end_headers()

# ── Main ───────────────────────────────────────────────────
def main():
    # Configurar manejadores de señales
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGUSR1, handle_sigusr1)  # Para logrotate

    # Hilo sensor en background
    t = threading.Thread(target=sensor_loop, daemon=True)
    t.start()

    # Servidor HTTP en primer plano
    server = HTTPServer(("0.0.0.0", HTTP_PORT), VitalsHandler)
    sys.stdout.write(f"[medical-sensor] Listening on :{HTTP_PORT}\n")
    sys.stdout.write(f"[medical-sensor] Log file: {LOG_FILE}\n")
    sys.stdout.write(f"[medical-sensor] Summary every: {SUMMARY_EVERY}s\n")
    sys.stdout.write(f"[medical-sensor] Buffer max: {LOG_BUFFER_MAX} entries\n")
    sys.stdout.write("[medical-sensor] Send SIGUSR1 to reopen logs (logrotate)\n")
    sys.stdout.flush()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        handle_shutdown(None, None)

if __name__ == "__main__":
    main()
