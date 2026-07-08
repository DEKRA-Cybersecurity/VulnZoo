#!/usr/bin/env python3
# lock-ui server - the IVI central-locking screen, runs ON the AGL head unit (Level 2).
#
# Serves index.html and turns a button click into an authenticated SOME/IP SetLock to
# the Central Gateway. The browser cannot send UDP, so this local bridge does. The
# token is the head unit's credential, held here. Operating the buttons is the
# occupant action a gray-box attacker sniffs (the token rides the SetLock in the clear).
#
# Run on AGL:  python3 server.py   then open http://<agl-ip>:8088/ in the IVI browser
#   CANARY_GW / CANARY_TOKEN / PORT via env.
import os
import socket
import struct
from http.server import BaseHTTPRequestHandler, HTTPServer

SERVICE_ID = 0x1401
M_SETLOCK = 0x0001
M_GETSTATE = 0x0002
GW = os.environ.get('CANARY_GW', '192.168.2.1')
TOKEN = os.environ.get('CANARY_TOKEN', 'AGL-HEADUNIT-7c2f').encode()
PORT = int(os.environ.get('PORT', '8088'))
HTML = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'index.html'), 'rb').read()


def someip(method, payload=b''):
    mid = (SERVICE_ID << 16) | method
    return struct.pack('>IIIBBBB', mid, 8 + len(payload), 0x00010001, 1, 1, 0, 0) + payload


def send(req):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.sendto(req, (GW, 30509))
    try:
        r = s.recvfrom(1024)[0]
    except socket.timeout:
        return 'no response'
    if r[14] == 0x81:
        return 'rejected'
    return 'locked' if r[16:] and r[16] else 'unlocked'


class Handler(BaseHTTPRequestHandler):
    def _txt(self, body):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        if self.path in ('/', '/index.html'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(HTML)
        elif self.path == '/api/state':
            self._txt(send(someip(M_GETSTATE)))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == '/api/lock':
            self._txt(send(someip(M_SETLOCK, TOKEN + b'\x01')))
        elif self.path == '/api/unlock':
            self._txt(send(someip(M_SETLOCK, TOKEN + b'\x00')))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


if __name__ == '__main__':
    print(f'IVI central-locking UI on http://0.0.0.0:{PORT}/  -> gateway {GW}:30509')
    HTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
