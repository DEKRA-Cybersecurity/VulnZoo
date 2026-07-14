// ============================================================
// VulnZoo — Messages Inbox
// Misma lógica de API que el original; UI adaptada al layout de dos paneles.
// ============================================================

// ---------- Dark mode ----------
function setDarkMode(enabled) {
    if (enabled) {
        document.body.classList.add('dark-mode');
    } else {
        document.body.classList.remove('dark-mode');
    }
    localStorage.setItem('theme', enabled ? 'dark' : 'light');
}

function initThemeToggle() {
    const btn = document.getElementById('theme-toggle');
    const saved = localStorage.getItem('theme');
    setDarkMode(saved === 'dark');
    if (!btn) return;
    btn.addEventListener('click', () => {
        const isDark = !document.body.classList.contains('dark-mode');
        setDarkMode(isDark);
    });
}
window.addEventListener('DOMContentLoaded', initThemeToggle);

// ---------- Estado ----------
let messages = [];
let currentMessageId = null;

const listEl = document.getElementById('messagesList');
const readerPanel = document.getElementById('readerPanel');
const loadingEl = document.getElementById('loadingIndicator');
const errorEl = document.getElementById('errorContainer');
const successEl = document.getElementById('successContainer');
const emptyStateEl = document.getElementById('emptyState');
const composeSectionEl = document.getElementById('sendMessageSection');
const inboxCountEl = document.getElementById('inboxCount');
const searchInput = document.getElementById('searchInput');

const sendMessageForm = document.getElementById('sendMessageForm');
const recipientInput = document.getElementById('recipientInput');
const subjectInput = document.getElementById('subjectInput');
const bodyInput = document.getElementById('bodyInput');
const sendMessageError = document.getElementById('sendMessageError');
const sendMessageSuccess = document.getElementById('sendMessageSuccess');

// ---------- Helpers de UI ----------
const AVATAR_COLORS = ['#4a90e2', '#5b7fb0', '#3f7a9c', '#5a6fa8', '#6a7d9c', '#4778a8'];

function avatarColor(seed) {
    const s = String(seed || '');
    let hash = 0;
    for (let i = 0; i < s.length; i++) hash = (hash * 31 + s.charCodeAt(i)) >>> 0;
    return AVATAR_COLORS[hash % AVATAR_COLORS.length];
}

function initialsFor(name) {
    const parts = String(name || '?').replace(/[._-]/g, ' ').trim().split(/\s+/);
    if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str == null ? '' : String(str);
    return div.innerHTML;
}

// Muestra uno de los tres paneles de la derecha: 'empty' | 'reader' | 'compose'
function showDetail(which) {
    emptyStateEl.style.display = which === 'empty' ? 'flex' : 'none';
    readerPanel.style.display = which === 'reader' ? 'flex' : 'none';
    composeSectionEl.style.display = which === 'compose' ? 'flex' : 'none';
}

function markActive(id) {
    listEl.querySelectorAll('.msg-item').forEach(el => {
        el.classList.toggle('active', el.dataset.id === String(id));
    });
}

// ---------- Cargar mensajes ----------
async function loadMessages() {
    try {
        loadingEl.style.display = 'block';
        listEl.style.display = 'none';
        errorEl.innerHTML = '';
        successEl.innerHTML = '';

        const token = localStorage.getItem('auth');
        if (!token) {
            showError('Authentication required. Redirecting to login...');
            setTimeout(() => window.location.href = '/login', 2000);
            return;
        }

        let url = '/api/messages';
        const params = new URLSearchParams();
        if (params.toString()) url += '?' + params.toString();

        const response = await fetch(url, {
            method: 'GET',
            headers: { 'X-Auth-Token': token, 'Content-Type': 'application/json' }
        });

        if (!response.ok) {
            if (response.status === 401) {
                showError('Session expired. Redirecting to login...');
                setTimeout(() => window.location.href = '/login', 2000);
                return;
            }
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        messages = data.messages || [];

        loadingEl.style.display = 'none';
        listEl.style.display = 'block';
        renderList();

    } catch (error) {
        loadingEl.style.display = 'none';
        showError(`Error loading messages: ${error.message}`);
        console.error('Load messages error:', error);
    }
}

// ---------- Render de la lista ----------
function renderList() {
    listEl.innerHTML = '';

    const term = (searchInput && searchInput.value || '').trim().toLowerCase();
    const visible = term
        ? messages.filter(m =>
            ((m.subject || '') + ' ' + (m.sender || '') + ' ' + (m.body || ''))
                .toLowerCase().includes(term))
        : messages;

    inboxCountEl.textContent =
        `${messages.length} message${messages.length === 1 ? '' : 's'}`;

    if (!visible.length) {
        listEl.innerHTML = `<div class="empty">📭 No messages found.</div>`;
        return;
    }

    visible.forEach(m => {
        const sender = m.sender || 'Unknown';
        const subject = m.subject || '(no subject)';
        const snippet = (m.body || '').replace(/\s+/g, ' ').slice(0, 60);

        const item = document.createElement('div');
        item.className = 'msg-item';
        item.dataset.id = m.id;
        if (String(m.id) === String(currentMessageId)) item.classList.add('active');

        item.innerHTML = `
            <div class="msg-avatar" style="background:${avatarColor(sender)}">${escapeHtml(initialsFor(sender))}</div>
            <div class="msg-main">
                <div class="msg-topline">
                    <p class="msg-sender">${escapeHtml(sender)}</p>
                </div>
                <p class="msg-title">${escapeHtml(subject)}</p>
                <p class="msg-snippet">${escapeHtml(snippet)}${m.body && m.body.length > 60 ? '…' : ''}</p>
            </div>
        `;

        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'delete-btn';
        deleteBtn.textContent = 'Delete';
        deleteBtn.onclick = (e) => { e.stopPropagation(); deleteMessage(m.id); };
        item.appendChild(deleteBtn);

        item.onclick = () => openMessage(m.id);
        listEl.appendChild(item);
    });
}

function filterMessages() {
    renderList();
}

// ---------- Abrir / cerrar mensaje ----------
async function openMessage(id) {
    const m = messages.find(x => String(x.id) === String(id));
    if (!m) return;

    currentMessageId = id;
    const sender = m.sender || 'Unknown';

    document.getElementById('readerTitle').textContent = m.subject || '(no subject)';
    const avatarEl = document.getElementById('readerAvatar');
    avatarEl.textContent = initialsFor(sender);
    avatarEl.style.background = avatarColor(sender);
    document.getElementById('readerSender').innerHTML =
        `${escapeHtml(sender)}<span class="meta">to me</span>`;
    // VULNERABILITY: Stored XSS - body rendered as HTML (chains with API10 sender spoofing)
    document.getElementById('readerBody').innerHTML = m.body || '';

    markActive(id);
    showDetail('reader');
}

function closeMessage() {
    currentMessageId = null;
    markActive(null);
    showDetail('empty');
}

// ---------- Redacción ----------
function openCompose() {
    currentMessageId = null;
    markActive(null);
    sendMessageError.style.display = 'none';
    sendMessageSuccess.style.display = 'none';
    showDetail('compose');
    recipientInput.focus();
}

function closeCompose() {
    showDetail('empty');
}

// ---------- Borrado ----------
async function deleteMessage(messageId) {
    if (!confirm('Are you sure you want to delete this message?')) return;

    try {
        const token = localStorage.getItem('auth');
        const response = await fetch(`/api/messages/${messageId}`, {
            method: 'DELETE',
            headers: { 'X-Auth-Token': token, 'Content-Type': 'application/json' }
        });

        if (response.ok) {
            showSuccess('Message deleted successfully');
            messages = messages.filter(m => String(m.id) !== String(messageId));
            if (String(currentMessageId) === String(messageId)) closeMessage();
            renderList();
        } else {
            const data = await response.json();
            showError(data.error || 'Failed to delete message');
        }
    } catch (error) {
        showError(`Error deleting message: ${error.message}`);
    }
}

async function deleteCurrentMessage() {
    if (!currentMessageId) return;
    await deleteMessage(currentMessageId);
}

// ---------- Avisos ----------
function showError(message) {
    errorEl.innerHTML = `<div class="error">${escapeHtml(message)}</div>`;
    setTimeout(() => errorEl.innerHTML = '', 5000);
}

function showSuccess(message) {
    successEl.innerHTML = `<div class="success">${escapeHtml(message)}</div>`;
    setTimeout(() => successEl.innerHTML = '', 3000);
}

// ---------- Envío ----------
sendMessageForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    sendMessageError.style.display = 'none';
    sendMessageSuccess.style.display = 'none';

    const recipient = recipientInput.value.trim();
    const subject = subjectInput.value.trim();
    const body = bodyInput.value.trim();

    if (!recipient || !body) {
        sendMessageError.textContent = 'Recipient and message body are required.';
        sendMessageError.style.display = 'block';
        return;
    }
    if (body.length > 5000) {
        sendMessageError.textContent = 'Message too long (max 5000 characters).';
        sendMessageError.style.display = 'block';
        return;
    }
    if (subject.length > 200) {
        sendMessageError.textContent = 'Subject too long (max 200 characters).';
        sendMessageError.style.display = 'block';
        return;
    }

    try {
        const token = localStorage.getItem('auth');
        const response = await fetch('/api/messages', {
            method: 'POST',
            headers: { 'X-Auth-Token': token, 'Content-Type': 'application/json' },
            body: JSON.stringify({
                sender: localStorage.getItem('user_name'),
                recipient: recipient,
                subject: subject,
                message: body
            })
        });
        const data = await response.json();
        if (response.ok) {
            sendMessageSuccess.textContent = 'Message sent successfully!';
            sendMessageSuccess.style.display = 'block';
            sendMessageForm.reset();
            loadMessages();
            setTimeout(closeCompose, 1200);
        } else {
            sendMessageError.textContent = data.error || 'Failed to send message.';
            sendMessageError.style.display = 'block';
        }
    } catch (err) {
        sendMessageError.textContent = 'Error sending message: ' + err.message;
        sendMessageError.style.display = 'block';
    }
});

loadMessages();
