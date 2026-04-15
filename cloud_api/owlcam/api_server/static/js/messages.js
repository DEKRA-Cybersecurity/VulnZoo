// Dark mode toggle logic
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
    if (!btn) return;
    btn.addEventListener('click', () => {
        const isDark = !document.body.classList.contains('dark-mode');
        setDarkMode(isDark);
    });
    // Load preference
    const saved = localStorage.getItem('theme');
    if (saved === 'dark') setDarkMode(true);
    else setDarkMode(false);
}

window.addEventListener('DOMContentLoaded', initThemeToggle);
let messages = [];
let currentMessageId = null;

const listEl = document.getElementById('messagesList');
const readerPanel = document.getElementById('readerPanel');
const loadingEl = document.getElementById('loadingIndicator');
const errorEl = document.getElementById('errorContainer');
const successEl = document.getElementById('successContainer');

const sendMessageForm = document.getElementById('sendMessageForm');
const recipientInput = document.getElementById('recipientInput');
const subjectInput = document.getElementById('subjectInput');
const bodyInput = document.getElementById('bodyInput');
const sendMessageError = document.getElementById('sendMessageError');
const sendMessageSuccess = document.getElementById('sendMessageSuccess');

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
        if (params.toString()) {
            url += '?' + params.toString();
        }

        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'X-Auth-Token': token,
                'Content-Type': 'application/json'
            }
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

function renderList() {
    listEl.innerHTML = '';
    if (!messages || messages.length === 0) {
        listEl.innerHTML = '<div class="empty">📭 No messages found.</div>';
        return;
    }
    
    messages.forEach(m => {
        const item = document.createElement('div');
        item.className = 'msg-item';
        
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'delete-btn';
        deleteBtn.textContent = '🗑️ Delete';
        deleteBtn.onclick = (e) => {
            e.stopPropagation();
            deleteMessage(m.id);
        };
        
        item.innerHTML = `
            <div class="msg-title">${m.subject || '(no subject)'}</div>
            <div class="msg-sender">From: ${m.sender || 'Unknown'}</div>
            <div class="msg-snippet">${(m.body || '').slice(0,100)}${m.body && m.body.length > 100 ? '...' : ''}</div>
        `;
        item.appendChild(deleteBtn);
        item.onclick = () => openMessage(m.id);
        listEl.appendChild(item);
    });
}

async function openMessage(id) {
    const m = messages.find(x => String(x.id) === String(id));
    if (!m) return;
    
    currentMessageId = id;
    
    readerPanel.querySelector('#readerTitle').textContent = m.subject || '(no subject)';
    readerPanel.querySelector('#readerSender').textContent = `From: ${m.sender || 'Unknown'}`;
    readerPanel.querySelector('#readerBody').innerHTML = m.body || '';
    
    listEl.style.display = 'none';
    readerPanel.style.display = 'block';
    
    window.scrollTo({top: 0, behavior: 'smooth'});
}

async function deleteMessage(messageId) {
    if (!confirm('Are you sure you want to delete this message?')) {
        return;
    }
    
    try {
        const token = localStorage.getItem('auth');
        const response = await fetch(`/api/messages/${messageId}`, {
            method: 'DELETE',
            headers: {
                'X-Auth-Token': token,
                'Content-Type': 'application/json'
            }
        });
        
        if (response.ok) {
            showSuccess('Message deleted successfully');
            messages = messages.filter(m => String(m.id) !== String(messageId));
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
    closeMessage();
}

function closeMessage() {
    readerPanel.style.display = 'none';
    listEl.style.display = 'block';
    currentMessageId = null;
    window.scrollTo({top: 0, behavior: 'smooth'});
}

function showError(message) {
    errorEl.innerHTML = `<div class="error">${message}</div>`;
    setTimeout(() => errorEl.innerHTML = '', 5000);
}

function showSuccess(message) {
    successEl.innerHTML = `<div class="success">${message}</div>`;
    setTimeout(() => successEl.innerHTML = '', 3000);
}

sendMessageForm.addEventListener('submit', async function(e) {
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
            headers: {
                'X-Auth-Token': token,
                'Content-Type': 'application/json'
            },
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