/* profile.js — CareOtter patient profile / account settings */
(function () {
    'use strict';

    const state = {
        token: localStorage.getItem('careotter_token') || ''
    };

    function authHeaders(extra) {
        return Object.assign({ 'Authorization': 'Bearer ' + state.token }, extra || {});
    }

    // ── Theme toggle (shared behaviour with index.js) ──────────────────────────
    function initThemeToggle() {
        const btn = document.getElementById('theme-toggle');
        if (!btn) return;
        if (localStorage.getItem('theme') === 'dark') document.body.classList.add('dark-mode');
        btn.addEventListener('click', () => {
            const isDark = !document.body.classList.contains('dark-mode');
            document.body.classList.toggle('dark-mode', isDark);
            localStorage.setItem('theme', isDark ? 'dark' : 'light');
        });
    }

    function initLogout() {
        const btn = document.getElementById('btn-logout');
        if (!btn) return;
        btn.addEventListener('click', async () => {
            try { await fetch('/api/auth/logout', { method: 'POST' }); } catch (_) {}
            localStorage.removeItem('careotter_token');
            window.location.href = '/patient/login';
        });
    }

    function setMsg(id, text, ok) {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = text;
        el.className = 'form-msg ' + (ok ? 'ok' : 'err');
    }

    function formatDate(s) {
        if (!s) return '—';
        const d = new Date(s.replace(' ', 'T'));
        return isNaN(d) ? s : d.toLocaleDateString();
    }

    // ── Load profile ───────────────────────────────────────────────────────────
    async function loadProfile() {
        try {
            const res = await fetch('/api/user/profile', { headers: authHeaders() });
            if (res.status === 401) { window.location.href = '/patient/login'; return; }
            if (!res.ok) return;
            const data = await res.json();
            const p = data.profile || {};

            document.getElementById('identity-username').textContent = p.username || '—';
            document.getElementById('identity-name').textContent = p.display_name || p.username || '—';
            document.getElementById('identity-role').textContent = p.role || 'patient';
            document.getElementById('identity-since').textContent = formatDate(p.created_at);

            const dn = document.getElementById('display-name-input');
            if (dn) dn.value = p.display_name || '';
            const un = document.getElementById('username-input');
            if (un) un.value = p.username || '';

            if (p.profile_photo) {
                document.getElementById('avatar-img').src = p.profile_photo;
            }
        } catch (e) {
            console.error('Failed to load profile:', e);
        }
    }

    // ── Photo upload ─────────────────────────────────────────────────────────--
    function initPhotoUpload() {
        const input = document.getElementById('avatar-input');
        if (!input) return;
        input.addEventListener('change', () => {
            const file = input.files && input.files[0];
            if (!file) return;
            if (!file.type.startsWith('image/')) {
                alert('Please choose an image file.');
                return;
            }
            if (file.size > 3 * 1024 * 1024) {
                alert('Image too large. Max 3 MB.');
                return;
            }
            const reader = new FileReader();
            reader.onload = async () => {
                const dataUri = reader.result;
                document.getElementById('avatar-img').src = dataUri;  // optimistic
                try {
                    const res = await fetch('/api/user/profile/photo', {
                        method: 'POST',
                        headers: authHeaders({ 'Content-Type': 'application/json' }),
                        body: JSON.stringify({ photo: dataUri })
                    });
                    if (!res.ok) {
                        const d = await res.json().catch(() => ({}));
                        alert(d.error || 'Failed to upload photo.');
                    }
                } catch (e) {
                    alert('Network error uploading photo.');
                }
            };
            reader.readAsDataURL(file);
        });
    }

    // ── Display name ─────────────────────────────────────────────────────────--
    function initDisplayName() {
        const btn = document.getElementById('btn-save-display');
        if (!btn) return;
        btn.addEventListener('click', async () => {
            const value = document.getElementById('display-name-input').value.trim();
            try {
                const res = await fetch('/api/user/profile/photo', {
                    method: 'POST',
                    headers: authHeaders({ 'Content-Type': 'application/json' }),
                    body: JSON.stringify({ display_name: value })
                });
                if (res.ok) {
                    setMsg('display-msg', 'Display name saved.', true);
                    document.getElementById('identity-name').textContent = value || document.getElementById('identity-username').textContent;
                } else {
                    const d = await res.json().catch(() => ({}));
                    setMsg('display-msg', d.error || 'Failed to save.', false);
                }
            } catch (e) {
                setMsg('display-msg', 'Network error.', false);
            }
        });
    }

    // ── Username ────────────────────────────────────────────────────────────--
    function initUsername() {
        const btn = document.getElementById('btn-save-username');
        if (!btn) return;
        btn.addEventListener('click', async () => {
            const value = document.getElementById('username-input').value.trim();
            if (value.length < 3) {
                setMsg('username-msg', 'Username must be at least 3 characters.', false);
                return;
            }
            try {
                const res = await fetch('/api/user/profile/username', {
                    method: 'POST',
                    headers: authHeaders({ 'Content-Type': 'application/json' }),
                    body: JSON.stringify({ new_username: value })
                });
                const d = await res.json().catch(() => ({}));
                if (res.ok) {
                    // Rotate the stored token so subsequent API calls authenticate
                    // as the renamed account.
                    if (d.token) {
                        state.token = d.token;
                        localStorage.setItem('careotter_token', d.token);
                    }
                    setMsg('username-msg', 'Username updated.', true);
                    document.getElementById('identity-username').textContent = d.username || value;
                } else {
                    setMsg('username-msg', d.error || 'Failed to change username.', false);
                }
            } catch (e) {
                setMsg('username-msg', 'Network error.', false);
            }
        });
    }

    // ── Password ────────────────────────────────────────────────────────────--
    function initPassword() {
        const btn = document.getElementById('btn-save-password');
        if (!btn) return;
        btn.addEventListener('click', async () => {
            const cur     = document.getElementById('current-pw-input').value;
            const next    = document.getElementById('new-pw-input').value;
            const confirm = document.getElementById('confirm-pw-input').value;

            if (next.length < 6) {
                setMsg('password-msg', 'New password must be at least 6 characters.', false);
                return;
            }
            if (next !== confirm) {
                setMsg('password-msg', 'New passwords do not match.', false);
                return;
            }
            try {
                const res = await fetch('/api/user/profile/password', {
                    method: 'POST',
                    headers: authHeaders({ 'Content-Type': 'application/json' }),
                    body: JSON.stringify({ current_password: cur, new_password: next })
                });
                const d = await res.json().catch(() => ({}));
                if (res.ok) {
                    setMsg('password-msg', 'Password updated.', true);
                    document.getElementById('current-pw-input').value = '';
                    document.getElementById('new-pw-input').value = '';
                    document.getElementById('confirm-pw-input').value = '';
                } else {
                    setMsg('password-msg', d.error || 'Failed to update password.', false);
                }
            } catch (e) {
                setMsg('password-msg', 'Network error.', false);
            }
        });
    }

    function init() {
        if (!state.token) { window.location.href = '/patient/login'; return; }
        initThemeToggle();
        initLogout();
        initPhotoUpload();
        initDisplayName();
        initUsername();
        initPassword();
        loadProfile();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
