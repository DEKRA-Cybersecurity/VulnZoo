/* patient_login.js — CareOtter patient portal login handler */

(function () {
    'use strict';

    const form        = document.getElementById('login-form');
    const usernameIn  = document.getElementById('username-input');
    const passwordIn  = document.getElementById('password-input');
    const btnLogin    = document.getElementById('btn-login');
    const alertErr    = document.getElementById('alert-error');
    const alertOk     = document.getElementById('alert-success');
    const toggleVis   = document.getElementById('toggle-visibility');

    /* ── Password visibility toggle ────────────────────────────────────────── */
    if (toggleVis) {
        toggleVis.addEventListener('click', () => {
            const isText = passwordIn.type === 'text';
            passwordIn.type = isText ? 'password' : 'text';
            toggleVis.title = isText ? 'Show password' : 'Hide password';
            toggleVis.querySelector('.eye-open').style.display  = isText ? 'block' : 'none';
            toggleVis.querySelector('.eye-closed').style.display = isText ? 'none'  : 'block';
        });
    }

    /* ── UI Helpers ────────────────────────────────────────────────────────── */
    function showError(msg) {
        alertErr.querySelector('.alert-msg').textContent = msg;
        alertErr.classList.add('show');
        alertOk.classList.remove('show');
    }

    function showSuccess(msg) {
        alertOk.querySelector('.alert-msg').textContent = msg;
        alertOk.classList.add('show');
        alertErr.classList.remove('show');
    }

    function setLoading(on) {
        btnLogin.disabled = on;
        btnLogin.classList.toggle('loading', on);
    }

    /* ── Submit ────────────────────────────────────────────────────────────── */
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        alertErr.classList.remove('show');
        alertOk.classList.remove('show');

        const username = usernameIn.value.trim();
        const password = passwordIn.value;
        if (!username) {
            showError('Enter your username.');
            usernameIn.focus();
            return;
        }
        if (!password) {
            showError('Enter your password.');
            passwordIn.focus();
            return;
        }

        setLoading(true);

        try {
            let res = await fetch('/api/auth/login/patient', {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify({ username, password })
            });

            let data = await res.json();

            /* Caregiver fallback: if patient login rejects with FORBIDDEN,
               try caregiver login before giving up. */
            if (!res.ok && data.code === 'FORBIDDEN') {
                res = await fetch('/api/auth/login/caregiver', {
                    method:  'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body:    JSON.stringify({ username, password })
                });
                data = await res.json();

                if (res.ok) {
                    /* Caregiver authenticated — store token and redirect */
                    localStorage.setItem('careotter_token', data.token);
                    localStorage.setItem('careotter_expires', data.expires_in || '8h');
                    showSuccess('Authentication successful. Redirecting…');
                    setTimeout(() => { window.location.href = '/caregiver/dashboard'; }, 900);
                    return;
                }
            }

            if (!res.ok) {
                const msg = data.code === 'AUTH_FAIL'
                    ? 'Invalid username or password.'
                    : data.code === 'FORBIDDEN'
                    ? 'This account does not have patient access.'
                    : (data.error || `Error ${res.status}`);
                showError(msg);
                passwordIn.select();
                return;
            }

            /* Store JWT in localStorage */
            localStorage.setItem('careotter_token', data.token);
            localStorage.setItem('careotter_expires', data.expires_in || '8h');

            showSuccess('Authentication successful. Redirecting…');
            setTimeout(() => { window.location.href = '/'; }, 900);

        } catch (err) {
            showError('Unable to connect to the server. Check the network.');
        } finally {
            setLoading(false);
        }
    });

    /* ── Auto-focus ────────────────────────────────────────────────────────── */
    usernameIn.focus();
})();

/* ── Forgot username / password helpers ──────────────────────────────────────
   Two intentional surfaces share this modal:
     1. The legacy info-disclosure hint (leaks the seeded patient's credentials).
     2. A real password-reset OTP flow (API9:2023). It posts to the external auth
        API api.careotter.lab, the SECURE mechanism (edge rate-limit + app-level
        per-account attempt cap). The forgotten beta.api.careotter.lab runs the same
        flow with NEITHER, so the 6-digit code is brute-forceable by pivoting to it.
        The legit reset goes to api. (protected); the attack is run out-of-band
        against beta.api.careotter.lab with a tool, not through this form. */
(function () {
    'use strict';

    const SEED_USER = 'john_doe';
    const SEED_PASS = 'johnny123';

    // The OTP reset is handled by the EXTERNAL authentication API, not this portal.
    // Posting here (absolute, cross-origin) makes that visible in the request — a
    // learner sees `Host: api.careotter.lab` and can pivot to fuzzing the forgotten
    // beta.api.careotter.lab, which has no rate-limit (API9). text/plain keeps it a
    // "simple" CORS request (no preflight); the API replies with Access-Control-
    // Allow-Origin. Both names must resolve in the browser (see /etc/hosts).
    const AUTH_API = 'http://api.careotter.lab';

    const overlay = document.getElementById('recovery-overlay');
    const titleEl = document.getElementById('recovery-title');
    const bodyEl  = document.getElementById('recovery-body');
    const cancel  = document.getElementById('recovery-cancel');
    const accept  = document.getElementById('recovery-accept');

    function openModal(opts) {
        titleEl.textContent = opts.title;
        bodyEl.innerHTML    = opts.body;
        cancel.textContent  = opts.cancelText || 'Close';
        if (opts.accept) {
            accept.style.display = '';
            accept.textContent = opts.acceptText || 'Accept';
            accept.onclick = () => opts.accept();
        } else {
            accept.style.display = 'none';
            accept.onclick = null;
        }
        overlay.hidden = false;
        if (typeof opts.afterOpen === 'function') opts.afterOpen();
    }

    function closeModal() {
        overlay.hidden = true;
        accept.onclick = null;
    }

    cancel.addEventListener('click', closeModal);
    overlay.addEventListener('click', (e) => { if (e.target === overlay) closeModal(); });

    function esc(s) {
        return String(s).replace(/[&<>"']/g, (c) => (
            { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
        ));
    }

    /* ── Password-reset OTP flow ─────────────────────────────────────────────── */
    function startOtpFlow() {
        openModal({
            title: 'Reset with a one-time code',
            body:
                `<p>Enter the username to send a 6-digit reset code to.</p>` +
                `<input type="text" id="otp-username" class="otp-field" ` +
                `value="${esc(SEED_USER)}" autocomplete="off" spellcheck="false">` +
                `<div class="otp-msg" id="otp-msg"></div>`,
            cancelText: 'Cancel',
            acceptText: 'Send code',
            accept: requestCode,
            afterOpen: () => { const i = document.getElementById('otp-username'); if (i) i.focus(); }
        });
    }

    async function requestCode() {
        const u = (document.getElementById('otp-username') || {}).value || '';
        const username = u.trim();
        const msg = document.getElementById('otp-msg');
        if (!username) { if (msg) msg.textContent = 'Enter a username.'; return; }
        try {
            await fetch(AUTH_API + '/api/auth/password-reset/request', {
                method:  'POST',
                headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
                body:    JSON.stringify({ username })
            });
        } catch (_) { /* generic response either way — fall through to code entry */ }
        enterCode(username, 'If the account exists, a 6-digit code has been sent.');
    }

    function enterCode(username, note) {
        openModal({
            title: 'Enter your reset code',
            body:
                (note ? `<p>${esc(note)}</p>` : '') +
                `<input type="text" id="otp-code" class="otp-field" inputmode="numeric" ` +
                `maxlength="6" placeholder="6-digit code" autocomplete="off">` +
                `<input type="password" id="otp-newpass" class="otp-field" ` +
                `placeholder="New password" autocomplete="new-password">` +
                `<div class="otp-msg" id="otp-msg"></div>`,
            cancelText: 'Cancel',
            acceptText: 'Reset password',
            accept: () => submitReset(username),
            afterOpen: () => { const i = document.getElementById('otp-code'); if (i) i.focus(); }
        });
    }

    async function submitReset(username) {
        const code = (document.getElementById('otp-code') || {}).value || '';
        const pass = (document.getElementById('otp-newpass') || {}).value || '';
        const msg  = document.getElementById('otp-msg');
        if (!code || !pass) { if (msg) msg.textContent = 'Enter the code and a new password.'; return; }
        try {
            const res = await fetch(AUTH_API + '/api/auth/password-reset/verify', {
                method:  'POST',
                headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
                body:    JSON.stringify({ username, otp: code.trim(), new_password: pass })
            });
            let data = {};
            try { data = await res.json(); } catch (_) { /* 429 from nginx is HTML */ }

            if (res.ok) {
                openModal({
                    title: 'Password updated',
                    body:  `<p>The password for <strong>${esc(username)}</strong> was reset. You can log in now.</p>`,
                    cancelText: 'Close'
                });
                return;
            }
            if (res.status === 403 && data.code === 'OTP_LOCKED') {
                enterCode(username, 'Too many attempts — this code is locked. Request a new one.');
                return;
            }
            if (res.status === 429) {
                enterCode(username, 'Too many attempts — the reset is rate-limited. Wait a moment and try again.');
                return;
            }
            enterCode(username, 'Invalid or expired code. Check it and try again.');
        } catch (_) {
            if (msg) msg.textContent = 'Unable to reach the server. Check the network.';
        }
    }

    /* ── Entry points ────────────────────────────────────────────────────────── */
    const forgotUsername = document.getElementById('forgot-username');
    const forgotPassword = document.getElementById('forgot-password');

    if (forgotUsername) {
        forgotUsername.addEventListener('click', () => {
            openModal({
                title: 'Your username',
                body:  `Your registered username is <strong>${esc(SEED_USER)}</strong>.`,
                cancelText: 'Close'
            });
        });
    }

    if (forgotPassword) {
        forgotPassword.addEventListener('click', () => {
            openModal({
                title: 'Password recovery',
                body:  `You can try getting this username password, ` +
                       `do you really want to know <strong>${esc(SEED_USER)}</strong>'s password?`,
                cancelText: 'Cancel',
                acceptText: 'Accept',
                accept: () => {
                    openModal({
                        title: `${SEED_USER}'s password`,
                        // Hidden behind a mask by default; the eye button reveals it
                        // (mirrors the login field's show/hide toggle). SEED_PASS is
                        // written to the DOM only when revealed.
                        body:  `Password: <span class="leaked-cred-wrap">` +
                               `<code class="leaked-cred" id="leaked-pw">••••••••</code>` +
                               `<button type="button" class="reveal-cred" id="reveal-pw" title="Show password" aria-label="Show password">` +
                               `<svg class="eye-open" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>` +
                               `<svg class="eye-closed" viewBox="0 0 24 24" style="display:none"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>` +
                               `</button></span>` +
                               `<br><button type="button" id="otp-start" class="otp-link">` +
                               `Reset it with a one-time code instead</button>`,
                        cancelText: 'Close',
                        afterOpen: () => {
                            const reveal = document.getElementById('reveal-pw');
                            const pw = document.getElementById('leaked-pw');
                            if (reveal && pw) {
                                let shown = false;
                                reveal.addEventListener('click', () => {
                                    shown = !shown;
                                    pw.textContent = shown ? SEED_PASS : '••••••••';
                                    reveal.title = shown ? 'Hide password' : 'Show password';
                                    reveal.setAttribute('aria-label', reveal.title);
                                    reveal.querySelector('.eye-open').style.display  = shown ? 'none'  : 'block';
                                    reveal.querySelector('.eye-closed').style.display = shown ? 'block' : 'none';
                                });
                            }
                            const b = document.getElementById('otp-start');
                            if (b) b.addEventListener('click', startOtpFlow);
                        }
                    });
                }
            });
        });
    }
})();
