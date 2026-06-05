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

/* ── Forgot username / password helpers — intentional info-disclosure flow ── */
(function () {
    'use strict';

    const SEED_USER = 'john_doe';
    const SEED_PASS = 'johnny123';

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
    }

    function closeModal() {
        overlay.hidden = true;
        accept.onclick = null;
    }

    cancel.addEventListener('click', closeModal);
    overlay.addEventListener('click', (e) => { if (e.target === overlay) closeModal(); });

    const forgotUsername = document.getElementById('forgot-username');
    const forgotPassword = document.getElementById('forgot-password');

    if (forgotUsername) {
        forgotUsername.addEventListener('click', () => {
            openModal({
                title: 'Your username',
                body:  `Your registered username is <strong>${SEED_USER}</strong>.`,
                cancelText: 'Close'
            });
        });
    }

    if (forgotPassword) {
        forgotPassword.addEventListener('click', () => {
            openModal({
                title: 'Password recovery',
                body:  `You can try getting this username password, ` +
                       `do you really want to know <strong>${SEED_USER}</strong>'s password?`,
                cancelText: 'Cancel',
                acceptText: 'Accept',
                accept: () => {
                    openModal({
                        title: `${SEED_USER}'s password`,
                        body:  `Password: <code class="leaked-cred">${SEED_PASS}</code>`,
                        cancelText: 'Close'
                    });
                }
            });
        });
    }
})();
