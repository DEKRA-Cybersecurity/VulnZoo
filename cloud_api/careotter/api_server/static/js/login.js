/* login.js — CareOtter login form handler */

(function () {
    'use strict';

    const form     = document.getElementById('login-form');
    const tokenIn  = document.getElementById('token-input');
    const btnLogin = document.getElementById('btn-login');
    const alertErr = document.getElementById('alert-error');
    const alertOk  = document.getElementById('alert-success');
    const toggleVis = document.getElementById('toggle-visibility');

    /* ── Token visibility toggle ───────────────────────────────────────────── */
    if (toggleVis) {
        toggleVis.addEventListener('click', () => {
            const isText = tokenIn.type === 'text';
            tokenIn.type = isText ? 'password' : 'text';
            toggleVis.title = isText ? 'Show token' : 'Hide token';
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

        const token = tokenIn.value.trim();
        if (!token) {
            showError('Enter the administrator token.');
            tokenIn.focus();
            return;
        }

        setLoading(true);

        try {
            const res = await fetch('/api/auth/login', {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify({ token })
            });

            const data = await res.json();

            if (!res.ok) {
                const msg = data.device_response === 'AUTH_FAIL'
                    ? 'Incorrect token. Verify the administrator token.'
                    : (data.error || `Error ${res.status}`);
                showError(msg);
                tokenIn.select();
                return;
            }

            /* Store JWT in localStorage */
            localStorage.setItem('careotter_token', data.token);
            localStorage.setItem('careotter_expires', data.expires_in || '8h');

            showSuccess('Authentication successful. Redirecting…');
            setTimeout(() => { window.location.href = '/admin/dashboard'; }, 900);

        } catch (err) {
            showError('Unable to connect to the server. Check the network.');
        } finally {
            setLoading(false);
        }
    });

    /* ── Auto-focus ────────────────────────────────────────────────────────── */
    tokenIn.focus();

    /* ── Redirect if active session exists ─────────────────────────────────── */
    if (localStorage.getItem('careotter_token')) {
        window.location.href = '/admin/dashboard';
    }
})();
