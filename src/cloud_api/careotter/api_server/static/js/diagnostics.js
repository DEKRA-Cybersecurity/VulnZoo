/* diagnostics.js — CareOtter Device Diagnostics (patient panel).
 *
 * Auth follows the other patient pages: JWT from localStorage('careotter_token')
 * sent as `Authorization: Bearer`. The probe URL is sent verbatim as `probe_url`;
 * the server fetches it and reflects the upstream status + body.
 */
(function () {
    'use strict';

    const state = { token: localStorage.getItem('careotter_token') || '' };
    const authHeaders = (extra) => Object.assign(
        { 'Authorization': 'Bearer ' + state.token }, extra || {});

    const urlInput  = document.getElementById('probe-url');
    const probeBtn  = document.getElementById('btn-probe');
    const resultEl  = document.getElementById('diag-result');
    const statusEl  = document.getElementById('diag-status');
    const bodyEl    = document.getElementById('diag-body');

    function showMsg(text, ok) {
        const el = document.getElementById('diag-msg');
        if (!el) return;
        el.textContent = text;
        el.style.display = 'block';
        el.style.color = ok ? 'var(--accent-primary)' : 'var(--danger)';
    }

    async function probe() {
        const probe_url = (urlInput.value || '').trim();
        if (!probe_url) { showMsg('Enter a device diagnostics URL.', false); return; }
        showMsg('Probing…', true);
        resultEl.style.display = 'none';
        probeBtn.disabled = true;
        try {
            const res = await fetch('/api/device/diagnostics', {
                method: 'POST',
                headers: authHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ probe_url })
            });
            const data = await res.json();
            if (res.ok && data.ok) {
                showMsg('Fetched ' + (data.fetched || probe_url), true);
                statusEl.textContent = 'HTTP ' + data.status;
                bodyEl.textContent = data.body || '(empty body)';
                resultEl.style.display = 'block';
            } else {
                const reason = {
                    host_not_allowed: 'That host is not a registered device.',
                    invalid_url: 'Invalid URL.',
                    fetch_failed: 'Could not reach the device.'
                }[data.error] || ('Diagnostics failed (' + (data.error || res.status) + ')');
                showMsg(reason, false);
            }
        } catch (e) {
            showMsg('Diagnostics error: ' + e.message, false);
        } finally {
            probeBtn.disabled = false;
        }
    }

    // ── Chrome (theme + logout), matching the other patient pages ────────────
    function initChrome() {
        const themeBtn = document.getElementById('theme-toggle');
        if (localStorage.getItem('theme') === 'dark') document.body.classList.add('dark-mode');
        if (themeBtn) themeBtn.addEventListener('click', () => {
            const isDark = !document.body.classList.contains('dark-mode');
            document.body.classList.toggle('dark-mode', isDark);
            localStorage.setItem('theme', isDark ? 'dark' : 'light');
        });
        const logoutBtn = document.getElementById('btn-logout');
        if (logoutBtn) logoutBtn.addEventListener('click', async () => {
            try { await fetch('/api/auth/logout', { method: 'POST' }); } catch (_) {}
            localStorage.removeItem('careotter_token');
            window.location.href = '/patient/login';
        });
    }

    document.addEventListener('DOMContentLoaded', () => {
        initChrome();
        if (probeBtn) probeBtn.addEventListener('click', probe);
        if (urlInput) urlInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') probe();
        });
    });
})();
