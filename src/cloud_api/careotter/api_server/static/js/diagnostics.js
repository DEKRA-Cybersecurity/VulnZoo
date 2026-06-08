/* diagnostics.js — CareOtter Device Diagnostics (patient panel).
 *
 * Auth follows the other patient pages: JWT from localStorage('careotter_token')
 * sent as `Authorization: Bearer`. The check posts the registered device's
 * diagnostics URL as `probe_url`; the server fetches it and reflects the status + body.
 */
(function () {
    'use strict';

    const state = { token: localStorage.getItem('careotter_token') || '' };
    const authHeaders = (extra) => Object.assign(
        { 'Authorization': 'Bearer ' + state.token }, extra || {});

    const urlInput   = document.getElementById('probe-url');
    const probeBtn   = document.getElementById('btn-probe');
    const resultEl   = document.getElementById('diag-result');
    const friendlyEl = document.getElementById('diag-friendly');
    const rawEl      = document.getElementById('diag-raw');
    const statusEl   = document.getElementById('diag-status');
    const bodyEl     = document.getElementById('diag-body');

    function showMsg(text, ok) {
        const el = document.getElementById('diag-msg');
        if (!el) return;
        el.textContent = text;
        el.style.display = 'block';
        el.style.color = ok ? 'var(--accent-primary)' : 'var(--danger)';
    }

    async function probe() {
        const probe_url = (urlInput.value || '').trim();
        if (!probe_url) { showMsg('No registered device to check.', false); return; }
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
                showMsg('Device responded successfully.', true);
                renderResult(data);
                resultEl.style.display = 'block';
            } else {
                const reason = {
                    host_not_allowed: 'That host is not one of your registered devices.',
                    no_device: 'Register your device first to run diagnostics.',
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

    // ── Result rendering ─────────────────────────────────────────────────────
    // A normal device health report becomes a friendly "Device online" summary.
    // Anything else (e.g. an internal endpoint's reply) falls back to the raw
    // reflected status + body so technical responses are still inspectable.
    function renderResult(data) {
        const health = parseHealth(data.body);
        if (health) {
            fillFriendly(health);
            friendlyEl.style.display = 'block';
            rawEl.style.display = 'none';
        } else {
            statusEl.textContent = 'HTTP ' + (data.status != null ? data.status : '—');
            bodyEl.textContent = data.body || '(empty body)';
            friendlyEl.style.display = 'none';
            rawEl.style.display = 'block';
        }
    }

    function parseHealth(body) {
        if (!body) return null;
        let obj;
        try { obj = JSON.parse(body); } catch (_) { return null; }
        if (!obj || typeof obj !== 'object') return null;
        // Distinctive shape of the sensor /health report.
        return (obj.status === 'ok' && typeof obj.service === 'string') ? obj : null;
    }

    function fillFriendly(h) {
        const ip   = h.wifi_ip || h.wlan0_ip || h.eth0_ip || '';
        const kind = (h.wifi_ip || h.wlan0_ip) ? 'Wi-Fi' : (h.eth0_ip ? 'Ethernet' : '');
        setText('info-status',  'Online');
        setText('info-network', ip ? (kind ? kind + ' · ' + ip : ip) : '—');
        setText('info-mac',     h.mac || '—');
        setText('info-uptime',  formatReport(h.uptime));
    }

    // The sensor reports `uptime` as a Unix epoch (its clock at reply time);
    // show it as a local timestamp. A small value is treated as an uptime
    // duration instead, so the field is robust to either convention.
    function formatReport(v) {
        const n = Number(v);
        if (!n || !isFinite(n)) return '—';
        if (n > 1e9) {
            try { return new Date(n * 1000).toLocaleString(); } catch (_) { return '—'; }
        }
        const d = Math.floor(n / 86400), hh = Math.floor((n % 86400) / 3600), mm = Math.floor((n % 3600) / 60);
        return (d ? d + 'd ' : '') + (hh ? hh + 'h ' : '') + mm + 'm';
    }

    function setText(id, text) {
        const el = document.getElementById(id);
        if (el) el.textContent = text;
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
    });
})();
