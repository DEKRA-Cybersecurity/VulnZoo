/* index.js — CareOtter Patient Monitor Frontend */
(function () {
    'use strict';

    const CONFIG = { refreshInterval: 3000 };

    const state = {
        lastUpdate: null,
        deviceMac: null,
        deviceName: null,
        token: localStorage.getItem('careotter_token') || ''
    };

    // ── Theme Toggle ──────────────────────────────────────────────────────────
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

    // ── Device Resolution ─────────────────────────────────────────────────────
    async function resolveDevice() {
        if (!state.token) return;
        try {
            const res = await fetch('/api/user/devices', {
                headers: { 'Authorization': 'Bearer ' + state.token }
            });
            if (!res.ok) return;
            const data = await res.json();
            const devices = data.devices || [];
            if (devices.length > 0) {
                state.deviceMac  = devices[0].mac;
                state.deviceName = devices[0].device_name || devices[0].mac;
                const el = document.getElementById('device-name');
                if (el) el.textContent = state.deviceName;
                const macEl = document.getElementById('device-mac');
                if (macEl) macEl.textContent = state.deviceMac;
            }
        } catch (err) {
            console.error('Failed to resolve device:', err);
        }
    }

    // ── Vitals Fetching ───────────────────────────────────────────────────────
    async function fetchVitals() {
        try {
            const res = await fetch('/api/vitals');
            if (!res.ok) throw new Error('HTTP ' + res.status);
            return await res.json();
        } catch (err) {
            console.error('Failed to fetch vitals:', err);
            return null;
        }
    }

    // ── UI Updates ────────────────────────────────────────────────────────────
    function updateVitalsDisplay(data) {
        if (!data) { updateStatus('offline'); return; }

        const bpm  = data.bpm  ?? null;
        const spo2 = data.spo2 ?? null;
        const irRaw   = data.ir_raw  ?? null;
        const redRaw  = data.red_raw ?? null;
        const timestamp = data.timestamp ?? Date.now() / 1000;

        // BPM
        const bpmEl     = document.getElementById('val-bpm');
        const bpmCard   = document.getElementById('card-bpm');
        const bpmStatus = document.getElementById('status-bpm');
        const bpmBar    = document.getElementById('bar-bpm');
        if (bpmEl) bpmEl.textContent = bpm !== null ? bpm : '—';
        if (bpmCard && bpm !== null) {
            bpmCard.classList.remove('ok', 'warn', 'crit');
            const abnormal = bpm < 60 || bpm > 100;
            bpmCard.classList.add(abnormal ? 'warn' : 'ok');
            if (bpmStatus) {
                bpmStatus.innerHTML = `<span class="dot"></span><span>${abnormal ? 'Warning' : 'Normal'}</span>`;
                bpmStatus.className = 'vital-status ' + (abnormal ? 'warn' : 'ok');
            }
            if (bpmBar) bpmBar.style.width = Math.min((bpm / 200) * 100, 100) + '%';
        }

        // SpO2
        const spo2El     = document.getElementById('val-spo2');
        const spo2Card   = document.getElementById('card-spo2');
        const spo2Status = document.getElementById('status-spo2');
        const spo2Bar    = document.getElementById('bar-spo2');
        if (spo2El) spo2El.textContent = spo2 !== null ? spo2 : '—';
        if (spo2Card && spo2 !== null) {
            spo2Card.classList.remove('ok', 'warn', 'crit');
            const cls  = spo2 < 90 ? 'crit' : spo2 < 95 ? 'warn' : 'ok';
            const label = spo2 < 90 ? 'Critical' : spo2 < 95 ? 'Low' : 'Normal';
            spo2Card.classList.add(cls);
            if (spo2Status) {
                spo2Status.innerHTML = `<span class="dot"></span><span>${label}</span>`;
                spo2Status.className = 'vital-status ' + cls;
            }
            if (spo2Bar) spo2Bar.style.width = spo2 + '%';
        }

        // Raw signals
        const irEl   = document.getElementById('val-ir');
        const metaIr = document.getElementById('meta-ir');
        if (irEl) irEl.textContent = irRaw !== null ? irRaw.toLocaleString() : '—';
        if (metaIr && irRaw !== null) metaIr.textContent = `Signal strength: ${(irRaw / 65535 * 100).toFixed(1)}%`;

        const redEl   = document.getElementById('val-red');
        const metaRed = document.getElementById('meta-red');
        if (redEl) redEl.textContent = redRaw !== null ? redRaw.toLocaleString() : '—';
        if (metaRed && redRaw !== null) metaRed.textContent = `Signal strength: ${(redRaw / 65535 * 100).toFixed(1)}%`;

        state.lastUpdate = new Date(timestamp * 1000);
        updateLastUpdate();
        updateStatus('online');
    }

    function updateStatus(status) {
        const el = document.getElementById('device-status');
        if (!el) return;
        el.textContent = status === 'online' ? 'Connected' : 'Disconnected';
        el.style.color  = status === 'online' ? 'var(--success)' : 'var(--danger)';
    }

    function updateLastUpdate() {
        const el = document.getElementById('last-update');
        if (el && state.lastUpdate) el.textContent = state.lastUpdate.toLocaleTimeString();
    }

    // ── Logout ────────────────────────────────────────────────────────────────
    function initLogout() {
        const btn = document.getElementById('btn-logout');
        if (!btn) return;
        btn.addEventListener('click', async () => {
            try { await fetch('/api/auth/logout', { method: 'POST' }); } catch (_) {}
            localStorage.removeItem('careotter_token');
            window.location.href = '/patient/login';
        });
    }

    // ── Refresh ───────────────────────────────────────────────────────────────
    async function refreshVitals() {
        const data = await fetchVitals();
        updateVitalsDisplay(data);
    }
    window.refreshVitals = refreshVitals;

    // ── Init ──────────────────────────────────────────────────────────────────
    async function init() {
        initThemeToggle();
        initLogout();
        await resolveDevice();
        refreshVitals();
        setInterval(refreshVitals, CONFIG.refreshInterval);
        setInterval(updateLastUpdate, 1000);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
