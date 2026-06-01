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
                showDeviceManagement();
            } else {
                showNoDevice();
            }
        } catch (err) {
            console.error('Failed to resolve device:', err);
        }
    }

    function showDeviceManagement() {
        const mgmt = document.getElementById('device-management');
        if (mgmt) mgmt.style.display = 'block';
        const noDev = document.getElementById('no-device-message');
        if (noDev) noDev.style.display = 'none';
        const vitalsSec = document.querySelector('.vitals-section');
        if (vitalsSec) vitalsSec.style.display = 'block';
        const histSec = document.querySelectorAll('.history-link-section');
        histSec.forEach(s => s.style.display = 'block');
        const nameEl = document.getElementById('mgmt-device-name');
        const macEl = document.getElementById('mgmt-device-mac');
        if (nameEl) nameEl.textContent = state.deviceName || '—';
        if (macEl) macEl.textContent = state.deviceMac || '';
    }

    function showNoDevice() {
        const mgmt = document.getElementById('device-management');
        if (mgmt) mgmt.style.display = 'none';
        const container = document.getElementById('no-device-message');
        if (container) container.style.display = 'block';
        const vitalsSec = document.querySelector('.vitals-section');
        if (vitalsSec) vitalsSec.style.display = 'none';
        const histSec = document.querySelectorAll('.history-link-section');
        histSec.forEach(s => s.style.display = 'none');
        updateStatus('no-device');
        initRegisterByHash();
    }

    function initRegisterByHash() {
        const btn = document.getElementById('btn-register-hash');
        if (!btn) return;
        btn.addEventListener('click', async () => {
            const input = document.getElementById('device-hash-input');
            const errEl = document.getElementById('register-hash-error');
            const hash = (input ? input.value : '').trim();
            if (!hash) {
                if (errEl) { errEl.textContent = 'Please enter a device hash.'; errEl.style.display = 'block'; }
                return;
            }
            try {
                const res = await fetch('/api/devices/register-by-hash', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + state.token
                    },
                    body: JSON.stringify({ device_hash: hash })
                });
                if (res.ok) {
                    window.location.reload();
                } else {
                    const data = await res.json().catch(() => ({}));
                    if (errEl) {
                        errEl.textContent = data.error || 'Registration failed. Check your code and try again.';
                        errEl.style.display = 'block';
                    }
                }
            } catch (e) {
                if (errEl) { errEl.textContent = 'Network error. Please try again.'; errEl.style.display = 'block'; }
            }
        });
    }

    // ── Vitals Fetching ───────────────────────────────────────────────────────
    async function fetchVitals() {
        try {
            const res = await fetch('/api/vitals');
            if (res.status === 404) {
                // No data yet from the device — return a sentinel so the UI
                // shows the vitals grid with placeholders instead of treating
                // it as a fatal error.
                return { _noData: true };
            }
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
        if (data._noData) { updateStatus('online'); return; }

        const bpm  = data.bpm  ?? null;
        const spo2 = data.spo2 ?? null;
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

        state.lastUpdate = new Date(timestamp * 1000);
        updateLastUpdate();
        updateStatus('online');
    }

    function updateStatus(status) {
        const el = document.getElementById('device-status');
        if (!el) return;
        if (status === 'online') {
            el.textContent = 'Connected';
            el.style.color = 'var(--success)';
        } else if (status === 'no-device') {
            el.textContent = 'No device registered';
            el.style.color = 'var(--warning, #f59e0b)';
        } else {
            el.textContent = 'Disconnected';
            el.style.color = 'var(--danger)';
        }
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

    // ── Caregiver Management ──────────────────────────────────────────────────
    async function loadCaregivers() {
        const listEl = document.getElementById('caregivers-list');
        const msgEl = document.getElementById('caregiver-msg');
        if (!listEl) return;
        try {
            const res = await fetch('/api/patient/caregivers', {
                headers: { 'Authorization': 'Bearer ' + state.token }
            });
            if (!res.ok) return;
            const data = await res.json();
            const caregivers = data.caregivers || [];
            if (caregivers.length === 0) {
                listEl.innerHTML = '<p style="color: var(--text-secondary); font-size: 0.875rem;">No caregivers assigned yet.</p>';
                return;
            }
            listEl.innerHTML = '<table class="data-table" style="font-size: 0.875rem;"><thead><tr><th>Username</th><th>Assigned</th><th></th></tr></thead><tbody>' +
                caregivers.map(c => `
                    <tr data-cg="${c.caregiver_username}">
                        <td>${c.caregiver_username}</td>
                        <td>${new Date(c.created_at).toLocaleDateString()}</td>
                        <td><button class="btn btn-ghost btn-sm btn-remove-cg" data-cg="${c.caregiver_username}" style="padding: 0.25rem 0.5rem; font-size: 0.75rem; color: var(--danger);">Remove</button></td>
                    </tr>
                `).join('') +
                '</tbody></table>';
            listEl.querySelectorAll('.btn-remove-cg').forEach(btn => {
                btn.addEventListener('click', () => removeCaregiver(btn.dataset.cg));
            });
        } catch (err) {
            console.error('Failed to load caregivers:', err);
        }
    }

    async function addCaregiver() {
        const input = document.getElementById('add-caregiver-input');
        const msgEl = document.getElementById('caregiver-msg');
        const username = (input ? input.value : '').trim();
        if (!username) {
            if (msgEl) { msgEl.textContent = 'Please enter a caregiver username.'; msgEl.style.color = 'var(--danger)'; msgEl.style.display = 'block'; }
            return;
        }
        try {
            const res = await fetch('/api/patient/caregivers', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + state.token
                },
                body: JSON.stringify({ caregiver_username: username })
            });
            const data = await res.json();
            if (res.ok) {
                if (input) input.value = '';
                if (msgEl) { msgEl.textContent = 'Caregiver added successfully.'; msgEl.style.color = 'var(--success)'; msgEl.style.display = 'block'; }
                loadCaregivers();
            } else {
                if (msgEl) { msgEl.textContent = data.error || 'Failed to add caregiver.'; msgEl.style.color = 'var(--danger)'; msgEl.style.display = 'block'; }
            }
        } catch (e) {
            if (msgEl) { msgEl.textContent = 'Network error. Please try again.'; msgEl.style.color = 'var(--danger)'; msgEl.style.display = 'block'; }
        }
    }

    async function removeCaregiver(caregiverUsername) {
        const msgEl = document.getElementById('caregiver-msg');
        try {
            const res = await fetch('/api/patient/caregivers/' + encodeURIComponent(caregiverUsername), {
                method: 'DELETE',
                headers: { 'Authorization': 'Bearer ' + state.token }
            });
            if (res.ok) {
                if (msgEl) { msgEl.textContent = 'Caregiver removed.'; msgEl.style.color = 'var(--success)'; msgEl.style.display = 'block'; }
                loadCaregivers();
            } else {
                const data = await res.json().catch(() => ({}));
                if (msgEl) { msgEl.textContent = data.error || 'Failed to remove caregiver.'; msgEl.style.color = 'var(--danger)'; msgEl.style.display = 'block'; }
            }
        } catch (e) {
            if (msgEl) { msgEl.textContent = 'Network error.'; msgEl.style.color = 'var(--danger)'; msgEl.style.display = 'block'; }
        }
    }

    function initDeviceManagement() {
        const btn = document.getElementById('btn-unregister-device');
        if (!btn) return;
        btn.addEventListener('click', async () => {
            if (!confirm('Are you sure you want to unregister this device? You will need to enter a new registration code to link another device.')) return;
            try {
                const res = await fetch('/api/devices/me', {
                    method: 'DELETE',
                    headers: { 'Authorization': 'Bearer ' + state.token }
                });
                if (res.ok) {
                    window.location.reload();
                } else {
                    const data = await res.json().catch(() => ({}));
                    alert(data.error || 'Failed to unregister device.');
                }
            } catch (e) {
                alert('Network error. Please try again.');
            }
        });
    }

    function initCaregiverManagement() {
        const btn = document.getElementById('btn-add-caregiver');
        const input = document.getElementById('add-caregiver-input');
        if (btn) btn.addEventListener('click', addCaregiver);
        if (input) input.addEventListener('keydown', (e) => { if (e.key === 'Enter') addCaregiver(); });
    }

    // ── Init ──────────────────────────────────────────────────────────────────
    async function init() {
        initThemeToggle();
        initLogout();
        initDeviceManagement();
        initCaregiverManagement();
        await resolveDevice();
        refreshVitals();
        loadCaregivers();
        setInterval(refreshVitals, CONFIG.refreshInterval);
        setInterval(updateLastUpdate, 10000);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
