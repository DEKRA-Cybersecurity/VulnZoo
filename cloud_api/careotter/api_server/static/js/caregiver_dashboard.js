/* caregiver_dashboard.js — CareOtter Caregiver Dashboard Frontend */
(function () {
    'use strict';

    const CONFIG = { apiBase: '' };

    const state = {
        token: localStorage.getItem('careotter_token') || ''
    };

    // ── DOM refs ────────────────────────────────────────────────────────────────
    const patientSelect = document.getElementById('patient-select');
    const loadBtn       = document.getElementById('btn-load-patient');
    const alertErr     = document.getElementById('alert-error');
    const statusBar    = document.getElementById('patient-status-bar');
    const vitalsSec    = document.getElementById('vitals-section');
    const readingsSec  = document.getElementById('readings-section');
    const alertsSec    = document.getElementById('alerts-section');

    // ── Theme Toggle ────────────────────────────────────────────────────────────
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

    // ── Logout ──────────────────────────────────────────────────────────────────
    function initLogout() {
        const btn = document.getElementById('btn-logout');
        if (!btn) return;
        btn.addEventListener('click', () => {
            localStorage.removeItem('careotter_token');
            localStorage.removeItem('careotter_expires');
            window.location.href = '/patient/login';
        });
    }

    // ── UI Helpers ──────────────────────────────────────────────────────────────
    function showError(msg) {
        alertErr.querySelector('.alert-msg').textContent = msg;
        alertErr.classList.add('show');
    }

    function hideError() {
        alertErr.classList.remove('show');
    }

    function setLoading(on) {
        loadBtn.disabled = on;
        loadBtn.classList.toggle('loading', on);
    }

    function fmtDate(ts) {
        const d = new Date(ts * 1000);
        return d.toLocaleString();
    }

    function setText(id, text) {
        const el = document.getElementById(id);
        if (el) el.textContent = text;
    }

    function setBar(id, pct) {
        const el = document.getElementById(id);
        if (el) el.style.width = Math.max(0, Math.min(100, pct)) + '%';
    }

    // ── Load Assigned Patients ──────────────────────────────────────────────────
    async function loadAssignedPatients() {
        try {
            const res = await fetch('/api/caregiver/patients', {
                headers: { 'Authorization': 'Bearer ' + state.token }
            });
            if (!res.ok) {
                console.warn('Failed to load assigned patients:', res.status);
                patientSelect.innerHTML = '<option value="">-- Unable to load patients --</option>';
                patientSelect.disabled = true;
                return;
            }
            const data = await res.json();
            const patients = data.patients || [];
            if (patients.length === 0) {
                patientSelect.innerHTML = '<option value="">-- No assigned patients --</option>';
                patientSelect.disabled = true;
                return;
            }
            patientSelect.innerHTML = '<option value="">-- Select a patient --</option>';
            patients.forEach(p => {
                const opt = document.createElement('option');
                opt.value = p.patient_username;
                const deviceLabel = p.device_name || p.device_mac || 'No device';
                opt.textContent = `${p.patient_username}  (${deviceLabel})`;
                patientSelect.appendChild(opt);
            });
            patientSelect.disabled = false;
        } catch (err) {
            console.error('Error loading assigned patients:', err);
            patientSelect.innerHTML = '<option value="">-- Error loading patients --</option>';
            patientSelect.disabled = true;
        }
    }

    // ── Load Patient Data ───────────────────────────────────────────────────────
    async function loadPatient(username) {
        hideError();
        if (!username) {
            showError('Select a patient from the dropdown.');
            patientSelect.focus();
            return;
        }

        setLoading(true);
        try {
            const res = await fetch(`/api/caregiver/patient/${encodeURIComponent(username)}/vitals`, {
                headers: { 'Authorization': 'Bearer ' + state.token }
            });

            const data = await res.json();

            if (!res.ok) {
                const is404 = res.status === 404;
                const msg = is404
                    ? `Patient "${username}" has no registered device. The caregiver cannot access vitals until a device is assigned.`
                    : (data.error || `Error ${res.status}`);
                showError(msg);
                statusBar.style.display = 'none';
                vitalsSec.style.display = 'none';
                readingsSec.style.display = 'none';
                alertsSec.style.display = 'none';
                return;
            }

            renderDashboard(data);

        } catch (err) {
            showError('Unable to connect to the server.');
            console.error(err);
        } finally {
            setLoading(false);
        }
    }

    // ── Render ──────────────────────────────────────────────────────────────────
    function renderDashboard(data) {
        const device = data.device || {};
        const readings = data.readings || [];
        const alerts = data.alerts || [];

        // Status bar
        statusBar.style.display = 'flex';
        setText('patient-name', data.patient_username || '—');
        setText('device-status', device.device_name || device.mac || '—');
        setText('device-mac', device.mac || '—');

        // Vitals section
        vitalsSec.style.display = 'block';

        // Latest reading (first in array, sorted DESC)
        const latest = readings[0] || {};
        const bpm = latest.bpm ?? '—';
        const spo2 = latest.spo2 ?? '—';

        setText('val-bpm', bpm);
        setText('val-spo2', spo2);
        setText('val-readings', data.readings_count ?? readings.length);
        setText('val-alerts', data.alerts_count ?? alerts.length);

        // Bars
        setBar('bar-bpm', typeof bpm === 'number' ? (bpm / 150) * 100 : 0);
        setBar('bar-spo2', typeof spo2 === 'number' ? spo2 : 0);

        // Status dots
        updateStatus('status-bpm', bpm, 60, 100);
        updateStatus('status-spo2', spo2, 95, 100);

        // Readings table
        readingsSec.style.display = 'block';
        const rTbody = document.querySelector('#readings-table tbody');
        rTbody.innerHTML = readings.slice(0, 10).map(r => `
            <tr>
                <td>${r.timestamp ? fmtDate(r.timestamp) : '—'}</td>
                <td>${r.bpm ?? '—'}</td>
                <td>${r.spo2 ?? '—'}</td>
            </tr>
        `).join('');

        // Alerts table
        alertsSec.style.display = 'block';
        const aTbody = document.querySelector('#alerts-table tbody');
        aTbody.innerHTML = alerts.slice(0, 10).map(a => `
            <tr>
                <td>${a.timestamp ? fmtDate(a.timestamp) : '—'}</td>
                <td>${a.type ?? '—'}</td>
                <td>${a.state ?? '—'}</td>
                <td>${a.severity ?? '—'}</td>
                <td>${a.value ?? '—'}</td>
                <td>${a.threshold ?? '—'}</td>
            </tr>
        `).join('');
    }

    function updateStatus(id, value, min, max) {
        const el = document.getElementById(id);
        if (!el) return;
        const isNum = typeof value === 'number';
        const ok = isNum && value >= min && value <= max;
        el.innerHTML = `<span class="dot ${ok ? 'ok' : 'alert'}"></span><span>${ok ? 'Normal' : 'Alert'}</span>`;
    }

    // ── Event wiring ────────────────────────────────────────────────────────────
    loadBtn.addEventListener('click', () => loadPatient(patientSelect.value));
    patientSelect.addEventListener('change', () => {
        if (patientSelect.value) loadPatient(patientSelect.value);
    });

    // ── Init ────────────────────────────────────────────────────────────────────
    initThemeToggle();
    initLogout();
    loadAssignedPatients();
})();
