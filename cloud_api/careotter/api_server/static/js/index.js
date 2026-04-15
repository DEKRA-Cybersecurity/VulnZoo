/* index.js — CareOtter Public Monitor Frontend (Simplified - No Charts) */
(function () {
    'use strict';

    // ── Configuration ─────────────────────────────────────────────────────────
    const CONFIG = {
        refreshInterval: 3000,  // 3 seconds
        deviceIp: '192.168.2.1'
    };

    // ── State ─────────────────────────────────────────────────────────────────
    const state = {
        lastUpdate: null
    };

    // ── Theme Toggle ──────────────────────────────────────────────────────────
    function initThemeToggle() {
        const btn = document.getElementById('theme-toggle');
        if (!btn) return;

        const saved = localStorage.getItem('theme');
        if (saved === 'dark') {
            document.body.classList.add('dark-mode');
        }

        btn.addEventListener('click', () => {
            const isDark = !document.body.classList.contains('dark-mode');
            document.body.classList.toggle('dark-mode', isDark);
            localStorage.setItem('theme', isDark ? 'dark' : 'light');
        });
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
        if (!data) {
            updateStatus('offline');
            return;
        }

        const bpm = data.bpm ?? null;
        const spo2 = data.spo2 ?? null;
        const irRaw = data.ir_raw ?? null;
        const redRaw = data.red_raw ?? null;
        const timestamp = data.timestamp ?? Date.now() / 1000;

        // Update BPM
        const bpmEl = document.getElementById('val-bpm');
        const bpmCard = document.getElementById('card-bpm');
        const bpmStatus = document.getElementById('status-bpm');
        const bpmBar = document.getElementById('bar-bpm');

        if (bpmEl) bpmEl.textContent = bpm !== null ? bpm : '—';

        if (bpmCard && bpm !== null) {
            bpmCard.classList.remove('ok', 'warn', 'crit');
            if (bpm < 60 || bpm > 100) {
                bpmCard.classList.add('warn');
                if (bpmStatus) bpmStatus.innerHTML = '<span class="dot"></span><span>Warning</span>';
                if (bpmStatus) bpmStatus.className = 'vital-status warn';
            } else {
                bpmCard.classList.add('ok');
                if (bpmStatus) bpmStatus.innerHTML = '<span class="dot"></span><span>Normal</span>';
                if (bpmStatus) bpmStatus.className = 'vital-status ok';
            }
            if (bpmBar) bpmBar.style.width = Math.min((bpm / 200) * 100, 100) + '%';
        }

        // Update SpO2
        const spo2El = document.getElementById('val-spo2');
        const spo2Card = document.getElementById('card-spo2');
        const spo2Status = document.getElementById('status-spo2');
        const spo2Bar = document.getElementById('bar-spo2');

        if (spo2El) spo2El.textContent = spo2 !== null ? spo2 : '—';

        if (spo2Card && spo2 !== null) {
            spo2Card.classList.remove('ok', 'warn', 'crit');
            if (spo2 < 90) {
                spo2Card.classList.add('crit');
                if (spo2Status) spo2Status.innerHTML = '<span class="dot"></span><span>Critical</span>';
                if (spo2Status) spo2Status.className = 'vital-status crit';
            } else if (spo2 < 95) {
                spo2Card.classList.add('warn');
                if (spo2Status) spo2Status.innerHTML = '<span class="dot"></span><span>Low</span>';
                if (spo2Status) spo2Status.className = 'vital-status warn';
            } else {
                spo2Card.classList.add('ok');
                if (spo2Status) spo2Status.innerHTML = '<span class="dot"></span><span>Normal</span>';
                if (spo2Status) spo2Status.className = 'vital-status ok';
            }
            if (spo2Bar) spo2Bar.style.width = spo2 + '%';
        }

        // Update Raw IR
        const irEl = document.getElementById('val-ir');
        const metaIr = document.getElementById('meta-ir');
        if (irEl) irEl.textContent = irRaw !== null ? irRaw.toLocaleString() : '—';
        if (metaIr && irRaw !== null) metaIr.textContent = `Signal strength: ${(irRaw / 65535 * 100).toFixed(1)}%`;

        // Update Raw Red
        const redEl = document.getElementById('val-red');
        const metaRed = document.getElementById('meta-red');
        if (redEl) redEl.textContent = redRaw !== null ? redRaw.toLocaleString() : '—';
        if (metaRed && redRaw !== null) metaRed.textContent = `Signal strength: ${(redRaw / 65535 * 100).toFixed(1)}%`;

        // Update timestamp
        state.lastUpdate = new Date(timestamp * 1000);
        updateLastUpdate();
        updateStatus('online');
    }

    function updateStatus(status) {
        const el = document.getElementById('device-status');
        if (!el) return;

        if (status === 'online') {
            el.textContent = 'Connected';
            el.className = 'status-value';
            el.style.color = 'var(--success)';
        } else {
            el.textContent = 'Disconnected';
            el.className = 'status-value';
            el.style.color = 'var(--danger)';
        }
    }

    function updateLastUpdate() {
        const el = document.getElementById('last-update');
        if (!el || !state.lastUpdate) return;
        el.textContent = state.lastUpdate.toLocaleTimeString();
    }

    // ── Refresh Functions ─────────────────────────────────────────────────────
    async function refreshVitals() {
        const data = await fetchVitals();
        updateVitalsDisplay(data);
    }

    // Make available globally
    window.refreshVitals = refreshVitals;

    // ── Initialization ────────────────────────────────────────────────────────
    function init() {
        initThemeToggle();
        
        // Initial load
        refreshVitals();
        
        // Set up refresh interval
        setInterval(refreshVitals, CONFIG.refreshInterval);
        setInterval(updateLastUpdate, 1000);
    }

    // Start when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
