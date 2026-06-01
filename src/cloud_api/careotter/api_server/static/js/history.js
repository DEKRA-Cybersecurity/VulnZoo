/* history.js — CareOtter History Page Frontend */
(function () {
    'use strict';

    // ── Configuration ─────────────────────────────────────────────────────────
    const CONFIG = {
        apiBase: '',
        defaultHours: 24,
        defaultRowsPerPage: 50
    };

    // ── State ─────────────────────────────────────────────────────────────────
    const state = {
        readings: [],
        filteredReadings: [],
        currentPage: 1,
        rowsPerPage: CONFIG.defaultRowsPerPage,
        totalCount: 0,
        isLoading: false,
        chartBpm: null,
        chartSpo2: null,
        deviceMac: null,
        deviceName: null,
        token: localStorage.getItem('careotter_token') || ''
    };

    // ── Theme Toggle ──────────────────────────────────────────────────────────
    function initThemeToggle() {
        const btn = document.getElementById('theme-toggle');
        if (!btn) return;

        // Load saved preference
        const saved = localStorage.getItem('theme');
        if (saved === 'dark') {
            document.body.classList.add('dark-mode');
        }

        btn.addEventListener('click', () => {
            const isDark = !document.body.classList.contains('dark-mode');
            document.body.classList.toggle('dark-mode', isDark);
            localStorage.setItem('theme', isDark ? 'dark' : 'light');
            // Redraw charts with updated grid/label colors
            renderCharts(state.filteredReadings);
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
                const nameEl = document.getElementById('device-name');
                if (nameEl) nameEl.textContent = state.deviceName;
                const macEl = document.getElementById('device-mac');
                if (macEl) macEl.textContent = state.deviceMac;
            }
        } catch (err) {
            console.error('Failed to resolve device:', err);
        }
    }

    // ── API Functions ─────────────────────────────────────────────────────────
    async function fetchHistory(hours = CONFIG.defaultHours) {
        try {
            let url = `/api/vitals/db/history?hours=${hours}&limit=10000`;
            if (state.deviceMac) url += `&device_mac=${encodeURIComponent(state.deviceMac)}`;
            const res = await fetch(url);
            if (!res.ok) throw new Error('HTTP ' + res.status);
            return await res.json();
        } catch (err) {
            console.error('Failed to fetch history:', err);
            return null;
        }
    }

    async function fetchStats(hours = CONFIG.defaultHours) {
        try {
            let url = `/api/vitals/db/stats?hours=${hours}`;
            if (state.deviceMac) url += `&device_mac=${encodeURIComponent(state.deviceMac)}`;
            const res = await fetch(url);
            if (!res.ok) throw new Error('HTTP ' + res.status);
            return await res.json();
        } catch (err) {
            console.error('Failed to fetch stats:', err);
            return null;
        }
    }

    // ── UI Updates ────────────────────────────────────────────────────────────
    function updateStats(stats) {
        if (!stats) return;

        // BPM stats
        const bpmEl = document.getElementById('stat-avg-bpm');
        const bpmMinEl = document.getElementById('stat-min-bpm');
        const bpmMaxEl = document.getElementById('stat-max-bpm');

        if (bpmEl) bpmEl.textContent = stats.bpm.avg ?? '—';
        if (bpmMinEl) bpmMinEl.textContent = stats.bpm.min ?? '—';
        if (bpmMaxEl) bpmMaxEl.textContent = stats.bpm.max ?? '—';

        // SpO2 stats
        const spo2El = document.getElementById('stat-avg-spo2');
        const spo2MinEl = document.getElementById('stat-min-spo2');
        const spo2MaxEl = document.getElementById('stat-max-spo2');

        if (spo2El) spo2El.textContent = stats.spo2.avg ?? '—';
        if (spo2MinEl) spo2MinEl.textContent = stats.spo2.min ?? '—';
        if (spo2MaxEl) spo2MaxEl.textContent = stats.spo2.max ?? '—';

        // Total readings
        const totalEl = document.getElementById('stat-total');
        if (totalEl) totalEl.textContent = stats.total_readings?.toLocaleString() ?? '—';

        // Period
        const periodEl = document.getElementById('stat-period');
        if (periodEl) periodEl.textContent = `Last ${stats.period_hours} hours`;

        // Alerts
        const alertsEl = document.getElementById('stat-alerts');
        const bpmAlertsEl = document.getElementById('stat-bpm-alerts');
        const spo2AlertsEl = document.getElementById('stat-spo2-alerts');

        const totalAlerts = (stats.alerts?.bpm || 0) + (stats.alerts?.spo2 || 0);
        if (alertsEl) alertsEl.textContent = totalAlerts;
        if (bpmAlertsEl) bpmAlertsEl.textContent = stats.alerts?.bpm || 0;
        if (spo2AlertsEl) spo2AlertsEl.textContent = stats.alerts?.spo2 || 0;
    }

    function formatTimestamp(timestamp) {
        if (!timestamp) return '—';
        const date = new Date(timestamp * 1000);
        return date.toLocaleString();
    }

    function getThresholds() {
        return (typeof window !== 'undefined' && window.THRESHOLDS)
            ? window.THRESHOLDS
            : { bpm_min: 60, bpm_max: 100, spo2_min: 95 };
    }

    function getStatusBadge(bpm, spo2) {
        const thr = getThresholds();
        const bpmAlert = bpm < thr.bpm_min || bpm > thr.bpm_max;
        const spo2Alert = spo2 < thr.spo2_min;

        if (bpmAlert || spo2Alert) {
            if (spo2Alert && spo2 < 90) {
                return '<span class="status-badge status-crit">Critical</span>';
            }
            return '<span class="status-badge status-warn">Warning</span>';
        }
        return '<span class="status-badge status-ok">Normal</span>';
    }

    function renderTable() {
        const tbody = document.getElementById('table-body');
        const tableInfo = document.getElementById('table-info');
        
        if (!tbody) return;

        // Calculate pagination
        const start = (state.currentPage - 1) * state.rowsPerPage;
        const end = start + state.rowsPerPage;
        const pageData = state.filteredReadings.slice(start, end);
        const totalPages = Math.ceil(state.filteredReadings.length / state.rowsPerPage);

        // Update info
        if (tableInfo) {
            tableInfo.textContent = `Showing ${Math.min(start + 1, state.filteredReadings.length)}-${Math.min(end, state.filteredReadings.length)} of ${state.filteredReadings.length} readings`;
        }

        // Clear table
        tbody.innerHTML = '';

        // Empty state
        if (pageData.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="9" class="empty-state">
                        <svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/></svg>
                        <h4>No data available</h4>
                        <p>No readings found for the selected time range.</p>
                    </td>
                </tr>
            `;
            updatePagination(0, 0);
            return;
        }

        // Render rows
        pageData.forEach(reading => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${formatTimestamp(reading.timestamp)}</td>
                <td><span class="source-badge">${reading.patient_username || '—'}</span></td>
                <td><code>${reading.device_mac || '—'}</code></td>
                <td>${reading.bpm ?? '—'}</td>
                <td>${reading.spo2 ?? '—'}%</td>
                <td><span class="source-badge">${reading.source || 'unknown'}</span></td>
                <td>${getStatusBadge(reading.bpm, reading.spo2)}</td>
            `;
            tbody.appendChild(row);
        });

        updatePagination(state.currentPage, totalPages);
    }

    function updatePagination(current, total) {
        const prevBtn = document.getElementById('prev-page');
        const nextBtn = document.getElementById('next-page');
        const pageInfo = document.getElementById('page-info');

        if (prevBtn) prevBtn.disabled = current <= 1;
        if (nextBtn) nextBtn.disabled = current >= total || total === 0;
        if (pageInfo) pageInfo.textContent = total > 0 ? `Page ${current} of ${total}` : 'No data';
    }

    // ── Data Loading ───────────────────────────────────────────────────────────
    async function loadData() {
        if (state.isLoading) return;
        
        state.isLoading = true;
        const timeRange = document.getElementById('time-range');
        const hours = timeRange ? parseInt(timeRange.value) : CONFIG.defaultHours;

        // Show loading state
        const tbody = document.getElementById('table-body');
        if (tbody) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="9" class="loading-row">
                        <span class="spin-sm"></span>
                        Loading data...
                    </td>
                </tr>
            `;
        }

        // Fetch data
        const [historyData, statsData] = await Promise.all([
            fetchHistory(hours),
            fetchStats(hours)
        ]);

        if (historyData && historyData.readings) {
            state.readings = historyData.readings;
            state.filteredReadings = [...state.readings];
            state.totalCount = historyData.total_count || 0;
            state.currentPage = 1;
        } else {
            state.readings = [];
            state.filteredReadings = [];
            state.totalCount = 0;
        }

        updateStats(statsData);
        renderCharts(state.filteredReadings);
        renderTable();

        state.isLoading = false;
    }

    // ── Event Handlers ────────────────────────────────────────────────────────
    function initEventHandlers() {
        // Time range filter
        const timeRange = document.getElementById('time-range');
        if (timeRange) {
            timeRange.addEventListener('change', () => {
                loadData();
            });
        }

        // Rows per page
        const rowsPerPage = document.getElementById('rows-per-page');
        if (rowsPerPage) {
            rowsPerPage.addEventListener('change', (e) => {
                state.rowsPerPage = parseInt(e.target.value);
                state.currentPage = 1;
                renderTable();
            });
        }

        // Refresh button
        const refreshBtn = document.getElementById('refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                loadData();
            });
        }

        // Export button
        const exportBtn = document.getElementById('export-btn');
        if (exportBtn) {
            exportBtn.addEventListener('click', exportToCSV);
        }

        // Pagination
        const prevBtn = document.getElementById('prev-page');
        const nextBtn = document.getElementById('next-page');

        if (prevBtn) {
            prevBtn.addEventListener('click', () => {
                if (state.currentPage > 1) {
                    state.currentPage--;
                    renderTable();
                }
            });
        }

        if (nextBtn) {
            nextBtn.addEventListener('click', () => {
                const totalPages = Math.ceil(state.filteredReadings.length / state.rowsPerPage);
                if (state.currentPage < totalPages) {
                    state.currentPage++;
                    renderTable();
                }
            });
        }
    }

    // ── Charts ────────────────────────────────────────────────────────────────
    function buildChartData(readings) {
        // Downsample to at most 300 points so charts stay readable
        const MAX_POINTS = 300;
        const sorted = [...readings].reverse(); // oldest → newest
        const step = Math.max(1, Math.floor(sorted.length / MAX_POINTS));
        const sampled = sorted.filter((_, i) => i % step === 0);

        return {
            labels: sampled.map(r => {
                const d = new Date(r.timestamp * 1000);
                return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            }),
            bpm:  sampled.map(r => r.bpm  ?? null),
            spo2: sampled.map(r => r.spo2 ?? null)
        };
    }

    function renderCharts(readings) {
        if (typeof Chart === 'undefined') return;
        const isDark = document.body.classList.contains('dark-mode');
        const gridColor  = isDark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)';
        const labelColor = isDark ? '#94a3b8' : '#64748b';

        const { labels, bpm, spo2 } = buildChartData(readings);
        const thr = getThresholds();

        const commonOptions = (yLabel, yMin, yMax) => ({
            responsive: true,
            maintainAspectRatio: true,
            animation: { duration: 300 },
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: { display: false },
                tooltip: { callbacks: { label: ctx => ` ${ctx.parsed.y} ${yLabel}` } }
            },
            scales: {
                x: {
                    ticks: { color: labelColor, maxTicksLimit: 8, maxRotation: 0 },
                    grid:  { color: gridColor }
                },
                y: {
                    min: yMin, max: yMax,
                    ticks: { color: labelColor },
                    grid:  { color: gridColor },
                    title: { display: true, text: yLabel, color: labelColor }
                }
            }
        });

        // BPM chart
        const ctxBpm = document.getElementById('chart-bpm');
        if (ctxBpm) {
            if (state.chartBpm) state.chartBpm.destroy();
            state.chartBpm = new Chart(ctxBpm, {
                type: 'line',
                data: {
                    labels,
                    datasets: [
                        {
                            label: 'Normal range',
                            data: labels.map(() => thr.bpm_max),
                            borderColor: 'transparent',
                            backgroundColor: 'rgba(229,57,53,0.08)',
                            fill: '+1',
                            pointRadius: 0,
                            tension: 0
                        },
                        {
                            label: 'Normal range low',
                            data: labels.map(() => thr.bpm_min),
                            borderColor: 'rgba(229,57,53,0.3)',
                            borderDash: [4, 4],
                            backgroundColor: 'transparent',
                            pointRadius: 0,
                            tension: 0
                        },
                        {
                            label: 'BPM',
                            data: bpm,
                            borderColor: '#E53935',
                            backgroundColor: 'rgba(229,57,53,0.15)',
                            fill: false,
                            pointRadius: 0,
                            pointHoverRadius: 4,
                            tension: 0.3,
                            borderWidth: 2
                        }
                    ]
                },
                options: commonOptions('BPM', 30, 160)
            });
        }

        // SpO2 chart
        const ctxSpo2 = document.getElementById('chart-spo2');
        if (ctxSpo2) {
            if (state.chartSpo2) state.chartSpo2.destroy();
            state.chartSpo2 = new Chart(ctxSpo2, {
                type: 'line',
                data: {
                    labels,
                    datasets: [
                        {
                            label: 'Critical threshold',
                            data: labels.map(() => thr.spo2_min),
                            borderColor: 'rgba(239,68,68,0.6)',
                            borderDash: [4, 4],
                            backgroundColor: 'transparent',
                            pointRadius: 0,
                            tension: 0
                        },
                        {
                            label: 'SpO₂',
                            data: spo2,
                            borderColor: '#1E88E5',
                            backgroundColor: 'rgba(30,136,229,0.12)',
                            fill: false,
                            pointRadius: 0,
                            pointHoverRadius: 4,
                            tension: 0.3,
                            borderWidth: 2
                        }
                    ]
                },
                options: commonOptions('%', 80, 101)
            });
        }
    }

    // ── Export to CSV ──────────────────────────────────────────────────────────
    function exportToCSV() {
        if (state.filteredReadings.length === 0) {
            alert('No data to export');
            return;
        }

        const headers = ['Timestamp', 'Patient', 'Device MAC', 'BPM', 'SpO2', 'Source'];
        const rows = state.filteredReadings.map(r => [
            formatTimestamp(r.timestamp),
            r.patient_username || '',
            r.device_mac || '',
            r.bpm ?? '',
            r.spo2 ?? '',
            r.source || 'unknown'
        ]);

        const csvContent = [
            headers.join(','),
            ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
        ].join('\n');

        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `careotter-vitals-${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
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

    // ── Initialization ────────────────────────────────────────────────────────
    async function init() {
        initThemeToggle();
        initLogout();
        await resolveDevice();
        initEventHandlers();
        loadData();
    }

    // Start when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
