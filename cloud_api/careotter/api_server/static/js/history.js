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
        isLoading: false
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
        });
    }

    // ── API Functions ─────────────────────────────────────────────────────────
    async function fetchHistory(hours = CONFIG.defaultHours) {
        try {
            const res = await fetch(`/api/vitals/db/history?hours=${hours}&limit=10000`);
            if (!res.ok) throw new Error('HTTP ' + res.status);
            return await res.json();
        } catch (err) {
            console.error('Failed to fetch history:', err);
            return null;
        }
    }

    async function fetchStats(hours = CONFIG.defaultHours) {
        try {
            const res = await fetch(`/api/vitals/db/stats?hours=${hours}`);
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

    function getStatusBadge(bpm, spo2) {
        const bpmAlert = bpm < 60 || bpm > 100;
        const spo2Alert = spo2 < 95;

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
                    <td colspan="7" class="empty-state">
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
                <td>${reading.bpm ?? '—'}</td>
                <td>${reading.spo2 ?? '—'}%</td>
                <td>${reading.ir_raw?.toLocaleString() ?? '—'}</td>
                <td>${reading.red_raw?.toLocaleString() ?? '—'}</td>
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
                    <td colspan="7" class="loading-row">
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

    // ── Export to CSV ──────────────────────────────────────────────────────────
    function exportToCSV() {
        if (state.filteredReadings.length === 0) {
            alert('No data to export');
            return;
        }

        const headers = ['Timestamp', 'BPM', 'SpO2', 'IR Raw', 'Red Raw', 'Source'];
        const rows = state.filteredReadings.map(r => [
            formatTimestamp(r.timestamp),
            r.bpm ?? '',
            r.spo2 ?? '',
            r.ir_raw ?? '',
            r.red_raw ?? '',
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

    // ── Initialization ────────────────────────────────────────────────────────
    function init() {
        initThemeToggle();
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
