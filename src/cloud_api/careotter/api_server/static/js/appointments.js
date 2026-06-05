/* appointments.js — CareOtter teleconsultation booking (patient panel).
 *
 * Auth follows the other patient pages: JWT from localStorage('careotter_token')
 * sent as `Authorization: Bearer` (the REST layer's @token_required reads the header).
 */
(function () {
    'use strict';

    const state = { token: localStorage.getItem('careotter_token') || '' };
    const authHeaders = (extra) => Object.assign(
        { 'Authorization': 'Bearer ' + state.token }, extra || {});

    const fmtTime = (iso) => {
        try { return new Date(iso).toLocaleString(); } catch (_) { return iso; }
    };

    function showMsg(id, text, ok) {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = text;
        el.style.display = 'block';
        el.style.color = ok ? 'var(--accent-primary)' : 'var(--danger)';
    }

    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    // ── My appointments ─────────────────────────────────────────────────────
    async function loadMine() {
        const list = document.getElementById('mine-list');
        try {
            const res = await fetch('/api/appointments/mine', { headers: authHeaders() });
            if (!res.ok) return;
            const { appointments } = await res.json();
            if (!appointments.length) {
                list.innerHTML = '<p style="color: var(--text-secondary); font-size: 0.875rem;">No appointments booked yet.</p>';
                return;
            }
            list.innerHTML = '';
            appointments.forEach((a) => {
                const row = document.createElement('div');
                row.className = 'appt-row';
                row.innerHTML =
                    '<div class="appt-when">' + escapeHtml(fmtTime(a.slot_time)) + '</div>' +
                    '<div class="appt-who"><span class="appt-clin">' + escapeHtml(a.clinician) +
                        '</span><span class="appt-spec">' + escapeHtml(a.specialty) + '</span></div>' +
                    '<button class="btn btn-ghost btn-sm appt-cancel">Cancel</button>';
                row.querySelector('.appt-cancel').addEventListener('click', () => cancel(a.id));
                list.appendChild(row);
            });
        } catch (_) { /* ignore */ }
    }

    // ── Available slots ─────────────────────────────────────────────────────
    async function loadSlots() {
        const grid = document.getElementById('slot-grid');
        try {
            const res = await fetch('/api/appointments/slots', { headers: authHeaders() });
            if (!res.ok) { grid.innerHTML = '<p>Could not load slots.</p>'; return; }
            const { slots } = await res.json();
            if (!slots.length) {
                grid.innerHTML = '<p style="color: var(--text-secondary);">No slots available — all appointments are booked.</p>';
                return;
            }
            grid.innerHTML = '';
            slots.forEach((s) => grid.appendChild(slotCard(s)));
        } catch (e) {
            grid.innerHTML = '<p>Error loading slots: ' + e.message + '</p>';
        }
    }

    function slotCard(s) {
        const card = document.createElement('div');
        card.className = 'card slot-card';
        card.innerHTML =
            '<div class="slot-when">' + escapeHtml(fmtTime(s.slot_time)) + '</div>' +
            '<div class="slot-clin">' + escapeHtml(s.clinician) + '</div>' +
            '<div class="slot-spec">' + escapeHtml(s.specialty) + '</div>' +
            '<button class="btn btn-primary btn-book">Book</button>';
        card.querySelector('.btn-book').addEventListener('click', () => book(s.id));
        return card;
    }

    async function book(slotId) {
        try {
            const res = await fetch('/api/appointments/book', {
                method: 'POST',
                headers: authHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ slot_id: slotId })
            });
            const data = await res.json();
            if (res.ok && data.ok) {
                showMsg('slots-msg', 'Booked: ' + data.slot.clinician + ' · ' +
                    fmtTime(data.slot.slot_time), true);
            } else {
                const reason = {
                    booking_limit_reached: 'You have reached your appointment limit',
                    slot_taken: 'That slot was just taken',
                    db_error: 'Server error'
                }[data.error] || ('Booking failed (' + (data.error || res.status) + ')');
                showMsg('slots-msg', reason, false);
            }
        } catch (e) {
            showMsg('slots-msg', 'Booking error: ' + e.message, false);
        } finally {
            loadSlots();
            loadMine();
        }
    }

    async function cancel(slotId) {
        try {
            const res = await fetch('/api/appointments/cancel', {
                method: 'POST',
                headers: authHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ slot_id: slotId })
            });
            const data = await res.json();
            if (res.ok && data.ok) showMsg('mine-msg', 'Appointment cancelled', true);
            else showMsg('mine-msg', 'Cancel failed: ' + (data.error || res.status), false);
        } catch (e) {
            showMsg('mine-msg', 'Cancel error: ' + e.message, false);
        } finally {
            loadSlots();
            loadMine();
        }
    }

    // ── Chrome ──────────────────────────────────────────────────────────────
    function initChrome() {
        // Match the main monitor page: toggle `body.dark-mode` (index.css defines the dark
        // variables for that class) and share the same 'theme' key so it persists across pages.
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
        loadMine();
        loadSlots();
    });
})();
