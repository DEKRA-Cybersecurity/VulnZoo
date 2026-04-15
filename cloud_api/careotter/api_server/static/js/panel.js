/* panel.js — shared utilities for all panel views */

(function () {
    'use strict';

    /* ── Auth guard ────────────────────────────────────────────────────────── */
    const token = localStorage.getItem('careotter_token');
    if (!token && !window.location.pathname.includes('/admin/login')) {
        window.location.href = '/admin/login';
    }

    /* ── Authenticated fetch helper ────────────────────────────────────────── */
    window.apiFetch = async function (url, options = {}) {
        const t = localStorage.getItem('careotter_token');
        const headers = Object.assign({
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${t}`
        }, options.headers || {});

        const res = await fetch(url, Object.assign({}, options, { headers }));

        if (res.status === 401) {
            localStorage.removeItem('careotter_token');
            window.location.href = '/admin/login';
            throw new Error('Session expired');
        }
        return res;
    };

    /* ── Logout ────────────────────────────────────────────────────────────── */
    document.querySelectorAll('.btn-logout').forEach(btn => {
        btn.addEventListener('click', () => {
            localStorage.removeItem('careotter_token');
            localStorage.removeItem('careotter_expires');
            window.location.href = '/admin/login';
        });
    });

    /* ── Mark active nav link ──────────────────────────────────────────────── */
    const path = window.location.pathname;
    document.querySelectorAll('.topbar-nav a').forEach(a => {
        if (a.getAttribute('href') === path) a.classList.add('active');
    });

})();
