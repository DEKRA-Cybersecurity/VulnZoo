/* store.js — CareOtter Health Store (patient purchase panel).
 *
 * Authenticates API calls the same way the other patient pages do: the JWT is
 * read from localStorage('careotter_token') and sent as `Authorization: Bearer`,
 * because the REST layer's @token_required reads the header (not the cookie).
 */
(function () {
    'use strict';

    const state = {
        token: localStorage.getItem('careotter_token') || ''
    };

    const authHeaders = (extra) => Object.assign(
        { 'Authorization': 'Bearer ' + state.token }, extra || {});

    const money = (n) => '$' + Number(n).toLocaleString(undefined, {
        minimumFractionDigits: 2, maximumFractionDigits: 2 });

    function showMsg(id, text, ok) {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = text;
        el.style.display = 'block';
        el.style.color = ok ? 'var(--accent-primary)' : 'var(--danger)';
    }

    // ── Wallet ──────────────────────────────────────────────────────────────
    async function loadWallet() {
        try {
            const res = await fetch('/api/store/wallet', { headers: authHeaders() });
            if (!res.ok) return;
            const { wallet } = await res.json();
            document.getElementById('wallet-balance').textContent = money(wallet.balance);
            document.getElementById('wallet-balance-badge').textContent = money(wallet.balance);
        } catch (_) { /* ignore */ }
    }

    // ── Catalog ─────────────────────────────────────────────────────────────
    async function loadProducts() {
        const grid = document.getElementById('product-grid');
        try {
            const res = await fetch('/api/store/products', { headers: authHeaders() });
            if (!res.ok) { grid.innerHTML = '<p>Could not load products.</p>'; return; }
            const { products } = await res.json();
            if (!products.length) { grid.innerHTML = '<p>No products available.</p>'; return; }
            grid.innerHTML = '';
            products.forEach((p) => grid.appendChild(productCard(p)));
        } catch (e) {
            grid.innerHTML = '<p>Error loading products: ' + e.message + '</p>';
        }
    }

    function productCard(p) {
        const card = document.createElement('div');
        card.className = 'card product-card';
        const rx = p.requires_prescription
            ? '<span class="rx-badge">Rx</span>' : '';
        const outOfStock = p.stock <= 0;
        card.innerHTML =
            '<div class="product-head">' +
                '<span class="product-name">' + escapeHtml(p.name) + '</span>' + rx +
            '</div>' +
            '<div class="product-cat">' + escapeHtml(p.category || '') + '</div>' +
            '<p class="product-desc">' + escapeHtml(p.description || '') + '</p>' +
            '<div class="product-foot">' +
                '<span class="product-price">' + money(p.price) + '</span>' +
                '<span class="product-stock">' + (outOfStock
                    ? 'Out of stock' : ('Stock: ' + p.stock)) + '</span>' +
            '</div>' +
            '<div class="product-buy">' +
                '<input type="number" min="1" value="1" class="qty-input" ' +
                    (outOfStock ? 'disabled' : '') + '>' +
                '<button class="btn btn-primary btn-buy" ' +
                    (outOfStock ? 'disabled' : '') + '>Buy</button>' +
            '</div>';
        const buyBtn = card.querySelector('.btn-buy');
        const qty = card.querySelector('.qty-input');
        if (buyBtn) buyBtn.addEventListener('click',
            () => buy(p.id, parseInt(qty.value, 10) || 1));
        return card;
    }

    async function buy(productId, quantity) {
        try {
            const res = await fetch('/api/store/purchase', {
                method: 'POST',
                headers: authHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ product_id: productId, quantity: quantity })
            });
            const data = await res.json();
            if (res.ok && data.ok) {
                showMsg('catalog-msg', 'Purchased ' + data.quantity + ' × ' +
                    data.product + ' for ' + money(data.total), true);
            } else {
                const reason = {
                    insufficient_funds: 'Insufficient balance',
                    out_of_stock: 'Out of stock',
                    quota_exceeded: 'Per-patient limit reached for this product',
                    bad_quantity: 'Invalid quantity',
                    not_found: 'Product not found'
                }[data.error] || ('Purchase failed (' + (data.error || res.status) + ')');
                showMsg('catalog-msg', reason, false);
            }
        } catch (e) {
            showMsg('catalog-msg', 'Purchase error: ' + e.message, false);
        } finally {
            loadWallet();
            loadProducts();
            loadOrders();
        }
    }

    // ── Orders ──────────────────────────────────────────────────────────────
    async function loadOrders() {
        const list = document.getElementById('orders-list');
        try {
            const res = await fetch('/api/store/orders', { headers: authHeaders() });
            if (!res.ok) return;
            const { orders } = await res.json();
            if (!orders.length) {
                list.innerHTML = '<p style="color: var(--text-secondary); font-size: 0.875rem;">No orders yet.</p>';
                return;
            }
            list.innerHTML = orders.map((o) =>
                '<div class="order-row">' +
                    '<span class="order-qty">' + o.quantity + '×</span>' +
                    '<span class="order-name">' + escapeHtml(o.product_name || ('#' + o.product_id)) + '</span>' +
                    '<span class="order-total">' + money(o.total) + '</span>' +
                    '<span class="order-date">' + (o.created_at || '') + '</span>' +
                '</div>').join('');
        } catch (_) { /* ignore */ }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────
    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

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
        loadWallet();
        loadProducts();
        loadOrders();
    });
})();
