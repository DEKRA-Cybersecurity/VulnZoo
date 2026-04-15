document.addEventListener('DOMContentLoaded', function () {
    const btn = document.getElementById('validate-admin-btn');
    const msgDiv = document.getElementById('admin-message');
    const accessContainer = document.getElementById('admin-access-container');
    const panelContainer = document.getElementById('admin-panel-container');

    async function validateAccess() {
        msgDiv.textContent = 'Validating access...';
        const token = localStorage.getItem('auth');
        if (!token) {
            msgDiv.textContent = 'No authentication token found. Redirecting to login...';
            setTimeout(() => window.location.href = '/login', 2000);
            return;
        }
        try {
            const response = await fetch('/api/v2/userinfo', {
                method: 'GET',
                headers: { 'X-Auth-Token': token }
            });
            const data = await response.json();
            if (response.ok && data.role === 'admin') {
                const panelResp = await fetch('/admin', {
                    method: 'POST',
                    headers: { 'X-Auth-Token': token }
                });
                if (panelResp.ok) {
                    const html = await panelResp.text();
                    accessContainer.style.display = 'none';
                    panelContainer.style.display = 'block';
                    panelContainer.innerHTML = html;
                } else {
                    msgDiv.textContent = 'Error loading admin panel. Please try again.';
                }
            } else {
                msgDiv.textContent = 'Access denied: You are not an admin.';
            }
        } catch (error) {
            msgDiv.textContent = 'Error validating access. Please try again.';
        }
    }
    btn.onclick = validateAccess;
});