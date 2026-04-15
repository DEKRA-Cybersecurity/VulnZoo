// Profile dropdown logic
function initProfileDropdown() {
    const dropdown = document.querySelector('.profile-dropdown');
    const btn = document.getElementById('profile-dropdown-btn');
    if (!dropdown || !btn) return;
    btn.addEventListener('click', (e) => {
        e.stopPropagation();
        dropdown.classList.toggle('show');
    });
    document.addEventListener('click', (e) => {
        if (!dropdown.contains(e.target)) {
            dropdown.classList.remove('show');
        }
    });
}

window.addEventListener('DOMContentLoaded', initProfileDropdown);
// Dark mode toggle logic
function setDarkMode(enabled) {
    if (enabled) {
        document.body.classList.add('dark-mode');
    } else {
        document.body.classList.remove('dark-mode');
    }
    localStorage.setItem('theme', enabled ? 'dark' : 'light');
}

function initThemeToggle() {
    const btn = document.getElementById('theme-toggle');
    if (!btn) return;
    btn.addEventListener('click', () => {
        const isDark = !document.body.classList.contains('dark-mode');
        setDarkMode(isDark);
    });
    // Load preference
    const saved = localStorage.getItem('theme');
    if (saved === 'dark') setDarkMode(true);
    else setDarkMode(false);
}

window.addEventListener('DOMContentLoaded', initThemeToggle);
// VulnZoo Cameras - JWT-based Camera Management

class CamerasManager {
    constructor() {
        this.camerasListElement = document.getElementById('cameras-list');
        this.loadingIndicator = document.getElementById('loading-indicator');
        this.errorMessageElement = document.getElementById('error-message');
        this.userRole = localStorage.getItem('user_role');
        this.username = localStorage.getItem('user_name');
        this.init();
    }
    
    init() {
        this.renderUserInfo();
        this.loadCameras();
        setInterval(() => this.loadCameras(), 120000);
    }

    renderUserInfo() {}

    getAuthToken() {
        return localStorage.getItem('auth');
    }

    async loadCameras() {
        try {
            this.showLoading(true);
            this.hideError();
            const token = this.getAuthToken();
            if (!token) {
                this.showError('No authentication token found');
                this.showLoading(false);
                this.logout('No authentication token found');
                return;
            }
            const response = await fetch('/api/cameras', {
                headers: {
                    'X-Auth-Token': token,
                    'Content-Type': 'application/json'
                }
            });
            const data = await response.json();
            if (response.status === 401 || response.status === 403) {
                this.logout(data.login_error || 'Session expired');
                return;
            }
            if (data.cameras && data.cameras.length > 0) {
                this.renderCameras(data.cameras);
            } else {
                this.showNoCameras();
            }
        } catch (error) {
            this.showError('Error loading cameras. Please try again later.');
        } finally {
            this.showLoading(false);
        }
    }

    renderCameras(cameras) {
        this.camerasListElement.innerHTML = '';
        cameras.forEach(camera => {
            const cameraElement = this.createCameraElement(camera);
            this.camerasListElement.appendChild(cameraElement);
        });
    }

   createCameraElement(camera) {
        const cameraDiv = document.createElement('div');
        cameraDiv.className = 'camera';
        cameraDiv.setAttribute('data-camera-id', camera.id);

        const title = document.createElement('h3');
        title.textContent = camera.name;
        cameraDiv.appendChild(title);

        if (camera.description) {
            const description = document.createElement('p');
            description.textContent = camera.description;
            cameraDiv.appendChild(description);
        }

        // Firmware info
        const fwVersion = document.createElement('div');
        fwVersion.className = 'firmware-version-info';
        fwVersion.textContent = `Installed firmware: ${camera['firmware-version'] || 'unknown'}`;
        cameraDiv.appendChild(fwVersion);

        // Firmware update box
        const updateBox = document.createElement('div');
        updateBox.className = 'firmware-update-box';

        // Firmware update button
        const updateBtn = document.createElement('button');
        updateBtn.className = 'firmware-update-btn';
        updateBtn.id = `firmware-update-btn-${camera.id}`;
        updateBtn.style.marginLeft = '12px';
        updateBtn.textContent = 'Update Firmware';
        updateBtn.disabled = true;

        // Status message
        const statusDiv = document.createElement('div');
        statusDiv.className = 'firmware-update-status';
        statusDiv.id = `firmware-update-status-${camera.id}`;
        statusDiv.style.display = 'none';

        // Check firmware version for this camera
        fetch('/firmware/latest-version')
            .then(resp => resp.json())
            .then(data => {
                const latestVersion = data.version;
                if (camera['firmware-version'] !== latestVersion) {
                    updateBox.innerHTML = `<strong>⚠️ Attention:</strong> There is a new firmware update available!<br>`;
                    updateBox.style.background = "#fffbe6";
                    updateBox.style.border = "2px solid #ffe066";
                    updateBox.style.color = "#b45309";
                    updateBtn.disabled = false;
                    updateBtn.textContent = `Update Firmware to ${latestVersion}`;
                    updateBtn.title = `Current: ${camera['firmware-version'] || 'unknown'}, Latest: ${latestVersion}`;
                } else {
                    updateBox.innerHTML = ""; // No mensaje de atención
                    updateBox.style.background = "";
                    updateBox.style.border = "";
                    updateBox.style.color = "";
                    updateBtn.disabled = true;
                    updateBtn.textContent = 'Firmware up to date';
                    updateBtn.title = `Current: ${camera['firmware-version'] || 'unknown'}, Latest: ${latestVersion}`;
                }
                updateBox.appendChild(updateBtn);
                updateBox.appendChild(statusDiv);
            });

        updateBtn.addEventListener('click', async function() {
            updateBtn.disabled = true;
            statusDiv.style.display = 'block';
            statusDiv.textContent = 'Updating firmware...';
            try {
                const device_ip = camera.server_ip;
                const firmware_url = '/firmware/latest';
                const response = await fetch('/firmware/trigger_update', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `device_ip=${encodeURIComponent(device_ip)}&firmware_url=${encodeURIComponent(firmware_url)}`
                });
                const data = await response.json();
                if (response.ok) {
                    statusDiv.textContent = 'Firmware update triggered!';
                } else {
                    statusDiv.textContent = 'Error updating: ' + (data.error || response.statusText);
                }
            } catch (err) {
                statusDiv.textContent = 'Network error updating firmware.';
            }
        });

        cameraDiv.appendChild(updateBox);

        // Camera access button
        const button = this.createCameraButton(camera);
        cameraDiv.appendChild(button);

        // Snapshot container
        const snapshotContainer = document.createElement('div');
        snapshotContainer.id = `snapshot-${camera.id}`;
        cameraDiv.appendChild(snapshotContainer);

        return cameraDiv;
    }

    createCameraButton(camera) {
        const button = document.createElement('button');
        button.id = `btn-${camera.id}`;
        const hasAccess = this.userRole === 'admin' || this.userRole === 'viewer';
        if (hasAccess) {
            if (camera.active) {
                button.textContent = 'View Snapshot';
                button.addEventListener('click', () => this.viewSnapshot(camera.id));
            } else {
                button.textContent = 'Camera is inactive';
                button.disabled = true;
            }
        } else {
            button.textContent = 'No access';
            button.disabled = true;
            button.title = 'You need viewer permissions to access this camera.';
        }
        return button;
    }

    viewSnapshot(cameraId) {
        const token = this.getAuthToken();
        const url = `/snapshot?camera=${cameraId}&token=${token}`;
        window.location.href = url;
    }

    showNoCameras() {
        this.camerasListElement.innerHTML = `
            <p class="no-access">No cameras available. Please contact support for access.</p>
        `;
    }

    showLoading(show) {
        if (this.loadingIndicator) {
            this.loadingIndicator.style.display = show ? 'flex' : 'none';
        }
    }

    showError(message) {
        if (this.errorMessageElement) {
            this.errorMessageElement.textContent = message;
            this.errorMessageElement.style.display = 'block';
        }
    }

    hideError() {
        if (this.errorMessageElement) {
            this.errorMessageElement.style.display = 'none';
        }
    }

    clearAuthData() {
        localStorage.removeItem('auth');
        localStorage.removeItem('user_role');
        localStorage.removeItem('user_name');
        (function clearAllCookies() {
            const cookies = document.cookie ? document.cookie.split(';') : [];
            const hostnameParts = location.hostname.split('.');
            cookies.forEach(cookie => {
                const eqPos = cookie.indexOf('=');
                const name = eqPos > -1 ? cookie.substr(0, eqPos).trim() : cookie.trim();
                if (!name) return;
                document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
                for (let i = 0; i < hostnameParts.length - 1; i++) {
                    const domain = '.' + hostnameParts.slice(i).join('.');
                    document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; domain=' + domain;
                }
            });
        })();
    }

    logout(login_error) {
        this.clearAuthData();
        document.cookie = "login_error=" + login_error;
        window.location.href = '/login';
    }

    getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const camerasManager = new CamerasManager();

    // Add admin link if user has admin role
    if (localStorage.getItem('admin_roles') === 'admin') {
        const adminLink = document.createElement('li');
        adminLink.innerHTML = '<a href="/admin" id="admin-link">Admin</a>';
        const menu = document.querySelector('.topbar-menu.left');
        if (menu) {
            menu.appendChild(adminLink);
        }
    }

    // Sidebar navigation
    const messagesLink = document.getElementById('messages-link');
    if (messagesLink) {
        messagesLink.addEventListener('click', function(e) {
            e.preventDefault();
            window.location.href = '/messages';
        });
    }
    const supportLink = document.getElementById('support-link');
    if (supportLink) {
        supportLink.addEventListener('click', function(e) {
            e.preventDefault();
            window.location.href = '/support';
        });
    }
    const profileLink = document.getElementById('profile-link');
    if (profileLink) {
        profileLink.addEventListener('click', function(e) {});
    }
    const logoutLink = document.getElementById('logout-link');
    if (logoutLink) {
        logoutLink.addEventListener('click', async function(e) {
            e.preventDefault();
            const token = localStorage.getItem('auth');
            try {
                await fetch('/api/v2/logout', {
                    method: 'DELETE',
                    headers: {
                        'X-Auth-Token': token,
                        'Content-Type': 'application/json'
                    }
                });
            } catch (err) {}
            camerasManager.logout('Logged out');
        });
    }
    const profileUsernameSpan = document.getElementById('profile-username');
    if (profileUsernameSpan) {
        profileUsernameSpan.textContent = camerasManager.username || 'User';
    }
});