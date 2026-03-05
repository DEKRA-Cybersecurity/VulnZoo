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
// JWT-based Login Form JavaScript
class MinimalLoginForm {
    constructor() {
        this.form = document.getElementById('loginForm');
        this.usernameInput = document.getElementById('username');
        this.passwordInput = document.getElementById('password');
        this.passwordToggle = document.getElementById('passwordToggle');
        this.submitButton = this.form.querySelector('.auth-btn');
        this.successMessage = document.getElementById('successMessage');
        this.init();
    }

    init() {
        this.bindEvents();
        this.setupPasswordToggle();
        this.showCookieError();
    }

    bindEvents() {
        this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        this.usernameInput.addEventListener('input', () => this.clearError('username'));
        this.passwordInput.addEventListener('input', () => this.clearError('password'));
    }

    setupPasswordToggle() {
        this.passwordToggle.addEventListener('click', () => {
            const type = this.passwordInput.type === 'password' ? 'text' : 'password';
            this.passwordInput.type = type;
            const icon = this.passwordToggle.querySelector('.toggle-icon');
            icon.classList.toggle('show-password', type === 'text');
        });
    }

    /**
     * Get JWT token from multiple sources
     */
    getAuthToken() {
        return localStorage.getItem('auth');
    }

    /**
     * Save JWT token in multiple locations
     */
    saveAuthToken(token, userData = {}) {
        // Save in localStorage
        localStorage.setItem('auth', token); // Compatibility
        localStorage.setItem('user_role', userData.role);
        localStorage.setItem('user_name', userData.username);
        if (userData.session_id) {
            document.cookie = `session_id=${userData.session_id}; path=/; max-age=3600; samesite=Lax`;
        }
    }

    /**
     * Clear all authentication data
     */
    clearAuthData() {
        // Clear localStorage
        localStorage.removeItem('auth');
        localStorage.removeItem('user_role');
        localStorage.removeItem('user_name');
        document.cookie = 'session_id=; Max-Age=0; path=/';
    }

    validateUsername() {
        const username = this.usernameInput.value.trim();
        if (!username) {
            this.showError('username', 'Username is required');
            return false;
        }
        if (username.length < 3) {
            this.showError('username', 'Username must be at least 3 characters');
            return false;
        }
        this.clearError('username');
        return true;
    }

    validatePassword() {
        const password = this.passwordInput.value;
        if (!password) {
            this.showError('password', 'Password is required');
            return false;
        }
        this.clearError('password');
        return true;
    }

    showError(field, message) {
        const formGroup = document.getElementById(field).closest('.form-group');
        const errorElement = document.getElementById(`${field}Error`);
        formGroup.classList.add('error');
        errorElement.textContent = message;
        errorElement.classList.add('show');
    }

    clearError(field) {
        const formGroup = document.getElementById(field).closest('.form-group');
        const errorElement = document.getElementById(`${field}Error`);
        formGroup.classList.remove('error');
        errorElement.classList.remove('show');
        setTimeout(() => {
            errorElement.textContent = '';
        }, 200);
    }

    async handleSubmit(e) {
        e.preventDefault();

        // Validate fields
        let valid = true;
        if (!this.validateUsername()) {
            valid = false;
        }
        if (!this.validatePassword()) {
            valid = false;
        }
        if (!valid) {
            return;
        }

        this.setLoading(true);

        try {
            const payload = {
                username: this.usernameInput.value.trim(),
                password: this.passwordInput.value
            };

            const response = await fetch('/api/v2/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            let data;
            try {
                data = await response.json();
            } catch (parseError) {
                console.error('JSON parse error:', parseError);
                this.showPopup('<strong>Error!</strong><br>Server error. Please try again later.');
                this.setLoading(false);
                return;
            }

            if (response.ok && data.auth) {
                // Successful login - save JWT
                this.saveAuthToken(data.auth, {
                    user_id: data.user_id,
                    role: data.role,
                    session_id: data.session_id,
                    username: this.usernameInput.value.trim()
                });

                // Clear visual errors
                document.querySelectorAll('input').forEach(input => input.classList.remove('input-error'));

                // Show success message
                this.showSuccess();

                // Redirect after 1 second
                setTimeout(() => {
                    window.location.href = data.redirect;
                }, 1000);

            } else {
                // Failed login
                let errorMessage = '<strong>Error!</strong><br>';
                
                if (data.error) {
                    errorMessage += data.error;
                } else {
                    errorMessage += 'These credentials do not match our records.';
                }

                if (data.type) {
                    errorMessage += `<br><small style="color: #9e9e9e;">Error type: ${data.type}</small>`;
                }

                this.showPopup(errorMessage);
                
                // Mark inputs with error
                document.querySelectorAll('input').forEach(input => input.classList.add('input-error'));
            }
        } catch (error) {
            console.error('Login error:', error);
            this.showPopup('<strong>Error!</strong><br>Network error. Please try again.');
        } finally {
            this.setLoading(false);
        }
    }

    setLoading(loading) {
        this.submitButton.classList.toggle('loading', loading);
        this.submitButton.disabled = loading;
    }

    showSuccess() {
        this.form.style.display = 'none';
        this.successMessage.classList.add('show');
    }

    showPopup(message) {
        const popup = document.createElement('div');
        popup.style.cssText = `
            position: fixed; top: 20px; right: 20px; background: #e74c3c; color: white;
            padding: 15px; border-radius: 8px; z-index: 1000; 
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
            font-family: Arial; font-size: 14px; max-width: 300px;
            animation: slideIn 0.3s ease-out;
        `;
        popup.innerHTML = message;
        document.body.appendChild(popup);

        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            @keyframes slideOut {
                from { transform: translateX(0); opacity: 1; }
                to { transform: translateX(100%); opacity: 0; }
            }
        `;
        document.head.appendChild(style);

        setTimeout(() => {
            popup.style.animation = 'slideOut 0.3s ease-in forwards';
            setTimeout(() => popup.remove(), 300);
        }, 5000);
    }

    getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return null;
    }

    showCookieError() {
        let errorMsg = this.getCookie('login_error');
        if (errorMsg) {
            if (errorMsg.startsWith('"') && errorMsg.endsWith('"')) {
                errorMsg = errorMsg.slice(1, -1);
            }
            this.showPopup(errorMsg);
            document.cookie = 'login_error=; Max-Age=0; path=/';
        }
    }
}

// Initialize when DOM is ready
 document.addEventListener('DOMContentLoaded', () => {
    new MinimalLoginForm();
});