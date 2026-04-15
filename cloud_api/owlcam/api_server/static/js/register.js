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
// VulnZoo Registration Form - JWT-based

class RegistrationForm {
    constructor() {
        this.form = document.getElementById('registerForm');
        this.usernameInput = document.getElementById('username');
        this.passwordInput = document.getElementById('password');
        this.confirmPasswordInput = document.getElementById('confirmPassword');
        this.passwordToggle = document.getElementById('passwordToggle');
        this.confirmPasswordToggle = document.getElementById('confirmPasswordToggle');
        this.submitButton = this.form.querySelector('.auth-btn');
        this.successMessage = document.getElementById('successMessage');
        this.init();
    }

    init() {
        this.bindEvents();
        this.setupPasswordToggles();
    }

    bindEvents() {
        this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        this.usernameInput.addEventListener('input', () => this.clearError('username'));
        this.passwordInput.addEventListener('input', () => {
            this.clearError('password');
            this.clearError('confirmPassword');
        });
        this.confirmPasswordInput.addEventListener('input', () => this.clearError('confirmPassword'));
    }

    setupPasswordToggles() {
        // Toggle para password
        this.passwordToggle.addEventListener('click', () => {
            const type = this.passwordInput.type === 'password' ? 'text' : 'password';
            this.passwordInput.type = type;
            const icon = this.passwordToggle.querySelector('.toggle-icon');
            icon.classList.toggle('show-password', type === 'text');
        });

        // Toggle para confirm password
        this.confirmPasswordToggle.addEventListener('click', () => {
            const type = this.confirmPasswordInput.type === 'password' ? 'text' : 'password';
            this.confirmPasswordInput.type = type;
            const icon = this.confirmPasswordToggle.querySelector('.toggle-icon');
            icon.classList.toggle('show-password', type === 'text');
        });
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
        
        if (username.length > 20) {
            this.showError('username', 'Username must be less than 20 characters');
            return false;
        }
        
        if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
            this.showError('username', 'Username can only contain letters, numbers, hyphens and underscores');
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
        
        if (password.length < 4) {
            this.showError('password', 'Password must be at least 4 characters');
            return false;
        }
        
        this.clearError('password');
        return true;
    }

    validateConfirmPassword() {
        const password = this.passwordInput.value;
        const confirmPassword = this.confirmPasswordInput.value;
        
        if (!confirmPassword) {
            this.showError('confirmPassword', 'Please confirm your password');
            return false;
        }
        
        if (password !== confirmPassword) {
            this.showError('confirmPassword', 'Passwords do not match');
            return false;
        }
        
        this.clearError('confirmPassword');
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

        // Validar todos los campos
        let valid = true;
        if (!this.validateUsername()) {
            valid = false;
        }
        if (!this.validatePassword()) {
            valid = false;
        }
        if (!this.validateConfirmPassword()) {
            valid = false;
        }
        
        if (!valid) {
            return;
        }

        this.setLoading(true);

        try {
            const formData = new FormData(this.form);
            
            const response = await fetch('/register', {
                method: 'POST',
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(Object.fromEntries(formData))
            });

            let data;
            try {
                data = await response.json();
            } catch (parseError) {
                console.error('JSON parse error:', parseError);
                this.showPopup('<strong>Error!</strong><br>Server error. Please try again later.', 'error');
                this.setLoading(false);
                return;
            }

            if (response.ok) {
                // Registro exitoso
                console.log('Registration successful:', data);
                
                // Limpiar errores visuales
                document.querySelectorAll('input').forEach(input => input.classList.remove('input-error'));
                
                // Mostrar mensaje de éxito
                this.showSuccess();
                
                // Redirigir a login después de 2 segundos
                setTimeout(() => {
                    window.location.href = '/login';
                }, 2000);

            } else {
                // Registro fallido
                let errorMessage = '<strong>Registration Failed!</strong><br>';
                
                if (data.error) {
                    errorMessage += data.error;
                } else {
                    errorMessage += 'Unable to create account. Please try again.';
                }

                if (data.hint) {
                    errorMessage += `<br><small style="color: #ff9800;">Hint: ${data.hint}</small>`;
                }

                if (data.type) {
                    errorMessage += `<br><small style="color: #9e9e9e;">Error type: ${data.type}</small>`;
                }

                if (data.error && data.error.includes('already exists')) {
                    errorMessage += '<br><small>Try a different username or <a href="/login">login here</a></small>';
                }

                this.showPopup(errorMessage, 'error');
                
                // Marcar inputs con error
                document.querySelectorAll('input').forEach(input => input.classList.add('input-error'));
            }
        } catch (error) {
            console.error('Registration error:', error);
            this.showPopup('<strong>Error!</strong><br>Network error. Please try again.', 'error');
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

    showPopup(message, type = 'error') {
        const popup = document.createElement('div');
        const bgColor = type === 'error' ? '#e74c3c' : '#10b981';
        
        popup.style.cssText = `
            position: fixed; top: 20px; right: 20px; background: ${bgColor}; color: white;
            padding: 15px; border-radius: 8px; z-index: 1000; 
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
            font-family: Arial; font-size: 14px; max-width: 350px;
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
        }, 6000);
    }
}

// Inicializar cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', () => {
    new RegistrationForm();

    window.vulnzooRegister = {
        checkUsername: async function(username) {
            try {
                // Intento de enumeración de usuarios
                const response = await fetch('/register', {
                    method: 'POST',
                    body: new URLSearchParams({
                        username: username,
                        password: 'test123'
                    })
                });
                const data = await response.json();
                
                if (data.error && data.error.includes('already exists')) {
                    console.log(`✓ Username '${username}' EXISTS`);
                    return { exists: true, message: data.error };
                } else {
                    console.log(`✗ Username '${username}' available or invalid`);
                    return { exists: false, message: data.error };
                }
            } catch (error) {
                console.error('Error checking username:', error);
                return { exists: false, error: error.message };
            }
        },
        enumerateUsers: async function(usernames) {
            console.log('🔍 Starting user enumeration...');
            const results = [];
            
            for (const username of usernames) {
                const result = await this.checkUsername(username);
                results.push({ username, ...result });
                await new Promise(resolve => setTimeout(resolve, 500)); // Delay para evitar rate limiting
            }
            
            console.table(results);
            return results;
        }
    };
});