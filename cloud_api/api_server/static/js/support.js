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
// VulnZoo Support Form - JWT-aware

class SupportForm {
    constructor() {
        this.form = document.getElementById('supportForm');
        this.responseMessage = document.getElementById('responseMessage');
        this.submitButton = this.form.querySelector('.auth-btn');
        
        // Form fields
        this.fields = {
            issue_type: document.getElementById('issue_type'),
            username: document.getElementById('username'),
            message: document.getElementById('message')
        };
        
        this.init();
    }

    init() {
        this.bindEvents();
        this.prefillUsername();
    }

    bindEvents() {
        this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        
        // Clear errors on input
        Object.keys(this.fields).forEach(fieldName => {
            const field = this.fields[fieldName];
            if (field) {
                field.addEventListener('input', () => this.clearError(fieldName));
                field.addEventListener('change', () => this.clearError(fieldName));
            }
        });
    }

    /**
     * Pre-rellenar username si el usuario está autenticado
     */
    prefillUsername() {
        const username = localStorage.getItem('username');
        if (username && this.fields.username) {
            this.fields.username.value = username;
        }
    }

    /**
     * Validar campos del formulario
     */
    validateForm() {
        let isValid = true;

        // Validar issue_type
        if (!this.fields.issue_type.value) {
            this.showError('issue_type', 'Please select a reason for contact');
            isValid = false;
        }

        // Validar username
        if (!this.fields.username.value.trim()) {
            this.showError('username', 'Username is required');
            isValid = false;
        }

        // Validar message
        if (!this.fields.message.value.trim()) {
            this.showError('message', 'Message is required');
            isValid = false;
        } else if (this.fields.message.value.trim().length < 10) {
            this.showError('message', 'Message must be at least 10 characters');
            isValid = false;
        }

        return isValid;
    }

    showError(field, message) {
        const errorElement = document.getElementById(`${field}Error`);
        const formGroup = this.fields[field]?.closest('.form-group');
        
        if (errorElement && formGroup) {
            formGroup.classList.add('error');
            errorElement.textContent = message;
            errorElement.classList.add('show');
        }
    }

    clearError(field) {
        const errorElement = document.getElementById(`${field}Error`);
        const formGroup = this.fields[field]?.closest('.form-group');
        
        if (errorElement && formGroup) {
            formGroup.classList.remove('error');
            errorElement.classList.remove('show');
            setTimeout(() => {
                errorElement.textContent = '';
            }, 200);
        }
    }

    clearAllErrors() {
        Object.keys(this.fields).forEach(field => this.clearError(field));
    }

    async handleSubmit(e) {
        e.preventDefault();
        
        if (!this.validateForm()) {
            return;
        }
        
        this.setLoading(true);
        
        const formData = new FormData();
        formData.append('issue_type', this.fields.issue_type.value);
        formData.append('username', this.fields.username.value.trim());
        formData.append('message', this.fields.message.value.trim());
        
        try {
            // Obtener token JWT
            const token = localStorage.getItem('auth');
            if (!token) {
                this.showResponseMessage('Authentication required. Please login first.', 'error');
                setTimeout(() => window.location.href = '/login', 2000);
                return;
            }
            
            const response = await fetch('/api/support/submit', {
                method: 'POST',
                headers: {
                    'X-Auth-Token': token
                },
                body: formData
            });
            
            const data = await response.json();
            
            if (response.ok) {
                this.showResponseMessage(data.message, 'success');
                this.form.reset();
            } else {
                this.showResponseMessage(data.message || data.error, 'error');
            }
            
        } catch (error) {
            this.showResponseMessage(`Request failed: ${error.message}`, 'error');
            console.error('Submit error:', error);
        } finally {
            this.setLoading(false);
        }
    }

getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

    /**
     * Manejar respuestas de error del servidor
     */
    handleErrorResponse(result) {
        let errorHtml = '';
        
        if (result.error === 'validation_failed' && result.message) {
            errorHtml = result.message;
        } else if (result.error === 'username_not_found' && result.message) {
            errorHtml = result.message;
        } else if (result.message) {
            errorHtml = result.message;
        } else {
            errorHtml = `<strong>Error:</strong> ${result.error || 'Unknown error occurred'}`;
        }
        
        if (result.suggestion) {
            errorHtml += `<br><small style="color: #ff9800; margin-top: 4px; display: block;">💡 ${result.suggestion}</small>`;
        }
        
        this.showResponseMessage(errorHtml, 'error');
        this.responseMessage.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    showResponseMessage(message, type = 'info') {
        this.responseMessage.innerHTML = message;
        this.responseMessage.className = `response-message ${type}`;
        this.responseMessage.style.display = 'block';
    }

    hideResponseMessage() {
        this.responseMessage.style.display = 'none';
    }

    setLoading(loading) {
        this.submitButton.classList.toggle('loading', loading);
        this.submitButton.disabled = loading;
    }
}

// Inicializar cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', () => {
    const supportForm = new SupportForm();
    
    window.vulnzooSupport = {
        form: supportForm,
        testUsername: async function(username) {
            const formData = new FormData();
            formData.append('issue_type', 'camera_access');
            formData.append('username', username);
            formData.append('message', 'Testing username enumeration');
            
            try {
                const response = await fetch('/api/support/submit', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.error === 'username_not_found') {
                    console.log(`❌ Username '${username}' NOT FOUND`);
                    return { exists: false, message: result.message };
                } else if (response.ok || result.error === 'User already has camera access') {
                    console.log(`✓ Username '${username}' EXISTS`);
                    return { exists: true, message: result.message };
                } else {
                    console.log(`? Username '${username}' - Unknown status`);
                    return { exists: null, message: result.message };
                }
            } catch (error) {
                console.error('Error testing username:', error);
                return { exists: null, error: error.message };
            }
        },
        enumerateUsers: async function(usernames) {
            console.log('🔍 Starting username enumeration via support form...');
            const results = [];
            
            for (const username of usernames) {
                const result = await this.testUsername(username);
                results.push({ username, ...result });
                await new Promise(resolve => setTimeout(resolve, 1000)); // Delay
            }
            
            console.table(results);
            return results;
        }
    };
});