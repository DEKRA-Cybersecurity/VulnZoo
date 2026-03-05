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
// VulnZoo Snapshot Viewer - JWT-based Camera Snapshot Management

class SnapshotViewer {
    constructor() {
        // DOM elements
        this.statusElement = document.getElementById('status');
        this.snapshotImage = document.getElementById('snapshot');
        this.loadingOverlay = document.getElementById('loading-overlay');
        this.errorMessageElement = document.getElementById('error-message');
        this.captureBtn = document.getElementById('captureBtn');
        this.autoBtn = document.getElementById('autoBtn');
        this.stopBtn = document.getElementById('stopBtn');
        this.backBtn = document.getElementById('backBtn');
        
        // State
        this.autoInterval = null;
        this.isAutoMode = false;
        this.cameraId = null;
        this.token = null;
        this.sessionId = null;
        
        this.init();
    }

    init() {
        // Obtener parámetros de URL
        this.cameraId = this.getUrlParameter('camera');
        this.token = this.getUrlParameter('token') || this.getAuthToken();
        this.sessionId = this.getUrlParameter('session') || localStorage.getItem('session_id');
        
        // Validar autenticación
        if (!this.validateAuth()) {
            return;
        }
        
        // Bind events
        this.bindEvents();
        
        // Capturar snapshot inicial
        this.updateSnapshot();
        
        // Iniciar auto-refresh por defecto
        this.stopAuto();
    }

    /**
     * Validar autenticación
     */
    validateAuth() {
        if (!this.cameraId) {
            this.showError('No camera specified');
            setTimeout(() => window.location.href = '/cameras', 2000);
            return false;
        }

        if (!this.token && !this.sessionId) {
            this.showError('Authentication required. Redirecting to login...');
            setTimeout(() => window.location.href = '/login', 2000);
            return false;
        }

        return true;
    }

    /**
     * Obtener token JWT de múltiples fuentes
     */
    getAuthToken() {
        return localStorage.getItem('authToken') || 
               localStorage.getItem('auth') || 
               sessionStorage.getItem('authToken');
    }

    /**
     * Obtener parámetros de URL
     */
    getUrlParameter(name) {
        const urlParams = new URLSearchParams(window.location.search);
        return urlParams.get(name);
    }

    /**
     * Bind event listeners
     */
    bindEvents() {
        this.captureBtn.addEventListener('click', () => this.updateSnapshot());
        this.autoBtn.addEventListener('click', () => this.toggleAuto());
        this.stopBtn.addEventListener('click', () => this.stopAuto());
        this.backBtn.addEventListener('click', () => this.goBack());
    }

    /**
     * Actualizar snapshot desde el servidor
     */
    async updateSnapshot() {
        try {
            this.setStatus('Capturing...');
            this.showLoading(true);
            this.hideError();
            
            // Construir URL con parámetros
            let snapshotUrl = `/snapshot?camera=${this.cameraId}`;
            if (this.sessionId) {
                snapshotUrl += `&session=${this.sessionId}`;
            }

            const response = await fetch(snapshotUrl, {
                method: 'POST',
                headers: {
                    'X-Auth-Token': this.token || ''
                }
            });

            if (response.ok) {
                const blob = await response.blob();
                this.displaySnapshot(blob);
                
                const now = new Date().toLocaleTimeString();
                this.setStatus(`Last update: ${now}`);
            } else {
                // Manejar errores HTTP
                const errorData = await response.json().catch(() => ({}));
                
                let errorMessage = errorData.error || `HTTP Error ${response.status}`;
                if (errorData.hint) {
                    errorMessage += `\nHint: ${errorData.hint}`;
                }
                if (errorData.type) {
                    errorMessage += `\nError type: ${errorData.type}`;
                }
                
                this.showError(errorMessage);
                this.setStatus('Error capturing snapshot');
                
                // Si error de autenticación, redirigir a login
                if (response.status === 401 || response.status === 403) {
                    console.error('Authentication error, redirecting to login');
                    setTimeout(() => {
                        this.clearAuthData();
                        window.location.href = '/login';
                    }, 3000);
                }
            }
        } catch (error) {
            console.error('Snapshot error:', error);
            this.showError('Network error. Please try again.');
            this.setStatus('Connection error');
        } finally {
            this.showLoading(false);
        }
    }

    /**
     * Mostrar snapshot en la imagen
     */
    displaySnapshot(blob) {
        const imageUrl = URL.createObjectURL(blob);
        
        // Limpiar URL anterior para evitar memory leaks
        if (this.snapshotImage.dataset.prevUrl) {
            URL.revokeObjectURL(this.snapshotImage.dataset.prevUrl);
        }
        
        this.snapshotImage.src = imageUrl;
        this.snapshotImage.dataset.prevUrl = imageUrl;
        this.snapshotImage.style.display = 'block';
    }

    /**
     * Toggle auto-refresh mode
     */
    toggleAuto() {
        if (this.isAutoMode) {
            this.stopAuto();
        } else {
            this.startAuto();
        }
    }

    /**
     * Iniciar auto-refresh
     */
    startAuto() {
        if (this.autoInterval) {
            clearInterval(this.autoInterval);
        }
        
        this.autoInterval = setInterval(() => this.updateSnapshot(), 2000);
        this.isAutoMode = true;
        
        this.autoBtn.textContent = '⏸️ Auto ON';
        this.autoBtn.classList.add('active');
    }

    /**
     * Detener auto-refresh
     */
    stopAuto() {
        if (this.autoInterval) {
            clearInterval(this.autoInterval);
            this.autoInterval = null;
        }
        
        this.isAutoMode = false;
        
        this.autoBtn.textContent = '▶️ Auto Refresh';
        this.autoBtn.classList.remove('active');
    }

    /**
     * Volver a la lista de cámaras
     */
    goBack() {
        this.stopAuto();
        window.location.href = '/cameras';
    }

    /**
     * Actualizar mensaje de estado
     */
    setStatus(message) {
        if (this.statusElement) {
            this.statusElement.textContent = message;
        }
    }

    /**
     * Mostrar/ocultar loading overlay
     */
    showLoading(show) {
        if (this.loadingOverlay) {
            this.loadingOverlay.style.display = show ? 'flex' : 'none';
        }
    }

    /**
     * Mostrar mensaje de error
     */
    showError(message) {
        if (this.errorMessageElement) {
            this.errorMessageElement.textContent = message;
            this.errorMessageElement.style.display = 'block';
        }
    }

    /**
     * Ocultar mensaje de error
     */
    hideError() {
        if (this.errorMessageElement) {
            this.errorMessageElement.style.display = 'none';
        }
    }

    /**
     * Limpiar datos de autenticación
     */
    clearAuthData() {
        localStorage.removeItem('auth');
        localStorage.removeItem('authToken');
        localStorage.removeItem('user_id');
        localStorage.removeItem('user_role');
        localStorage.removeItem('session_id');
        localStorage.removeItem('username');
        sessionStorage.removeItem('auth');
        sessionStorage.removeItem('authToken');
    }

    /**
     * Cleanup al salir
     */
    cleanup() {
        this.stopAuto();
        
        // Revocar todas las URLs de objeto
        if (this.snapshotImage.dataset.prevUrl) {
            URL.revokeObjectURL(this.snapshotImage.dataset.prevUrl);
        }
    }
}

// Inicializar cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', () => {
    const viewer = new SnapshotViewer();
    
    // Cleanup al cerrar la página
    window.addEventListener('beforeunload', () => {
        viewer.cleanup();
    });
    
    window.vulnzooSnapshot = {
        viewer: viewer,
        getToken: function() {
            return viewer.token;
        },
        getCameraId: function() {
            return viewer.cameraId;
        },
        captureNow: function() {
            return viewer.updateSnapshot();
        },
        toggleAuto: function() {
            return viewer.toggleAuto();
        },
        getAutoStatus: function() {
            return viewer.isAutoMode;
        }
    };
});