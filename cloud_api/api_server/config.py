import os
from pymongo import MongoClient


class Config:
    MONGO_USERNAME = os.getenv('MONGO_USERNAME')
    MONGO_PASSWORD = os.getenv('MONGO_PASSWORD')
    MONGO_URI = 'mongodb://mongo:27017/'
    CAMERA_ADMIN_USERNAME = os.getenv('CAMERA_ADMIN_USERNAME')
    CAMERA_ADMIN_PASSWORD = os.getenv('CAMERA_ADMIN_PASSWORD') 
    FEATURES = {
        "cpu_info": "/proc/cpuinfo",
        "mem_info": "/proc/meminfo",
        "disk_info": "/proc/diskstats",
        "uptime": "/proc/uptime",
        "loadavg": "/proc/loadavg",
        "mounts": "/proc/mounts",
        "net_info": "/proc/net/dev",
        "os_release": "/etc/os-release",
        "hostname": "/etc/hostname",
        "users": "/etc/passwd",
        "processes": "/proc/self/status"
    }
    FIRMWARE_KEY = os.getenv('FIRMWARE_KEY')
    FIRMWARE_SECRET = os.getenv('FIRMWARE_SECRET')
    MAX_TIME_DIFF=30
    LATEST_FIRMWARE_VERSION = "1.0.3"
    SERVER_IP = '192.168.2.1'
    # URLs internas Docker para las cámaras simuladas
    CAMERA_URLS = {
        "1": "http://172.30.0.11:9090/video", # Admin's camera (simulada)
        "2": "http://172.30.0.22:9090/video", # Peter's camera (simulada)
        "3": "http://192.168.2.1:9090/video"   # Attacker's camera (real, Raspberry Pi)
    }

    # IPs públicas ficticias para mostrar en la API/interfaz
    CAMERA_PUBLIC_IPS = {
        "1": "80.23.45.11",      # Admin's camera
        "2": "201.33.44.55",    # Peter's camera
        "3": "203.0.113.99"     # Attacker's camera (puedes cambiarla por la que prefieras)
    }

    # JWT Configuration (VULNERABLE)
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'default_secret_key')  # Clave por defecto insegura
    JWT_ALGORITHM = 'HS256' # Vulnerable to algorithm confusion attacks
    JWT_EXPIRATION_HOURS = 24

    # Additional vulnerability: Allow 'none' algorithm
    JWT_ALLOW_NONE_ALGORITHM = True

    # C2 Server Configuration
    # El C2 ahora es un servicio externo, no embebido en la API
    C2_ENABLED = True
    C2_SERVER_URL = os.getenv('C2_SERVER_URL', 'http://c2-server:4999')
    C2_PANEL_PASSWORD = "letstechin"
    
    # Configuración legacy (mantenida por compatibilidad)
    C2_PORT = 8443  # Obsoleto - solo para referencia
    TECH_USERNAME = 'tech_support'

    # Diagnostic system
    DIAG_ENDPOINT = '/api/v2/diag'
    METRICS_ENDPOINT = '/api/v2/metrics'

    SUPPORT_RESPONSE_TEMPLATE = """
    Hello {username},

    Your support request has been received and registered successfully.

    Request Details:
    • Type: {issue_type}
    • Ticket ID: #{ticket_id}
    • Status: Under Review

    Our technical team will analyze your request and respond within 24-48 hours.
    {camera_access_note}

    Thank you for contacting VulnZoo Support.

    ---
    {admin_username}
    VulnZoo Security Platform
    """

    SUPPORT_SUCCESS_RESPONSE_TEMPLATE = """
    <strong>✅ Support Request Submitted Successfully!</strong><br><br>

    <strong>Request Details:</strong><br>
    • Type: {issue_type}<br>
    • Ticket ID: #{ticket_id}<br><br>

    <strong>📧 Next Steps:</strong><br>
    Your request has been forwarded to the system administrator.<br>
    Check your <a href="/messages">message inbox</a> for the response within 24-48 hours.<br><br>

    <em>Please do not reply to this confirmation message.</em>
    <em> If you need to modify your request or attach additional files, use the link below:</em><br>
    <a href="/support/modify?ticket_id={ticket_id}">Modify or attach a file to your request</a>
    """


    WELCOME_SUPPORT_MESSAGE_TEMPLATE = """
    <strong>✅ Welcome to VulnZoo {username}!</strong><br><br>
    <strong>Your account has been created successfully.</strong><br><br>
    <strong>We have all your details and information about your account. The camera installation was successful.</strong><br><br>
    <strong>In order to validate your account and grant access to the camera feeds, we may need to contact you for additional information.</strong><br><br>
    <strong>We need a photo of you standing with your ID to verify your identity and ensure the security of your account.</strong><br><br>
    <em>If you haven't done so already, please contact the support team to upload the required photo.</em>
    """

    SUPPORT_TEAM_MESSAGE_TEMPLATE = """
    <strong>📢 New Support Request from {username}!</strong><br><br>
    <strong>Request Details:</strong><br>
    • Type: {issue_type}<br>
    • Ticket ID: #{ticket_id}<br><br>
    Please insert the following debuging token in the support message. Our technical team will use this token to correlate your request with the camera feed and provide you with the necessary support.<br><br>
    <strong>Debugging Token:</strong><br>
    <code>DEBUG-00000E-TECH</code><br><br>
    Please do not share this token with anyone else, as it is unique to your request and will be used to access the camera feed for troubleshooting purposes.<br><br>
    <em>Our technical team will review your request and respond within 24-48 hours. Thank you for your patience!</em>
    """


mongo_client = MongoClient(Config.MONGO_URI, 
                           username=Config.MONGO_USERNAME, 
                           password=Config.MONGO_PASSWORD, 
                           serverSelectionTimeoutMS=2000)
