package com.vulnzoo.careotter_app;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.spec.AlgorithmParameterSpec;
import java.util.zip.CRC32;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * CareOtter Secure Config Protocol v1 (CSCP v1) — threshold packet builder/parser.
 *
 * Implements "AES-128 military-grade encryption" for GATT characteristic 0xFF01.
 *
 * VULNERABILITY (OWASP M1 — Improper Credential Usage):
 *   CSCP_KEY is hardcoded in plain text. Recoverable with:
 *     strings careotter_app.apk | grep careotter
 *     jadx careotter_app.apk  →  CareOtterConfig.CSCP_KEY
 *   The same key is embedded in the device firmware (ble_server.py).
 *   Compromising one APK or one device exposes the entire CareOtter fleet.
 *
 * VULNERABILITY (OWASP M3 — Insecure Authentication/Authorization):
 *   The CSCP v1 "encryption" provides no session authentication. Any attacker
 *   who knows CSCP_KEY (trivially extracted) can forge valid packets and write
 *   lethal threshold values to the device without pairing or credentials.
 *
 * Packet layout (24 bytes, big-endian):
 *   [0:4]  Magic   — 0xCAFE0DDA
 *   [4:8]  CRC32   — CRC32(ciphertext[8:24])
 *   [8:24] Payload — AES-128-ECB(plaintext, key=CSCP_KEY)
 *
 * Plaintext block (16 bytes):
 *   [0]    bpm_min  (uint8)
 *   [1]    bpm_max  (uint8)
 *   [2]    spo2_min (uint8)
 *   [3:16] padding  (0x00)
 */
public class CareOtterConfig {

    // VULNERABILITY: hardcoded AES key — identical across all CareOtter devices
    private static final byte[] CSCP_KEY   = "careotter-key-16".getBytes(StandardCharsets.UTF_8);
    private static final int    CSCP_MAGIC = 0xCAFE0DDA;
    private static final int    PACKET_SIZE = 24;

    /** Immutable threshold value object returned by parseResponse(). */
    public static final class Thresholds {
        public final int bpmMin;
        public final int bpmMax;
        public final int spo2Min;

        Thresholds(int bpmMin, int bpmMax, int spo2Min) {
            this.bpmMin  = bpmMin;
            this.bpmMax  = bpmMax;
            this.spo2Min = spo2Min;
        }

        @Override
        public String toString() {
            return "{\"bpm_min\":" + bpmMin + ",\"bpm_max\":" + bpmMax
                    + ",\"spo2_min\":" + spo2Min + "}";
        }
    }

    /**
     * Build a 24-byte CSCP v1 packet for the given clinical thresholds.
     *
     * VULNERABILITY: no range validation — bpmMin=0, bpmMax=255, spo2Min=0 accepted.
     */
    public static byte[] buildThresholdPacket(int bpmMin, int bpmMax, int spo2Min)
            throws Exception {
        // Plaintext: 3 threshold bytes + 13 zero-padding bytes
        byte[] plaintext = new byte[16];
        plaintext[0] = (byte) (bpmMin  & 0xFF);
        plaintext[1] = (byte) (bpmMax  & 0xFF);
        plaintext[2] = (byte) (spo2Min & 0xFF);
        // plaintext[3..15] already 0x00

        // AES-128-ECB encryption (no IV — ECB mode is deterministic, vulnerable to replay)
        SecretKeySpec keySpec = new SecretKeySpec(CSCP_KEY, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] ciphertext = cipher.doFinal(plaintext);

        // CRC32 of ciphertext
        CRC32 crc32 = new CRC32();
        crc32.update(ciphertext);
        long crc = crc32.getValue();

        // Assemble packet: Magic(4) + CRC(4) + Ciphertext(16)
        ByteBuffer buf = ByteBuffer.allocate(PACKET_SIZE).order(ByteOrder.BIG_ENDIAN);
        buf.putInt(CSCP_MAGIC);
        buf.putInt((int) (crc & 0xFFFFFFFFL));
        buf.put(ciphertext);
        return buf.array();
    }

    /**
     * Parse and validate a 24-byte CSCP v1 response packet.
     *
     * @return Thresholds object, or null if packet is malformed / CRC mismatch.
     */
    public static Thresholds parseResponse(byte[] packet) throws Exception {
        if (packet == null || packet.length != PACKET_SIZE) return null;

        ByteBuffer buf = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN);
        int  magic = buf.getInt();
        long crc   = buf.getInt() & 0xFFFFFFFFL;

        if (magic != CSCP_MAGIC) return null;

        byte[] ciphertext = new byte[16];
        buf.get(ciphertext);

        CRC32 crc32 = new CRC32();
        crc32.update(ciphertext);
        if (crc32.getValue() != crc) return null;

        SecretKeySpec keySpec = new SecretKeySpec(CSCP_KEY, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] plaintext = cipher.doFinal(ciphertext);

        int bpmMin  = plaintext[0] & 0xFF;
        int bpmMax  = plaintext[1] & 0xFF;
        int spo2Min = plaintext[2] & 0xFF;
        return new Thresholds(bpmMin, bpmMax, spo2Min);
    }
}
