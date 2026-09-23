package com.vulnzoo.bulbbee_app.local;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Direct-LAN transport (BULB-R5): drives the bulb over the AES-CCM {@code :6668}
 * plane (BULB-A4) without the cloud. The frame is the server's:
 * {@code nonce(11) || ciphertext || tag(16)}, length-prefixed with a 2-byte
 * big-endian header, plaintext = the same control JSON the other legs use.
 *
 * AES-CCM is not in the Android/JDK javax.crypto provider, so this uses the
 * BouncyCastle lightweight {@code CCMBlockCipher} directly.
 *
 * VULNERABILITY (client side of BULB-P03 / BULB-P06): the local key is the static
 * 16-byte firmware key, identical on every device, embedded here. Being on the
 * LAN plus this shared key is control, no per-device secret, no owner check.
 */
public class LocalClient {

    /** BULB-P03: the static firmware key, the same on every unit. */
    public static final byte[] STATIC_LOCAL_KEY =
            "bulbbee-local-16".getBytes(StandardCharsets.US_ASCII);   // 16 bytes

    private static final int NONCE_LEN = 11;
    private static final int TAG_BITS = 128;                          // 16-byte tag
    private static final SecureRandom RNG = new SecureRandom();

    private final byte[] key;

    public LocalClient() { this(STATIC_LOCAL_KEY); }
    public LocalClient(byte[] key) { this.key = key; }

    // ── AES-CCM frame codec ───────────────────────────────────────────

    public static byte[] encryptFrame(byte[] key, byte[] pt) throws Exception {
        byte[] nonce = new byte[NONCE_LEN];
        RNG.nextBytes(nonce);
        CCMBlockCipher ccm = new CCMBlockCipher(new AESEngine());
        ccm.init(true, new AEADParameters(new KeyParameter(key), TAG_BITS, nonce));
        byte[] out = new byte[ccm.getOutputSize(pt.length)];         // ct || tag
        int n = ccm.processBytes(pt, 0, pt.length, out, 0);
        ccm.doFinal(out, n);
        byte[] frame = new byte[NONCE_LEN + out.length];
        System.arraycopy(nonce, 0, frame, 0, NONCE_LEN);
        System.arraycopy(out, 0, frame, NONCE_LEN, out.length);
        return frame;
    }

    /** Return the plaintext, or null on a malformed frame or a bad CCM tag. */
    public static byte[] decryptFrame(byte[] key, byte[] frame) {
        if (frame.length < NONCE_LEN + TAG_BITS / 8) return null;
        byte[] nonce = Arrays.copyOfRange(frame, 0, NONCE_LEN);
        byte[] body = Arrays.copyOfRange(frame, NONCE_LEN, frame.length);
        try {
            CCMBlockCipher ccm = new CCMBlockCipher(new AESEngine());
            ccm.init(false, new AEADParameters(new KeyParameter(key), TAG_BITS, nonce));
            byte[] out = new byte[ccm.getOutputSize(body.length)];
            int n = ccm.processBytes(body, 0, body.length, out, 0);
            n += ccm.doFinal(out, n);
            return n == out.length ? out : Arrays.copyOf(out, n);
        } catch (Exception e) {
            return null;
        }
    }

    // ── transport ─────────────────────────────────────────────────────

    /** Send one control JSON to the bulb's LAN port, return the decrypted reply
     *  state JSON, or null. */
    public String send(String host, int port, String json) throws Exception {
        byte[] frame = encryptFrame(key, json.getBytes(StandardCharsets.UTF_8));
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), 3000);
            s.setSoTimeout(3000);
            OutputStream os = s.getOutputStream();
            os.write(prefix(frame.length));
            os.write(frame);
            os.flush();
            InputStream in = s.getInputStream();
            byte[] hdr = readN(in, 2);
            if (hdr == null) return null;
            int n = ((hdr[0] & 0xFF) << 8) | (hdr[1] & 0xFF);
            byte[] reply = readN(in, n);
            if (reply == null) return null;
            byte[] pt = decryptFrame(key, reply);
            return pt == null ? null : new String(pt, StandardCharsets.UTF_8);
        }
    }

    /** True if the bulb's LAN port accepts a TCP connection (reachability probe). */
    public static boolean reachable(String host, int port, int timeoutMs) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] prefix(int len) {
        return new byte[]{(byte) ((len >> 8) & 0xFF), (byte) (len & 0xFF)};
    }

    private static byte[] readN(InputStream in, int n) throws java.io.IOException {
        byte[] buf = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(buf, off, n - off);
            if (r < 0) return null;
            off += r;
        }
        return buf;
    }

    // ── runnable check ────────────────────────────────────────────────

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || args[0].equals("--selfcheck")) {
            byte[] pt = "{\"scene\":\"solid\"}".getBytes(StandardCharsets.UTF_8);
            byte[] frame = encryptFrame(STATIC_LOCAL_KEY, pt);
            if (!Arrays.equals(pt, decryptFrame(STATIC_LOCAL_KEY, frame))) throw new AssertionError("round-trip");
            byte[] bad = frame.clone(); bad[bad.length - 1] ^= 0x01;
            if (decryptFrame(STATIC_LOCAL_KEY, bad) != null) throw new AssertionError("tamper -> null");
            System.out.println("LocalClient selfcheck OK");
            return;
        }
        if (args[0].equals("--emit")) {        // print a frame (hex) for the given JSON
            System.out.println(hex(encryptFrame(STATIC_LOCAL_KEY, args[1].getBytes(StandardCharsets.UTF_8))));
            return;
        }
        if (args[0].equals("--decode")) {      // decrypt a hex frame under the static key
            byte[] pt = decryptFrame(STATIC_LOCAL_KEY, unhex(args[1]));
            System.out.println(pt == null ? "NULL" : new String(pt, StandardCharsets.UTF_8));
            return;
        }
        String host = args[0];                 // live: host port [json]
        int port = Integer.parseInt(args[1]);
        String json = args.length > 2 ? args[2] : "{\"scene\":\"breathe\"}";
        System.out.println("reply: " + new LocalClient().send(host, port, json));
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static byte[] unhex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++)
            b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }
}
