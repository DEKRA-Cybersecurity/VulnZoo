package com.vulnzoo.bulbbee_app.cloud;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Minimal REST client for the BulbBee cloud API (BULB-CLD / BULB-R1..R3), the
 * app's remote transport (BULB-R4). Dependency-free (java.net only, no org.json),
 * so it is unit-runnable off-device and is exactly the class the app ships.
 *
 * Client-side weaknesses (intentional, consistent with the app):
 *  - talks plain HTTP by default (no TLS), so the bearer JWT and the commands
 *    travel in the clear (the plaintext plane).
 *  - trusts any host, no certificate pinning.
 *  - the login is username-only (the API's weak auth); the JWT it returns is a
 *    long-lived bearer that {@code CloudRepository} stores in the clear (M9).
 */
public class CloudClient {

    private final String base;      // e.g. http://192.168.2.10:5004
    private String token;           // bearer JWT from /api/login

    public CloudClient(String base) {
        this.base = base.replaceAll("/+$", "");
    }

    public String token() { return token; }
    public void setToken(String t) { this.token = t; }

    /** POST /api/login {"user":...} -> the JWT (also stored on this client). */
    public String login(String user) throws IOException {
        return login(user, "");
    }

    /** The outcome of a login: the JWT on success, plus the HTTP status and the
     *  API `error` field so the caller can show a message matching the response. */
    public static final class LoginResult {
        public final String token;
        public final int status;
        public final String error;
        LoginResult(String token, int status, String error) {
            this.token = token;
            this.status = status;
            this.error = error;
        }
        public boolean ok() { return token != null; }
    }

    /** POST /api/login {"user":...,"password":...} -> the JWT. The default ignores
     *  the password (API2), secure verifies it (BULB-R6). Stored on this client. */
    public String login(String user, String password) throws IOException {
        return loginResult(user, password).token;
    }

    /** POST /api/login returning the full outcome (status + `error` body), so the
     *  UI can show a distinct message per API response. */
    public LoginResult loginResult(String user, String password) throws IOException {
        String body = "{\"user\":\"" + esc(user) + "\",\"password\":\"" + esc(password) + "\"}";
        HttpURLConnection c = open("POST", "/api/login", false);
        writeBody(c, body);
        int code = c.getResponseCode();
        String resp = read(code < 400 ? c.getInputStream() : c.getErrorStream());
        String tok = extractToken(resp);
        if (tok != null) {
            this.token = tok;
        }
        return new LoginResult(tok, code, extractField(resp, "error"));
    }

    /** POST /api/claim -> a single-use claim token to bind a bulb to this account
     *  (BULB-R6). The app hands it to the bulb over BLE during onboarding. */
    public String claim() throws IOException {
        return extractField(send("POST", "/api/claim", "{}", true), "claim_token");
    }

    /** GET /api/mybulbs -> the first bulb_id bound to this account, or null. */
    public String firstBulbId() throws IOException {
        return firstKey(send("GET", "/api/mybulbs", null, true));
    }

    /** POST /api/register {device_id} -> the bulb_id bound to this account (BULB-R2).
     *  Used at sign-in to bind the real device serial the app read over BLE. */
    public String register(String deviceId) throws IOException {
        return extractField(send("POST", "/api/register",
                "{\"device_id\":\"" + esc(deviceId) + "\"}", true), "bulb_id");
    }

    /** POST /api/bulb/&lt;id&gt;/state &lt;json&gt; -> HTTP status. json is the same
     *  shape the BLE path writes, e.g. {"color":[1,2,3]} or {"power":true}. */
    public int control(String bulbId, String json) throws IOException {
        return status("POST", "/api/bulb/" + enc(bulbId) + "/state", json);
    }

    /** POST /api/bulb/&lt;id&gt;/scene {"scene":...} -> HTTP status. */
    public int scene(String bulbId, String scene) throws IOException {
        return status("POST", "/api/bulb/" + enc(bulbId) + "/scene",
                "{\"scene\":\"" + esc(scene) + "\"}");
    }

    /** GET /api/bulb/&lt;id&gt;/state -> the raw state JSON body (BULB-R3 live state). */
    public String getState(String bulbId) throws IOException {
        return send("GET", "/api/bulb/" + enc(bulbId) + "/state", null, true);
    }

    // ── HTTP plumbing ─────────────────────────────────────────────────

    private int status(String method, String path, String body) throws IOException {
        HttpURLConnection c = open(method, path, true);
        writeBody(c, body);
        int code = c.getResponseCode();
        drain(c, code);
        return code;
    }

    private String send(String method, String path, String body, boolean auth) throws IOException {
        HttpURLConnection c = open(method, path, auth);
        if (body != null) writeBody(c, body);
        int code = c.getResponseCode();
        return read(code < 400 ? c.getInputStream() : c.getErrorStream());
    }

    private HttpURLConnection open(String method, String path, boolean auth) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(base + path).openConnection();
        c.setRequestMethod(method);
        c.setConnectTimeout(4000);
        c.setReadTimeout(4000);
        c.setRequestProperty("Content-Type", "application/json");
        if (auth && token != null) c.setRequestProperty("Authorization", "Bearer " + token);
        return c;
    }

    private static void writeBody(HttpURLConnection c, String body) throws IOException {
        c.setDoOutput(true);
        try (OutputStream os = c.getOutputStream()) {
            os.write(body.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static String read(InputStream in) throws IOException {
        if (in == null) return "";
        try (ByteArrayOutputStream bo = new ByteArrayOutputStream()) {
            byte[] buf = new byte[1024];
            int n;
            while ((n = in.read(buf)) != -1) bo.write(buf, 0, n);
            return bo.toString("UTF-8");
        }
    }

    private static void drain(HttpURLConnection c, int code) {
        try { read(code < 400 ? c.getInputStream() : c.getErrorStream()); }
        catch (IOException ignored) { }
    }

    // ── tiny helpers (no JSON lib) ────────────────────────────────────

    static String extractToken(String json) { return extractField(json, "token"); }

    /** The string value of a top-level JSON field, or null (no JSON lib). */
    static String extractField(String json, String field) {
        int i = json.indexOf("\"" + field + "\"");
        if (i < 0) return null;
        int q1 = json.indexOf('"', json.indexOf(':', i) + 1);
        int q2 = json.indexOf('"', q1 + 1);
        return (q1 < 0 || q2 < 0) ? null : json.substring(q1 + 1, q2);
    }

    /** The first top-level key of a JSON object (mybulbs is keyed by bulb_id). */
    static String firstKey(String json) {
        int q1 = json.indexOf('"');
        int q2 = q1 < 0 ? -1 : json.indexOf('"', q1 + 1);
        return q2 < 0 ? null : json.substring(q1 + 1, q2);
    }

    private static String esc(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String enc(String s) {
        try { return URLEncoder.encode(s, "UTF-8"); }
        catch (IOException e) { return s; }
    }

    // ── runnable check: `--selfcheck` (offline) or a base URL (live drive) ──

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || args[0].equals("--selfcheck")) {
            if (!"abc".equals(extractToken("{\"token\":\"abc\"}"))) throw new AssertionError("token parse");
            if (extractToken("{}") != null) throw new AssertionError("empty -> null");
            System.out.println("CloudClient selfcheck OK");
            return;
        }
        String base = args[0];                              // e.g. http://127.0.0.1:5004
        String user = args.length > 1 ? args[1] : "alice";
        String bulb = args.length > 2 ? args[2] : "bulb-2";
        CloudClient cc = new CloudClient(base);
        String jwt = cc.login(user);
        System.out.println("login " + user + " -> token len " + (jwt == null ? 0 : jwt.length()));
        System.out.println("control " + bulb + " -> " + cc.control(bulb, "{\"power\":true,\"color\":[10,20,30]}"));
        System.out.println("scene " + bulb + " breathe -> " + cc.scene(bulb, "breathe"));
        System.out.println("state " + bulb + " -> " + cc.getState(bulb));
    }
}
