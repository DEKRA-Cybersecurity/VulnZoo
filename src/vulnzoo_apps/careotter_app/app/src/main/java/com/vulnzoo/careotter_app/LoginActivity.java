package com.vulnzoo.careotter_app;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONObject;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * LoginActivity — CareOtter app entry point.
 *
 * Authenticates via HTTP POST to the Cloud API. The API server IP is composed
 * from two fields:
 *   etApiUrl    — network prefix (e.g. "192.168.1."), auto-detected from the
 *                 phone's own WiFi IP. Editable in case the detected prefix
 *                 is wrong.
 *   etHostOctet — last octet of the API server IP (e.g. "2"). The user only
 *                 needs to change this number.
 *
 * The full API URL is built as:  http://<etApiUrl><etHostOctet>:5002
 *
 * Routes to MainActivity (patient BLE) or AdminActivity (IGP v4) based on
 * the role returned in the JWT response.
 *
 * VULNERABILITIES:
 * 1. Credentials sent over plain HTTP — no TLS enforcement
 * 2. JWT stored in SharedPreferences without encryption
 * 3. No certificate pinning
 */
public class LoginActivity extends AppCompatActivity {

    private static final String TAG              = "LoginActivity";
    private static final String PREFS_NAME       = "careotter_prefs";
    private static final String KEY_TOKEN        = "jwt_token";
    private static final String KEY_ROLE         = "user_role";
    private static final String KEY_USERNAME     = "username";
    private static final String KEY_API_URL      = "api_url";
    private static final String KEY_API_PREFIX   = "api_prefix";
    private static final String KEY_API_HOST     = "api_host";
    private static final String DEFAULT_PREFIX   = "192.168.2.";
    private static final String DEFAULT_HOST     = "2";
    private static final int    API_PORT         = 5002;

    private EditText  etUsername;
    private EditText  etPassword;
    private ImageView btnTogglePassword;
    private boolean   passwordVisible = false;
    private EditText  etApiUrl;      // network prefix, e.g. "192.168.1."
    private EditText  etHostOctet;   // last octet, e.g. "2"
    private Button    btnLogin;
    private Button    btnScanApi;
    private Button    btnPing;
    private TextView  tvStatus;

    private final Handler         uiHandler = new Handler(Looper.getMainLooper());
    private final ExecutorService executor  = Executors.newSingleThreadExecutor();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        etUsername  = findViewById(R.id.etUsername);
        etPassword  = findViewById(R.id.etPassword);
        btnTogglePassword = findViewById(R.id.btnTogglePassword);
        etApiUrl    = findViewById(R.id.etApiUrl);
        etHostOctet = findViewById(R.id.etHostOctet);
        btnLogin    = findViewById(R.id.btnLogin);
        btnScanApi  = findViewById(R.id.btnScanApi);
        btnPing     = findViewById(R.id.btnPing);
        tvStatus    = findViewById(R.id.tvLoginStatus);

        // Restore last-used prefix + host, or detect from current WiFi
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        String savedPrefix = prefs.getString(KEY_API_PREFIX, "");
        String savedHost   = prefs.getString(KEY_API_HOST, "");

        if (!savedPrefix.isEmpty()) {
            etApiUrl.setText(savedPrefix);
            etHostOctet.setText(savedHost.isEmpty() ? DEFAULT_HOST : savedHost);
        } else {
            // Auto-detect network prefix from phone's WiFi interface
            String detectedPrefix = detectWifiNetworkPrefix();
            etApiUrl.setText(detectedPrefix);
            etHostOctet.setText(DEFAULT_HOST);
        }

        tvStatus.setVisibility(android.view.View.VISIBLE);
        tvStatus.setTextColor(0xFF9AA0A6);
        tvStatus.setText("Edit only the last octet if the detected network prefix is correct");

        btnLogin.setOnClickListener(v -> attemptLogin());

        // Password visibility toggle — hidden by default
        btnTogglePassword.setOnClickListener(v -> {
            passwordVisible = !passwordVisible;
            int sel = etPassword.getSelectionEnd();
            etPassword.setTransformationMethod(passwordVisible
                    ? HideReturnsTransformationMethod.getInstance()
                    : PasswordTransformationMethod.getInstance());
            btnTogglePassword.setImageResource(passwordVisible
                    ? R.drawable.ic_password_show
                    : R.drawable.ic_password_hide);
            btnTogglePassword.setContentDescription(
                    passwordVisible ? "Hide password" : "Show password");
            etPassword.setSelection(sel);
        });

        // Reset to WiFi-detected prefix + default host
        btnScanApi.setText("Detect WiFi Prefix");
        btnScanApi.setOnClickListener(v -> {
            String prefix = detectWifiNetworkPrefix();
            etApiUrl.setText(prefix);
            etHostOctet.setText(DEFAULT_HOST);
            tvStatus.setVisibility(android.view.View.VISIBLE);
            tvStatus.setTextColor(0xFF9AA0A6);
            tvStatus.setText("Network detected: " + prefix + DEFAULT_HOST);
        });

        // Ping the API server (ICMP reachability via InetAddress.isReachable)
        btnPing.setOnClickListener(v -> pingApi());
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdownNow();
    }

    // ── Ping / reachability check ────────────────────────────────────────────

    /**
     * Tests ICMP reachability of the API server IP using InetAddress.isReachable().
     * On Android, isReachable() sends an ICMP echo request if the process has
     * sufficient privileges; otherwise it falls back to a TCP connect on port 7.
     * Runs on the executor thread to avoid blocking the main thread.
     */
    private void pingApi() {
        String prefix    = etApiUrl.getText().toString().trim();
        String hostOctet = etHostOctet.getText().toString().trim();
        if (prefix.isEmpty())    prefix    = DEFAULT_PREFIX;
        if (hostOctet.isEmpty()) hostOctet = DEFAULT_HOST;
        if (!prefix.endsWith(".")) prefix = prefix + ".";

        final String ip = prefix + hostOctet;

        btnPing.setEnabled(false);
        tvStatus.setVisibility(android.view.View.VISIBLE);
        tvStatus.setTextColor(0xFF9AA0A6);
        tvStatus.setText("Pinging " + ip + "…");

        executor.execute(() -> {
            long start = System.currentTimeMillis();
            boolean reachable = false;
            String detail;
            try {
                java.net.InetAddress addr = java.net.InetAddress.getByName(ip);
                reachable = addr.isReachable(3000);
                long rtt = System.currentTimeMillis() - start;
                detail = reachable
                        ? ip + " reachable  (" + rtt + " ms)"
                        : ip + " unreachable (timeout 3 s)";
            } catch (Exception e) {
                detail = ip + " error: " + e.getMessage();
            }

            final boolean ok  = reachable;
            final String  msg = detail;
            uiHandler.post(() -> {
                btnPing.setEnabled(true);
                tvStatus.setVisibility(android.view.View.VISIBLE);
                tvStatus.setTextColor(ok ? 0xFF2E7D32 : 0xFFE53935);
                tvStatus.setText(ok ? "✓ " + msg : "✗ " + msg);
            });
        });
    }

    // ── WiFi prefix detection ────────────────────────────────────────────────

    /**
     * Reads the phone's current WiFi IP and returns the network prefix
     * (first three octets + trailing dot), e.g. "192.168.1."
     * Falls back to DEFAULT_PREFIX if WiFi is unavailable or the API
     * is not accessible.
     *
     * Requires ACCESS_WIFI_STATE (normal permission, no runtime request).
     */
    private String detectWifiNetworkPrefix() {
        try {
            WifiManager wm = (WifiManager) getApplicationContext()
                    .getSystemService(Context.WIFI_SERVICE);
            if (wm == null) return DEFAULT_PREFIX;

            int ipInt = wm.getConnectionInfo().getIpAddress();
            if (ipInt == 0) return DEFAULT_PREFIX;

            // Android stores the IP as a little-endian int
            int a = ipInt         & 0xFF;
            int b = (ipInt >>  8) & 0xFF;
            int c = (ipInt >> 16) & 0xFF;
            return a + "." + b + "." + c + ".";
        } catch (Exception e) {
            Log.w(TAG, "WiFi IP detection failed: " + e.getMessage());
            return DEFAULT_PREFIX;
        }
    }

    // ── Login ────────────────────────────────────────────────────────────────

    private void attemptLogin() {
        String username  = etUsername.getText().toString().trim();
        String password  = etPassword.getText().toString();
        String prefix    = etApiUrl.getText().toString().trim();
        String hostOctet = etHostOctet.getText().toString().trim();

        if (prefix.isEmpty())    prefix    = DEFAULT_PREFIX;
        if (hostOctet.isEmpty()) hostOctet = DEFAULT_HOST;

        // Ensure prefix ends with a dot
        if (!prefix.endsWith(".")) prefix = prefix + ".";

        // Build full URL — VULNERABILITY: plain HTTP, no TLS
        final String apiIp  = prefix + hostOctet;
        final String apiUrl = "http://" + apiIp + ":" + API_PORT;

        if (username.isEmpty() || password.isEmpty()) {
            tvStatus.setVisibility(android.view.View.VISIBLE);
            tvStatus.setTextColor(0xFFE53935);
            tvStatus.setText("Username and password are required.");
            return;
        }

        final String finalPrefix    = prefix;
        final String finalHostOctet = hostOctet;

        setUiEnabled(false);
        tvStatus.setVisibility(android.view.View.VISIBLE);
        tvStatus.setTextColor(0xFF9AA0A6);
        tvStatus.setText("Connecting to " + apiIp + "…");

        executor.execute(() -> {
            String errorMsg = null;
            try {
                String result = doLogin(apiUrl, username, password);
                JSONObject json = new JSONObject(result);

                if (json.has("token")) {
                    String token = json.getString("token");
                    String role  = json.optString("role", "patient");
                    String uname = json.optString("username", username);

                    // VULNERABILITY: JWT stored unencrypted in SharedPreferences
                    getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit()
                            .putString(KEY_TOKEN,      token)
                            .putString(KEY_ROLE,       role)
                            .putString(KEY_USERNAME,   uname)
                            .putString(KEY_API_URL,    apiUrl)
                            .putString(KEY_API_PREFIX, finalPrefix)
                            .putString(KEY_API_HOST,   finalHostOctet)
                            .apply();

                    uiHandler.post(() -> routeByRole(role));
                    return;
                } else {
                    errorMsg = json.optString("error", "Login failed — no token received.");
                    Log.w(TAG, "Login rejected: " + errorMsg);
                }
            } catch (java.net.UnknownHostException e) {
                errorMsg = "API not found at " + apiIp + ". Check the IP.";
                Log.w(TAG, "UnknownHost", e);
            } catch (java.net.ConnectException e) {
                errorMsg = "Cannot connect to " + apiIp + ". Is Docker running?";
                Log.w(TAG, "ConnectException", e);
            } catch (java.net.SocketTimeoutException e) {
                errorMsg = "Timeout connecting to " + apiIp + ".";
                Log.w(TAG, "SocketTimeout", e);
            } catch (Exception e) {
                errorMsg = e.getMessage();
                if (errorMsg == null || errorMsg.isEmpty()) errorMsg = "Unexpected error.";
                Log.e(TAG, "Login error", e);
            }

            final String msg = errorMsg;
            uiHandler.post(() -> {
                tvStatus.setVisibility(android.view.View.VISIBLE);
                tvStatus.setText(msg);
                tvStatus.setTextColor(0xFFE53935);
                setUiEnabled(true);
            });
        });
    }

    /** HTTP POST to /api/auth/login — plaintext, no TLS (intentional vuln). */
    private String doLogin(String baseUrl, String username, String password) throws Exception {
        URL url = new URL(baseUrl + "/api/auth/login");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);

        JSONObject body = new JSONObject();
        body.put("username", username);
        body.put("password", password);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.toString().getBytes(StandardCharsets.UTF_8));
        }

        int code = conn.getResponseCode();
        java.io.InputStream is = (code < 400) ? conn.getInputStream() : conn.getErrorStream();
        String response = new String(readAllBytesCompat(is), StandardCharsets.UTF_8);

        if (code >= 400) {
            String msg = "Server error (" + code + ")";
            try {
                JSONObject err = new JSONObject(response);
                String serverError = err.optString("error", "");
                String serverCode  = err.optString("code", "");
                if (!serverError.isEmpty()) {
                    msg = serverError;
                    if ("AUTH_FAIL".equals(serverCode))          msg = "Invalid username or password";
                    else if ("FORBIDDEN".equals(serverCode))     msg = "Access denied for this role";
                    else if ("MISSING_FIELD".equals(serverCode)) msg = "Field required";
                    else if ("DB_ERROR".equals(serverCode))      msg = "Database unavailable";
                }
            } catch (Exception ignored) {}
            throw new Exception(msg);
        }
        return response;
    }

    private byte[] readAllBytesCompat(java.io.InputStream is) throws java.io.IOException {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int n;
        while ((n = is.read(buffer)) != -1) bos.write(buffer, 0, n);
        return bos.toByteArray();
    }

    private void routeByRole(String role) {
        startActivity(new Intent(this, "admin".equals(role)
                ? AdminActivity.class : MainActivity.class));
        finish();
    }

    private void setUiEnabled(boolean enabled) {
        btnLogin.setEnabled(enabled);
        btnPing.setEnabled(enabled);
        etUsername.setEnabled(enabled);
        etPassword.setEnabled(enabled);
        etApiUrl.setEnabled(enabled);
        etHostOctet.setEnabled(enabled);
    }
}
