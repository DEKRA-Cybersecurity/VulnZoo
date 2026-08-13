package com.vulnzoo.octobot_app;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONObject;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * LoginActivity - OctoBot app entry point.
 *
 * The API server is configured through split IP and Port fields. A "Detect WiFi"
 * button fills the prefix from the phone's current WiFi network, and a
 * "Test Connection" button saves the composed "ip:port" value and fetches the
 * firmware version from the unauthenticated /api/v0/firmware/version endpoint.
 * The version is shown at the bottom of the login panel and the server is saved
 * to SharedPreferences for the login attempt and for ControlActivity.
 *
 * Authenticates against the cloud's form-encoded POST /login and captures the
 * Flask session cookie, which is reused by ControlActivity on the /api/* endpoints
 * (same endpoints as the web UI).
 *
 * Plain HTTP, no TLS (lab).
 */
public class LoginActivity extends AppCompatActivity {

    private static final String TAG = "OctoBotLogin";
    static final String PREFS          = "octobot_prefs";
    static final String KEY_SERVER     = "server";          // "ip:port"
    static final String KEY_COOKIE     = "session_cookie";  // "session=..."
    static final String DEFAULT_SERVER = "192.168.2.2:5002";
    static final int    DEFAULT_PORT   = 5002;

    private EditText etApiIp, etApiPort, etUsername, etPassword;
    private Button   btnLogin, btnDetectWifi, btnTestConnection;
    private TextView tvStatus, tvFirmware;

    private final Handler         ui   = new Handler(Looper.getMainLooper());
    private final ExecutorService exec = Executors.newSingleThreadExecutor();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        // Route all HTTP over WiFi (the lab AP has no internet, so the default
        // network is mobile data). Done before the startup firmware fetch below.
        WifiNet.bindToWifi(this);

        etApiIp    = findViewById(R.id.etApiIp);
        etApiPort  = findViewById(R.id.etApiPort);
        etUsername = findViewById(R.id.etUsername);
        etPassword = findViewById(R.id.etPassword);
        btnLogin   = findViewById(R.id.btnLogin);
        btnDetectWifi     = findViewById(R.id.btnDetectWifi);
        btnTestConnection = findViewById(R.id.btnTestConnection);
        tvStatus   = findViewById(R.id.tvStatus);
        tvFirmware = findViewById(R.id.tvFirmware);

        // Restore last server or split the default into IP + port fields.
        String savedServer = getSharedPreferences(PREFS, MODE_PRIVATE)
                .getString(KEY_SERVER, DEFAULT_SERVER);
        String[] parts = savedServer.split(":");
        etApiIp.setText(parts[0]);
        etApiPort.setText(parts.length > 1 ? parts[1] : String.valueOf(DEFAULT_PORT));

        // The login panel shows the current firmware version by calling
        // /api/v2/firmware/version. The app does not reference the legacy v0 route;
        // an attacker must fuzz lower API versions to discover the unauthenticated
        // /api/v0/firmware endpoint (API5:2023 / IoT:I4).
        btnTestConnection.setOnClickListener(v -> testConnection());
        btnDetectWifi.setOnClickListener(v -> {
            String prefix = detectWifiNetworkPrefix();
            etApiIp.setText(prefix + "2");
            etApiPort.setText(String.valueOf(DEFAULT_PORT));
            status("Detected WiFi prefix: " + prefix, false);
        });

        btnLogin.setOnClickListener(v -> attemptLogin());

        // Try to populate the firmware label from the saved/default server on startup.
        fetchFirmwareVersion(getServerString());
    }

    @Override
    protected void onResume() {
        super.onResume();
        // Re-bind in case WiFi was joined after the app was already open.
        WifiNet.bindToWifi(this);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        exec.shutdownNow();
    }

    /** Build the canonical "ip:port" string from the split IP and Port fields. */
    private String getServerString() {
        String ip   = etApiIp.getText().toString().trim();
        String port = etApiPort.getText().toString().trim();
        if (ip.isEmpty())   ip   = "192.168.2.2";
        if (port.isEmpty()) port = String.valueOf(DEFAULT_PORT);
        return ip + ":" + port;
    }

    /**
     * Test the API connection. Saves the composed server string to preferences,
     * then fetches the firmware version from /api/v2/firmware/version so the bottom
     * panel reflects the reachable API. This single request both validates connectivity
     * and updates the firmware label, avoiding a second race-prone call. The app only
     * references the v2 endpoint; the unauthenticated v0 route is left for an attacker
     * to discover through fuzzing.
     */
    private void testConnection() {
        final String server = getServerString();
        getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                .putString(KEY_SERVER, server)
                .apply();

        btnTestConnection.setEnabled(false);
        status("Testing connection to " + server + "…", false);

        exec.execute(() -> {
            String result;
            String version = null;
            boolean ok = false;
            try {
                HttpURLConnection c = (HttpURLConnection)
                        new URL("http://" + server + "/api/v2/firmware/version").openConnection();
                c.setRequestMethod("GET");
                c.setInstanceFollowRedirects(false);
                c.setConnectTimeout(3000);
                c.setReadTimeout(3000);
                int code = c.getResponseCode();
                if (code == 200) {
                    JSONObject data = new JSONObject(
                            new String(readAll(c.getInputStream()), StandardCharsets.UTF_8));
                    version = data.optString("version", "unknown");
                    result = "Connected successfully";
                    ok = true;
                } else {
                    result = "API reachable but returned HTTP " + code;
                }
            } catch (java.net.ConnectException | java.net.UnknownHostException e) {
                result = "Cannot connect to " + server;
            } catch (Exception e) {
                result = "Connection test failed: " + e.getMessage();
            }

            final String msg = result;
            final boolean success = ok;
            final String fw = version;
            ui.post(() -> {
                btnTestConnection.setEnabled(true);
                status(msg, !success);
                tvFirmware.setText(fw != null ? "Firmware: " + fw : "Firmware: unavailable");
            });
        });
    }

    /**
     * Reads the phone's current WiFi IP and returns the network prefix
     * (first three octets + trailing dot), e.g. "192.168.1.".
     * Falls back to "192.168.2." if WiFi is unavailable.
     */
    private String detectWifiNetworkPrefix() {
        try {
            WifiManager wm = (WifiManager) getApplicationContext()
                    .getSystemService(Context.WIFI_SERVICE);
            if (wm == null) return "192.168.2.";

            int ipInt = wm.getConnectionInfo().getIpAddress();
            if (ipInt == 0) return "192.168.2.";

            // Android stores the IP as a little-endian int
            int a = ipInt         & 0xFF;
            int b = (ipInt >>  8) & 0xFF;
            int c = (ipInt >> 16) & 0xFF;
            return a + "." + b + "." + c + ".";
        } catch (Exception e) {
            Log.w(TAG, "WiFi IP detection failed: " + e.getMessage());
            return "192.168.2.";
        }
    }

    /**
     * Fetch the firmware version from /api/v2/firmware/version and show it at the
     * bottom of the login panel. The app only references the v2 endpoint; an attacker
     * would have to fuzz lower API versions to discover the unauthenticated v0 route.
     */
    private void fetchFirmwareVersion(String server) {
        ui.post(() -> tvFirmware.setText("Firmware: checking…"));
        exec.execute(() -> {
            String label;
            try {
                HttpURLConnection c = (HttpURLConnection)
                        new URL("http://" + server + "/api/v2/firmware/version").openConnection();
                c.setRequestMethod("GET");
                c.setInstanceFollowRedirects(false);
                c.setConnectTimeout(3000);
                c.setReadTimeout(3000);
                int code = c.getResponseCode();
                if (code == 200) {
                    JSONObject data = new JSONObject(
                            new String(readAll(c.getInputStream()), StandardCharsets.UTF_8));
                    label = "Firmware: " + data.optString("version", "unknown");
                } else {
                    label = "Firmware: unavailable";
                }
            } catch (Exception e) {
                label = "Firmware: offline";
                Log.w(TAG, "firmware version fetch failed", e);
            }
            final String text = label;
            ui.post(() -> tvFirmware.setText(text));
        });
    }

    private byte[] readAll(java.io.InputStream is) throws java.io.IOException {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
        return bos.toByteArray();
    }

    private void attemptLogin() {
        final String server = getServerString();
        final String user   = etUsername.getText().toString().trim();
        final String pass   = etPassword.getText().toString();

        if (user.isEmpty() || pass.isEmpty()) {
            status("Username and password are required.", true);
            return;
        }

        setUiEnabled(false);
        status("Connecting to " + server + "…", false);

        exec.execute(() -> {
            String err;
            try {
                String cookie = doLogin(server, user, pass);
                if (cookie != null) {
                    getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                            .putString(KEY_SERVER, server)
                            .putString(KEY_COOKIE, cookie)
                            .apply();
                    ui.post(() -> {
                        startActivity(new Intent(this, ControlActivity.class));
                        finish();
                    });
                    return;
                }
                err = "Invalid credentials.";
            } catch (java.net.ConnectException e) {
                err = "Cannot connect to " + server + ". Is the cloud running?";
            } catch (java.net.UnknownHostException e) {
                err = "Host not found: " + server;
            } catch (java.net.SocketTimeoutException e) {
                err = "Timeout connecting to " + server + ".";
            } catch (Exception e) {
                err = (e.getMessage() == null || e.getMessage().isEmpty()) ? "Login error." : e.getMessage();
                Log.w(TAG, "login error", e);
            }
            final String m = err;
            ui.post(() -> { status(m, true); setUiEnabled(true); });
        });
    }

    /**
     * Form-encoded POST /login. On success the cloud replies 302 (redirect to /)
     * with the Flask session cookie; we keep redirects off and read Set-Cookie
     * ourselves. Returns the cookie string ("session=...") on success, null on 401.
     */
    private String doLogin(String server, String user, String pass) throws Exception {
        URL url = new URL("http://" + server + "/login");
        HttpURLConnection c = (HttpURLConnection) url.openConnection();
        c.setRequestMethod("POST");
        c.setInstanceFollowRedirects(false);     // success is a 302 we don't follow
        c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        c.setDoOutput(true);
        c.setConnectTimeout(5000);
        c.setReadTimeout(5000);

        String body = "username=" + URLEncoder.encode(user, "UTF-8")
                    + "&password=" + URLEncoder.encode(pass, "UTF-8");
        try (OutputStream os = c.getOutputStream()) {
            os.write(body.getBytes(StandardCharsets.UTF_8));
        }

        int code = c.getResponseCode();           // 302 = ok, 401 = bad creds
        if (code == 302 || code == 303 || code == 200) {
            List<String> setCookies = c.getHeaderFields().get("Set-Cookie");
            StringBuilder cookie = new StringBuilder();
            if (setCookies != null) {
                for (String sc : setCookies) {
                    if (cookie.length() > 0) cookie.append("; ");
                    cookie.append(sc.split(";", 2)[0]);   // keep only name=value
                }
            }
            return cookie.length() > 0 ? cookie.toString() : null;
        }
        return null;
    }

    private void setUiEnabled(boolean e) {
        btnLogin.setEnabled(e);
        btnDetectWifi.setEnabled(e);
        btnTestConnection.setEnabled(e);
        etApiIp.setEnabled(e);
        etApiPort.setEnabled(e);
        etUsername.setEnabled(e);
        etPassword.setEnabled(e);
    }

    private void status(String msg, boolean error) {
        tvStatus.setVisibility(View.VISIBLE);
        tvStatus.setTextColor(error ? 0xFFE53935 : 0xFF607D8B);
        tvStatus.setText(msg);
    }
}
