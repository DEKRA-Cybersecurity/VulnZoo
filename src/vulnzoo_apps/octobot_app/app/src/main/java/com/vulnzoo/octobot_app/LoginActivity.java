package com.vulnzoo.octobot_app;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

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
 * One inline field holds the cloud server as "ip:port" (the Docker WiFi/Ethernet
 * interface; port defaults to 5003 if omitted). Authenticates against the cloud's
 * form-encoded POST /login and captures the Flask session cookie, which is reused
 * by ControlActivity on the /api/* endpoints (same endpoints as the web UI).
 *
 * Plain HTTP, no TLS (lab).
 */
public class LoginActivity extends AppCompatActivity {

    private static final String TAG = "OctoBotLogin";
    static final String PREFS          = "octobot_prefs";
    static final String KEY_SERVER     = "server";          // "ip:port"
    static final String KEY_COOKIE     = "session_cookie";  // "session=..."
    static final String DEFAULT_SERVER = "192.168.2.2:5003";
    static final int    DEFAULT_PORT   = 5003;

    private EditText etServer, etUsername, etPassword;
    private Button   btnLogin;
    private TextView tvStatus;

    private final Handler         ui   = new Handler(Looper.getMainLooper());
    private final ExecutorService exec = Executors.newSingleThreadExecutor();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        etServer   = findViewById(R.id.etServer);
        etUsername = findViewById(R.id.etUsername);
        etPassword = findViewById(R.id.etPassword);
        btnLogin   = findViewById(R.id.btnLogin);
        tvStatus   = findViewById(R.id.tvStatus);

        etServer.setText(getSharedPreferences(PREFS, MODE_PRIVATE)
                .getString(KEY_SERVER, DEFAULT_SERVER));

        btnLogin.setOnClickListener(v -> attemptLogin());
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        exec.shutdownNow();
    }

    /** Trim, default empty -> DEFAULT_SERVER, and append :5003 if no port given. */
    private String normalizeServer(String s) {
        s = s.trim();
        if (s.isEmpty()) return DEFAULT_SERVER;
        if (!s.contains(":")) s = s + ":" + DEFAULT_PORT;
        return s;
    }

    private void attemptLogin() {
        final String server = normalizeServer(etServer.getText().toString());
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
        etServer.setEnabled(e);
        etUsername.setEnabled(e);
        etPassword.setEnabled(e);
    }

    private void status(String msg, boolean error) {
        tvStatus.setVisibility(View.VISIBLE);
        tvStatus.setTextColor(error ? 0xFFE53935 : 0xFF607D8B);
        tvStatus.setText(msg);
    }
}
