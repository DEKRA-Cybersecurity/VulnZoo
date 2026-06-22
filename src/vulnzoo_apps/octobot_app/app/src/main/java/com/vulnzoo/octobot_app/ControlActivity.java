package com.vulnzoo.octobot_app;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.Button;
import android.widget.SeekBar;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * ControlActivity - OctoBot operator panel.
 *
 * Four sliders (base/left/right/claw) and the Record/Play/Stop/Demo buttons drive
 * the SAME cloud endpoints as the web UI:
 *   POST /api/servo/<n>   {"angle": N}
 *   POST /api/command/<name>
 *   GET  /api/state          (polled every 1s to reflect the firmware feedback)
 * The Flask session cookie captured at login authorises every request. A 401
 * (session gone) bounces back to LoginActivity.
 *
 * Servo writes are sent on release (onStopTrackingTouch) so dragging does not
 * flood the cloud->Modbus path.
 */
public class ControlActivity extends AppCompatActivity {

    private static final String TAG = "OctoBotControl";

    private String server;
    private String cookie;

    private SeekBar sbBase, sbLeft, sbRight, sbClaw;
    private TextView vBase, vLeft, vRight, vClaw, tvStatus, tvServer;
    private final boolean[] dragging = new boolean[5];   // index by api servo number 1..4

    private final Handler ui    = new Handler(Looper.getMainLooper());
    private final Handler poll  = new Handler(Looper.getMainLooper());
    private final ExecutorService exec = Executors.newSingleThreadExecutor();
    private boolean polling = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_control);

        SharedPreferences p = getSharedPreferences(LoginActivity.PREFS, MODE_PRIVATE);
        server = p.getString(LoginActivity.KEY_SERVER, LoginActivity.DEFAULT_SERVER);
        cookie = p.getString(LoginActivity.KEY_COOKIE, "");

        tvServer = findViewById(R.id.tvServer);
        tvStatus = findViewById(R.id.tvStatus);
        tvServer.setText(server);

        sbBase  = findViewById(R.id.sbBase);  vBase  = findViewById(R.id.vBase);
        sbLeft  = findViewById(R.id.sbLeft);  vLeft  = findViewById(R.id.vLeft);
        sbRight = findViewById(R.id.sbRight); vRight = findViewById(R.id.vRight);
        sbClaw  = findViewById(R.id.sbClaw);  vClaw  = findViewById(R.id.vClaw);

        // api servo index n -> cloud register n-1 (matches the web slider mapping)
        setupServo(sbBase,  vBase,  1, 65, 135);
        setupServo(sbLeft,  vLeft,  2, 80, 140);
        setupServo(sbRight, vRight, 3, 70, 120);
        setupServo(sbClaw,  vClaw,  4, 5,  30);

        ((Button) findViewById(R.id.btnRecord)).setOnClickListener(v -> sendCommand("record"));
        ((Button) findViewById(R.id.btnPlay)).setOnClickListener(v -> sendCommand("play"));
        ((Button) findViewById(R.id.btnStop)).setOnClickListener(v -> sendCommand("stop"));
        ((Button) findViewById(R.id.btnDemo)).setOnClickListener(v -> sendCommand("demo"));
        ((Button) findViewById(R.id.btnLogout)).setOnClickListener(v -> logout());
    }

    @Override protected void onResume()  { super.onResume();  polling = true;  poll.post(pollTask); }
    @Override protected void onPause()   { super.onPause();   polling = false; poll.removeCallbacks(pollTask); }
    @Override protected void onDestroy() { super.onDestroy(); exec.shutdownNow(); }

    private void setupServo(SeekBar sb, TextView label, int apiIndex, int min, int max) {
        sb.setMin(min);
        sb.setMax(max);
        sb.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            @Override public void onProgressChanged(SeekBar s, int progress, boolean fromUser) {
                label.setText(String.valueOf(progress));   // progress is already the real angle
            }
            @Override public void onStartTrackingTouch(SeekBar s) { dragging[apiIndex] = true; }
            @Override public void onStopTrackingTouch(SeekBar s) {
                dragging[apiIndex] = false;
                setServo(apiIndex, s.getProgress());
            }
        });
    }

    private void setServo(int n, int angle) {
        exec.execute(() -> {
            try {
                postJson("/api/servo/" + n, new JSONObject().put("angle", angle).toString());
            } catch (AuthExpired e) {
                ui.post(this::logout);
            } catch (Exception e) {
                ui.post(() -> tvStatus.setText("Move failed: " + e.getMessage()));
            }
        });
    }

    private void sendCommand(String name) {
        exec.execute(() -> {
            try {
                postJson("/api/command/" + name, "{}");
                ui.post(() -> tvStatus.setText("Sent: " + name));
            } catch (AuthExpired e) {
                ui.post(this::logout);
            } catch (Exception e) {
                ui.post(() -> tvStatus.setText(name + " failed: " + e.getMessage()));
            }
        });
    }

    private final Runnable pollTask = new Runnable() {
        @Override public void run() {
            exec.execute(() -> {
                try {
                    JSONObject s = new JSONObject(getStr("/api/state"));
                    ui.post(() -> applyState(s));
                } catch (AuthExpired e) {
                    ui.post(ControlActivity.this::logout);
                } catch (Exception ignored) {
                    /* transient network error - next tick retries */
                }
            });
            if (polling) poll.postDelayed(this, 1000);
        }
    };

    private void applyState(JSONObject s) {
        int[] f = new int[4];
        JSONArray fb = s.optJSONArray("feedback");
        if (fb != null && fb.length() >= 4) {
            for (int i = 0; i < 4; i++) f[i] = fb.optInt(i);
        } else {
            f[0] = s.optInt("base");  f[1] = s.optInt("left");
            f[2] = s.optInt("right"); f[3] = s.optInt("claw");
        }
        updateSlider(sbBase,  vBase,  1, f[0]);
        updateSlider(sbLeft,  vLeft,  2, f[1]);
        updateSlider(sbRight, vRight, 3, f[2]);
        updateSlider(sbClaw,  vClaw,  4, f[3]);
        tvStatus.setText("Connected  ·  cmd=" + s.optInt("command") + "  speed=" + s.optInt("speed"));
    }

    private void updateSlider(SeekBar sb, TextView label, int idx, int val) {
        if (dragging[idx]) return;                 // don't fight the user mid-drag
        if (val < sb.getMin() || val > sb.getMax()) return;
        sb.setProgress(val);
        label.setText(String.valueOf(val));
    }

    // --- http ---------------------------------------------------------------
    private HttpURLConnection open(String path, String method) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL("http://" + server + path).openConnection();
        c.setRequestMethod(method);
        c.setInstanceFollowRedirects(false);
        c.setConnectTimeout(4000);
        c.setReadTimeout(4000);
        if (cookie != null && !cookie.isEmpty()) c.setRequestProperty("Cookie", cookie);
        return c;
    }

    private void postJson(String path, String json) throws Exception {
        HttpURLConnection c = open(path, "POST");
        c.setRequestProperty("Content-Type", "application/json");
        c.setDoOutput(true);
        try (OutputStream os = c.getOutputStream()) {
            os.write(json.getBytes(StandardCharsets.UTF_8));
        }
        check(c);
    }

    private String getStr(String path) throws Exception {
        HttpURLConnection c = open(path, "GET");
        check(c);
        return new String(readAll(c.getInputStream()), StandardCharsets.UTF_8);
    }

    private void check(HttpURLConnection c) throws Exception {
        int code = c.getResponseCode();
        if (code == 401 || code == 302) throw new AuthExpired();   // session gone
        if (code >= 400) throw new Exception("HTTP " + code);
    }

    private byte[] readAll(java.io.InputStream is) throws java.io.IOException {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
        return bos.toByteArray();
    }

    private static class AuthExpired extends Exception { }

    private void logout() {
        getSharedPreferences(LoginActivity.PREFS, MODE_PRIVATE).edit()
                .remove(LoginActivity.KEY_COOKIE).apply();
        startActivity(new Intent(this, LoginActivity.class));
        finish();
    }
}
