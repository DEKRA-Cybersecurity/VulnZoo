package com.vulnzoo.careotter_app;

import android.Manifest;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;

/**
 * MainActivity — CareOtter Patient Monitoring App
 *
 * BLE-only cardiac monitor. Displays live BPM and SpO2 from CareOtter_HR device.
 * Alerts when vitals exceed thresholds. Logs all readings to external storage.
 *
 * VULNERABILITIES:
 * 1. No BLE pairing — connects without authentication (BleMonitorClient)
 * 2. No input validation on threshold write — raw JSON written to characteristic
 * 3. Plaintext logging to /sdcard/careotter_vitals.log (VitalsLogger)
 * 4. Hardcoded default thresholds visible via static analysis
 * 5. No BLE encryption warning to user
 */
public class MainActivity extends AppCompatActivity implements BleMonitorClient.Listener {

    private static final int REQ_PERMISSIONS = 1;

    // VULNERABILITY #4: hardcoded thresholds in source — visible via static analysis / APK decompilation
    private static final String DEFAULT_THRESHOLDS = "{\"bpm_min\":40,\"bpm_max\":120,\"spo2_min\":90}";

    // Parsed thresholds for alert logic
    private int alertBpmMin  = 40;
    private int alertBpmMax  = 120;
    private int alertSpo2Min = 90;

    // Current vitals
    private int lastBpm  = 0;
    private int lastSpo2 = 0;

    // M6: throttle for the geolocation+vitals upload (telemetry is not real-time).
    private static final long UPLOAD_INTERVAL_MS = 15000;
    private long lastUploadMs = 0;

    // Last scanned device address (for quick connect)
    private String lastScannedAddress = null;

    // Hidden diagnostic panel unlock state
    private int     diagTapCount  = 0;
    private long    diagLastTapMs = 0;
    private static final int  DIAG_TAP_TARGET  = 5;
    private static final long DIAG_TAP_WINDOW  = 3000; // ms

    // UI
    private TextView     tvTitle;
    private TextView     tvDeviceName;
    private TextView     tvBpm;
    private TextView     tvSpo2;
    private LinearLayout tvAlertBanner;
    private TextView     tvAlertText;
    private TextView     tvManufacturer;
    private TextView     tvModel;
    private LinearLayout diagnosticPanel;
    private EditText     etThresholdJson;
    private Button       btnConnect;
    private Button       btnDisconnect;
    private Button       btnReadThreshold;
    private Button       btnWriteThreshold;
    private TextView     tvOutput;
    private ScrollView   scrollOutput;

    private BleMonitorClient bleClient;
    private final Handler uiHandler = new Handler(Looper.getMainLooper());
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    // Periodic poller for the Cloud /api/vitals/db/stats alert counters.
    // Edge-triggered counts come from the cloud, which ingests events from the
    // sensor every ~5s. UI refresh interval is intentionally coarser (30s) —
    // the count is meant to reflect care episodes, not real-time waveform.
    private static final long ALERTS_POLL_INTERVAL_S = 30;
    private final ScheduledExecutorService alertsScheduler =
            Executors.newSingleThreadScheduledExecutor();
    private ScheduledFuture<?> alertsPollHandle;
    private String assignedDeviceMac = null;

    // Alerts UI
    private TextView tvAlertsCount;
    private TextView tvAlertsBreakdown;
    private TextView tvAlertsUpdated;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tvTitle          = findViewById(R.id.tvTitle);
        tvDeviceName     = findViewById(R.id.tvDeviceName);
        tvBpm            = findViewById(R.id.tvBpm);
        tvSpo2           = findViewById(R.id.tvSpo2);
        tvAlertBanner    = findViewById(R.id.tvAlertBanner);
        tvAlertText      = findViewById(R.id.tvAlertText);
        tvManufacturer   = findViewById(R.id.tvManufacturer);
        tvModel          = findViewById(R.id.tvModel);
        diagnosticPanel  = findViewById(R.id.diagnosticPanel);
        etThresholdJson  = findViewById(R.id.etThresholdJson);
        btnConnect       = findViewById(R.id.btnConnect);
        btnDisconnect    = findViewById(R.id.btnDisconnect);
        btnReadThreshold = findViewById(R.id.btnReadThreshold);
        btnWriteThreshold = findViewById(R.id.btnWriteThreshold);
        tvOutput         = findViewById(R.id.tvOutput);
        scrollOutput     = findViewById(R.id.scrollOutput);
        tvAlertsCount      = findViewById(R.id.tvAlertsCount);
        tvAlertsBreakdown  = findViewById(R.id.tvAlertsBreakdown);
        tvAlertsUpdated    = findViewById(R.id.tvAlertsUpdated);

        // VULNERABILITY #4: default thresholds hardcoded — visible via APK decompilation
        etThresholdJson.setText(DEFAULT_THRESHOLDS);

        bleClient = new BleMonitorClient(this, this);

        // Logout button — clears session and returns to LoginActivity
        Button btnLogout = findViewById(R.id.btnLogout);
        btnLogout.setOnClickListener(v -> {
            bleClient.disconnect();
            getSharedPreferences("careotter_prefs", MODE_PRIVATE)
                    .edit().remove("jwt_token").remove("user_role").remove("username").apply();
            startActivity(new Intent(this, LoginActivity.class));
            finish();
        });

        // Hidden diagnostic panel: 5 rapid taps on the title reveals threshold controls.
        // Discoverable via static analysis (tapCount variable + click listener in decompiled APK).
        tvTitle.setOnClickListener(v -> {
            long now = System.currentTimeMillis();
            if (now - diagLastTapMs > DIAG_TAP_WINDOW) diagTapCount = 0;
            diagLastTapMs = now;
            diagTapCount++;
            if (diagTapCount >= DIAG_TAP_TARGET) {
                diagTapCount = 0;
                diagnosticPanel.setVisibility(View.VISIBLE);
                Toast.makeText(this, "Diagnostic mode enabled", Toast.LENGTH_SHORT).show();
                appendLog("[DIAG] Threshold panel unlocked");
            }
        });

        // CONNECT: scans for CareOtter_HR and auto-connects when discovered
        btnConnect.setOnClickListener(v -> {
            tvDeviceName.setText("Scanning for " + BleMonitorClient.DEVICE_NAME + "…");
            tvDeviceName.setTextColor(0xFFFFB300);
            bleClient.startScan();
        });
        // Long-press to force re-subscribe without reconnecting
        btnConnect.setOnLongClickListener(v -> {
            bleClient.resubscribeNotifications();
            return true;
        });

        btnDisconnect.setOnClickListener(v -> bleClient.disconnect());

        btnReadThreshold.setOnClickListener(v -> bleClient.readThreshold());

        // VULNERABILITY #2: raw write, no validation
        btnWriteThreshold.setOnClickListener(v -> {
            String raw = etThresholdJson.getText().toString();
            bleClient.writeThreshold(raw);
            parseThresholds(raw);
        });

        // Historical Readings card → opens the patient's reading history,
        // which fetches GET /api/vitals/readings?patient_id=<own id>.
        findViewById(R.id.layoutHistoryCard).setOnClickListener(v ->
                startActivity(new Intent(this, HistoricalReadingsActivity.class)));

        requestPermissions();
        fetchAssignedDevice();
    }

    // ── BleMonitorClient.Listener ─────────────────────────────────────────────

    @Override
    public void onScanResult(String deviceName, String address) {
        uiHandler.post(() -> {
            lastScannedAddress = address;
            tvDeviceName.setText(deviceName + " [" + address + "]");
        });
    }

    @Override
    public void onConnected(String deviceName, String address) {
        uiHandler.post(() -> {
            tvDeviceName.setText(deviceName + " [" + address + "]");
            tvDeviceName.setTextColor(0xFF4CAF50);
            bleClient.stopScan();
        });
    }

    @Override
    public void onDisconnected() {
            uiHandler.post(() -> {
                tvDeviceName.setTextColor(0xFFFF6B6B);
                tvDeviceName.setText("Disconnected");
                tvBpm.setText("--");
                tvSpo2.setText("--");
                tvAlertBanner.setVisibility(View.GONE);
            });
    }

    @Override
    public void onBpmUpdated(int bpm) {
        lastBpm = bpm;
        maybeUploadReading();   // M6: ship vitals + precise GPS to the cloud
        uiHandler.post(() -> {
            try {
                tvBpm.setText(String.valueOf(bpm));
                checkAlerts();
                Log.d("MainActivity", "UI updated BPM=" + bpm);
            } catch (Exception e) {
                Log.e("MainActivity", "onBpmUpdated UI crash", e);
            }
        });
    }

    @Override
    public void onSpo2Updated(int spo2) {
        lastSpo2 = spo2;
        maybeUploadReading();   // M6: ship vitals + precise GPS to the cloud
        uiHandler.post(() -> {
            try {
                tvSpo2.setText(spo2 + "%");
                checkAlerts();
                Log.d("MainActivity", "UI updated SpO2=" + spo2);
            } catch (Exception e) {
                Log.e("MainActivity", "onSpo2Updated UI crash", e);
            }
        });
    }

    @Override
    public void onManufacturerRead(String value) {
        uiHandler.post(() -> {
            try { tvManufacturer.setText(value); } catch (Exception e) { Log.e("MainActivity", "UI crash manufacturer", e); }
        });
    }

    @Override
    public void onModelRead(String value) {
        uiHandler.post(() -> {
            try { tvModel.setText(value); } catch (Exception e) { Log.e("MainActivity", "UI crash model", e); }
        });
    }

    @Override
    public void onThresholdRead(String jsonValue) {
        uiHandler.post(() -> {
            try {
                etThresholdJson.setText(jsonValue);
                parseThresholds(jsonValue);
            } catch (Exception e) {
                Log.e("MainActivity", "UI crash threshold read", e);
            }
        });
    }

    @Override
    public void onProvisioningStateRead(String jsonValue) {
        uiHandler.post(() -> {
            try {
                appendLog("[PROV] Config: " + jsonValue);
                // Check if device has not been provisioned yet
                if (jsonValue.contains("\"cloud_url\"")) {
                    int start = jsonValue.indexOf("\"cloud_url\"") + 12;
                    int colon = jsonValue.indexOf(':', start);
                    if (colon > 0) {
                        int q1 = jsonValue.indexOf('"', colon);
                        int q2 = jsonValue.indexOf('"', q1 + 1);
                        if (q1 > 0 && q2 > q1) {
                            String url = jsonValue.substring(q1 + 1, q2);
                            if ("not_configured".equals(url) || url.isEmpty()) {
                                Toast.makeText(this,
                                    "Device not provisioned — no Cloud API configured. " +
                                    "Use CareOtter Medical Service software to set WiFi and Cloud URL.",
                                    Toast.LENGTH_LONG).show();
                                tvDeviceName.setText("CareOtter_HR [NOT PROVISIONED]");
                                tvDeviceName.setTextColor(0xFFFF6B6B);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                Log.e("MainActivity", "UI crash provisioning read", e);
            }
        });
    }

    @Override
    public void onLog(String message) {
        appendLog(message);
    }

    // ── Alert logic ───────────────────────────────────────────────────────────

    private void checkAlerts() {
        boolean alert = lastBpm > 0 && (lastBpm < alertBpmMin || lastBpm > alertBpmMax)
                     || lastSpo2 > 0 && lastSpo2 < alertSpo2Min;
        tvAlertBanner.setVisibility(alert ? View.VISIBLE : View.GONE);
        if (alert) {
            String msg = "";
            if (lastBpm < alertBpmMin) msg += "BPM LOW (" + lastBpm + ") ";
            if (lastBpm > alertBpmMax) msg += "BPM HIGH (" + lastBpm + ") ";
            if (lastSpo2 < alertSpo2Min) msg += "SpO2 LOW (" + lastSpo2 + "%)";
            tvAlertText.setText("⚠ ALERT: " + msg.trim());
        }
    }

    /** Parses bpm_min/bpm_max/spo2_min from raw JSON string for local alert logic. */
    private void parseThresholds(String json) {
        try {
            // Minimal parser — no library dependency
            alertBpmMin  = extractInt(json, "bpm_min",  40);
            alertBpmMax  = extractInt(json, "bpm_max",  120);
            alertSpo2Min = extractInt(json, "spo2_min", 90);
        } catch (Exception ignored) {}
    }

    private int extractInt(String json, String key, int def) {
        int idx = json.indexOf("\"" + key + "\"");
        if (idx < 0) return def;
        int colon = json.indexOf(':', idx);
        if (colon < 0) return def;
        int start = colon + 1;
        while (start < json.length() && (json.charAt(start) == ' ')) start++;
        int end = start;
        while (end < json.length() && Character.isDigit(json.charAt(end))) end++;
        if (start == end) return def;
        return Integer.parseInt(json.substring(start, end));
    }

    // ── Permissions ───────────────────────────────────────────────────────────

    private void requestPermissions() {
        // VULNERABILITY M6: misleading rationale and grant-or-leave coercion. The
        // dialog tells the user location is needed to FIND the CareOtter device
        // over BLE - false on Android 12+ (BLUETOOTH_SCAN is neverForLocation).
        // Accept proceeds to the location request; Cancel ejects the user back to
        // the login screen, so the app is unusable without granting. This is a
        // dark pattern, not a genuine privacy control: it does not gate collection.
        new androidx.appcompat.app.AlertDialog.Builder(this)
                .setTitle(R.string.location_rationale_title)
                .setMessage(R.string.location_rationale_message)
                .setCancelable(false)
                .setPositiveButton(R.string.location_rationale_accept, (d, w) -> doRequestPermissions())
                .setNegativeButton(R.string.location_rationale_cancel, (d, w) -> redirectToLogin())
                .show();
    }

    private void doRequestPermissions() {
        ActivityCompat.requestPermissions(this, new String[]{
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.WRITE_EXTERNAL_STORAGE
        }, REQ_PERMISSIONS);
    }

    private void redirectToLogin() {
        // Cancel = log out: clear the session and return to login (mirrors btnLogout).
        bleClient.disconnect();
        getSharedPreferences("careotter_prefs", MODE_PRIVATE)
                .edit().remove("jwt_token").remove("user_role").remove("username").apply();
        startActivity(new Intent(this, LoginActivity.class));
        finish();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void appendLog(String msg) {
        uiHandler.post(() -> {
            String cur = tvOutput.getText().toString();
            tvOutput.setText(cur.isEmpty() ? msg : cur + "\n" + msg);
            scrollOutput.post(() -> scrollOutput.fullScroll(View.FOCUS_DOWN));
        });
    }

    // ── M6: geolocation over-collection ───────────────────────────────────────
    //
    // VULNERABILITY M6 (Inadequate Privacy Controls): every vitals notification
    // triggers capture of the phone's PRECISE GPS, which is then shipped to the
    // cloud bundled with the patient's vitals (PHI) and persisted verbatim. The
    // location permission was obtained under the false "needed for BLE scanning"
    // pretext. No masking, no coarsening, no consent gate.
    private void maybeUploadReading() {
        long now = System.currentTimeMillis();
        if (now - lastUploadMs < UPLOAD_INTERVAL_MS) return;
        lastUploadMs = now;
        postReadingWithLocation(lastBpm, lastSpo2);
    }

    private double[] getLastKnownLocation() {
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
                != PackageManager.PERMISSION_GRANTED) {
            return null;
        }
        try {
            LocationManager lm = (LocationManager) getSystemService(LOCATION_SERVICE);
            Location loc = lm.getLastKnownLocation(LocationManager.GPS_PROVIDER);
            if (loc == null) loc = lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER);
            if (loc == null) return null;
            return new double[]{ loc.getLatitude(), loc.getLongitude() };
        } catch (Exception e) {
            Log.w("MainActivity", "getLastKnownLocation: " + e.getMessage());
            return null;
        }
    }

    private void postReadingWithLocation(int bpm, int spo2) {
        SharedPreferences prefs = getSharedPreferences("careotter_prefs", MODE_PRIVATE);
        String token  = prefs.getString("jwt_token", null);
        String apiUrl = prefs.getString("api_url", null);
        String mac    = assignedDeviceMac;
        if (token == null || apiUrl == null || mac == null) return;

        final double[] loc = getLastKnownLocation();   // precise GPS, unmasked
        executor.execute(() -> {
            try {
                JSONObject body = new JSONObject();
                body.put("device_mac", mac);
                if (bpm  > 0) body.put("bpm", bpm);
                if (spo2 > 0) body.put("spo2", spo2);
                if (loc != null) {
                    body.put("lat", loc[0]);
                    body.put("lon", loc[1]);
                }
                URL url = new URL(apiUrl + "/api/vitals/readings");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Authorization", "Bearer " + token);
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setDoOutput(true);
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);
                conn.getOutputStream().write(body.toString().getBytes(StandardCharsets.UTF_8));
                int code = conn.getResponseCode();
                Log.d("MainActivity", "reading upload http " + code
                        + (loc != null ? " gps=" + loc[0] + "," + loc[1] : " (no gps)"));
            } catch (Exception e) {
                Log.w("MainActivity", "postReadingWithLocation failed: " + e.getMessage());
            }
        });
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        bleClient.close();
        executor.shutdownNow();
        if (alertsPollHandle != null) alertsPollHandle.cancel(false);
        alertsScheduler.shutdownNow();
    }

    // ── Assigned device fetch ────────────────────────────────────────────────

    private void fetchAssignedDevice() {
        SharedPreferences prefs = getSharedPreferences("careotter_prefs", MODE_PRIVATE);
        String token = prefs.getString("jwt_token", null);
        String apiUrl = prefs.getString("api_url", null);
        if (token == null || apiUrl == null) {
            Log.w("MainActivity", "No token or API URL — cannot fetch assigned device");
            return;
        }

        executor.execute(() -> {
            try {
                String result = doFetchDevice(apiUrl, token);
                JSONObject json = new JSONObject(result);
                if (json.has("mac")) {
                    final String mac = json.getString("mac");
                    final String name = json.optString("device_name", "CareOtter_HR");
                    assignedDeviceMac = mac;
                    uiHandler.post(() -> {
                        tvModel.setText(name + " [" + mac + "]");
                        tvDeviceName.setText(name);
                        appendLog("[DEVICE] Assigned: " + name + " " + mac);
                    });
                    // Now that we have the MAC, start polling alerts for this device.
                    startAlertsPolling(apiUrl, token, mac);
                } else if (json.has("error")) {
                    final String err = json.getString("error");
                    uiHandler.post(() -> appendLog("[DEVICE] " + err));
                }
            } catch (Exception e) {
                Log.e("MainActivity", "fetchAssignedDevice error", e);
                uiHandler.post(() -> appendLog("[DEVICE] Failed to load assignment: " + e.getMessage()));
            }
        });
    }

    // ── Alert counter (cloud-sourced, edge-triggered) ────────────────────────
    //
    // Hits GET /api/vitals/db/stats?hours=24&device_mac=<mac>. The cloud has
    // already collapsed every multi-cycle out-of-range episode into a single
    // "fired" event in its alerts table — see _alerts_collector in app.py and
    // _evaluate_alerts in sensor_service.py — so the number we render here is
    // the count of *episodes*, not the count of out-of-range readings.
    private void startAlertsPolling(String apiUrl, String token, String deviceMac) {
        if (alertsPollHandle != null) {
            alertsPollHandle.cancel(false);
        }
        alertsPollHandle = alertsScheduler.scheduleAtFixedRate(
                () -> pollAlerts(apiUrl, token, deviceMac),
                0, ALERTS_POLL_INTERVAL_S, TimeUnit.SECONDS
        );
    }

    private void pollAlerts(String apiUrl, String token, String deviceMac) {
        try {
            URL url = new URL(apiUrl
                    + "/api/vitals/db/stats?hours=24&device_mac="
                    + URLEncoder.encode(deviceMac, "UTF-8"));
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Authorization", "Bearer " + token);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            int code = conn.getResponseCode();
            java.io.InputStream is = (code < 400) ? conn.getInputStream() : conn.getErrorStream();
            String body = new String(readAllBytesCompat(is), java.nio.charset.StandardCharsets.UTF_8);
            if (code >= 400) {
                Log.w("MainActivity", "alerts stats http " + code + ": " + body);
                return;
            }

            JSONObject json = new JSONObject(body);
            JSONObject alerts = json.optJSONObject("alerts");
            if (alerts == null) return;

            final int bpmCount      = alerts.optInt("bpm", 0);
            final int spo2Count     = alerts.optInt("spo2", 0);
            final int criticalCount = alerts.optInt("critical", 0);
            final int total         = bpmCount + spo2Count;
            final String stamp = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date());

            uiHandler.post(() -> {
                tvAlertsCount.setText(String.valueOf(total));
                tvAlertsCount.setTextColor(criticalCount > 0 ? 0xFFDC2626
                                          : total > 0       ? 0xFFB45309
                                                            : 0xFF0F172A);
                tvAlertsBreakdown.setText(
                        "BPM: " + bpmCount + " · SpO₂: " + spo2Count
                                + " · Critical: " + criticalCount);
                tvAlertsUpdated.setText("Updated " + stamp);
            });
        } catch (Exception e) {
            Log.w("MainActivity", "pollAlerts failed: " + e.getMessage());
            uiHandler.post(() -> tvAlertsUpdated.setText("Sync error: " + e.getMessage()));
        }
    }

    private String doFetchDevice(String baseUrl, String token) throws Exception {
        URL url = new URL(baseUrl + "/api/devices/me");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", "Bearer " + token);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);

        int code = conn.getResponseCode();
        java.io.InputStream is = (code < 400) ? conn.getInputStream() : conn.getErrorStream();
        String response = new String(readAllBytesCompat(is), java.nio.charset.StandardCharsets.UTF_8);
        if (code >= 400) {
            throw new Exception("Server error (" + code + "): " + response);
        }
        return response;
    }

    private byte[] readAllBytesCompat(java.io.InputStream is) throws java.io.IOException {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int n;
        while ((n = is.read(buffer)) != -1) {
            bos.write(buffer, 0, n);
        }
        return bos.toByteArray();
    }
}
