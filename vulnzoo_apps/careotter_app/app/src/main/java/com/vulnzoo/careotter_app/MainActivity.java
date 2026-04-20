package com.vulnzoo.careotter_app;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

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

    // Last scanned device address (for quick connect)
    private String lastScannedAddress = null;

    // UI
    private TextView  tvDeviceName;
    private TextView  tvBpm;
    private TextView  tvSpo2;
    private TextView  tvAlertBanner;
    private TextView  tvManufacturer;
    private TextView  tvModel;
    private EditText  etThresholdJson;
    private Button    btnScan;
    private Button    btnConnect;
    private Button    btnDisconnect;
    private Button    btnReadThreshold;
    private Button    btnWriteThreshold;
    private TextView  tvOutput;
    private ScrollView scrollOutput;

    private BleMonitorClient bleClient;
    private final Handler uiHandler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tvDeviceName     = findViewById(R.id.tvDeviceName);
        tvBpm            = findViewById(R.id.tvBpm);
        tvSpo2           = findViewById(R.id.tvSpo2);
        tvAlertBanner    = findViewById(R.id.tvAlertBanner);
        tvManufacturer   = findViewById(R.id.tvManufacturer);
        tvModel          = findViewById(R.id.tvModel);
        etThresholdJson  = findViewById(R.id.etThresholdJson);
        btnScan          = findViewById(R.id.btnScan);
        btnConnect       = findViewById(R.id.btnConnect);
        btnDisconnect    = findViewById(R.id.btnDisconnect);
        btnReadThreshold = findViewById(R.id.btnReadThreshold);
        btnWriteThreshold = findViewById(R.id.btnWriteThreshold);
        tvOutput         = findViewById(R.id.tvOutput);
        scrollOutput     = findViewById(R.id.scrollOutput);

        // VULNERABILITY #4: default thresholds hardcoded
        etThresholdJson.setText(DEFAULT_THRESHOLDS);

        bleClient = new BleMonitorClient(this, this);

        // SCAN: busca CareOtter_HR y conecta automáticamente al encontrarlo
        btnScan.setOnClickListener(v -> {
            tvDeviceName.setText("Buscando " + BleMonitorClient.DEVICE_NAME + "…");
            tvDeviceName.setTextColor(0xFFFFB300);
            bleClient.startScan();
        });

        // CONNECT: alias de scan (el target es siempre CareOtter_HR)
        btnConnect.setOnClickListener(v -> {
            tvDeviceName.setText("Buscando " + BleMonitorClient.DEVICE_NAME + "…");
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

        requestPermissions();
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
            tvDeviceName.setText("Desconectado");
            tvBpm.setText("--");
            tvSpo2.setText("--");
            tvAlertBanner.setVisibility(View.GONE);
        });
    }

    @Override
    public void onBpmUpdated(int bpm) {
        lastBpm = bpm;
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
            tvAlertBanner.setText("⚠ ALERT: " + msg.trim());
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
        ActivityCompat.requestPermissions(this, new String[]{
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.WRITE_EXTERNAL_STORAGE
        }, REQ_PERMISSIONS);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void appendLog(String msg) {
        uiHandler.post(() -> {
            String cur = tvOutput.getText().toString();
            tvOutput.setText(cur.isEmpty() ? msg : cur + "\n" + msg);
            scrollOutput.post(() -> scrollOutput.fullScroll(View.FOCUS_DOWN));
        });
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        bleClient.close();
    }
}
