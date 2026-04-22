package com.vulnzoo.careotter_app;

import android.Manifest;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanRecord;
import android.bluetooth.le.ScanResult;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.util.SparseArray;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

import org.json.JSONObject;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * LoginActivity — CareOtter unified app entry point.
 *
 * On start, performs a BLE scan to auto-discover the Cloud API URL from the
 * CareOtter_HR device's ManufacturerData advertising field (company ID 0x08D4).
 * Once found, pre-fills etApiUrl and stops the scan.
 *
 * Authenticates via HTTP POST to the discovered URL (/api/auth/login).
 * Routes to PatientActivity (BLE monitoring) or AdminActivity (IGP v4)
 * based on the 'role' field returned in the JWT response.
 *
 * VULNERABILITIES:
 * 1. Cloud API URL leaked via BLE advertising — passive scan reveals management
 *    endpoint without connecting or authenticating (info disclosure)
 * 2. Credentials sent over plain HTTP (no TLS enforcement)
 * 3. JWT stored in SharedPreferences without encryption
 * 4. No certificate pinning
 */
public class LoginActivity extends AppCompatActivity {

    private static final String TAG              = "LoginActivity";
    private static final String PREFS_NAME       = "careotter_prefs";
    private static final String KEY_TOKEN        = "jwt_token";
    private static final String KEY_ROLE         = "user_role";
    private static final String KEY_USERNAME     = "username";
    private static final String KEY_API_URL      = "api_url";
    private static final String KEY_DEVICE_IP    = "device_ip";
    private static final String DEFAULT_API      = "http://192.168.2.1:5002";
    private static final String BLE_DEVICE_NAME  = "CareOtter_HR";
    // Company ID used in ManufacturerData: 0x08D4 ("CareOtter Medical Devices")
    private static final int    COMPANY_ID       = 0x08D4;
    private static final long   SCAN_TIMEOUT_MS  = 8000;
    private static final int    REQ_PERMISSIONS  = 2;

    private EditText  etUsername;
    private EditText  etPassword;
    private EditText  etApiUrl;
    private Button    btnLogin;
    private TextView  tvStatus;

    private BluetoothLeScanner bleScanner;
    private boolean            scanning = false;

    private final Handler         uiHandler = new Handler(Looper.getMainLooper());
    private final ExecutorService executor  = Executors.newSingleThreadExecutor();

    // ── BLE scan callback ────────────────────────────────────────────────────

    private final ScanCallback scanCallback = new ScanCallback() {
        @Override
        public void onScanResult(int callbackType, ScanResult result) {
            String name = result.getDevice().getName();
            if (!BLE_DEVICE_NAME.equals(name)) return;

            ScanRecord record = result.getScanRecord();
            if (record == null) return;

            // VULNERABILITY: ManufacturerData carries API IP+port and device WiFi IP
            // in a 10-byte binary payload — visible to any passive BLE scanner.
            SparseArray<byte[]> mfr = record.getManufacturerSpecificData();
            if (mfr == null) return;

            byte[] payload = mfr.get(COMPANY_ID);
            if (payload == null || payload.length != 10) return;

            // Binary layout (big-endian):
            //   [0:4]  Cloud API IPv4
            //   [4:6]  Cloud API port
            //   [6:10] Device WiFi IPv4
            ByteBuffer buf = ByteBuffer.wrap(payload);
            byte[] apiIpBytes  = new byte[4]; buf.get(apiIpBytes);
            int    apiPort     = buf.getShort() & 0xFFFF;
            byte[] devIpBytes  = new byte[4]; buf.get(devIpBytes);

            String apiIp  = (apiIpBytes[0] & 0xFF) + "." + (apiIpBytes[1] & 0xFF) + "."
                          + (apiIpBytes[2] & 0xFF) + "." + (apiIpBytes[3] & 0xFF);
            String devIp  = (devIpBytes[0] & 0xFF) + "." + (devIpBytes[1] & 0xFF) + "."
                          + (devIpBytes[2] & 0xFF) + "." + (devIpBytes[3] & 0xFF);
            String discoveredUrl = "http://" + apiIp + ":" + apiPort;

            Log.d(TAG, "BLE ManufacturerData → api=" + discoveredUrl + " device=" + devIp);

            getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit()
                    .putString(KEY_DEVICE_IP, devIp)
                    .apply();

            stopBleScan();

            uiHandler.post(() -> {
                etApiUrl.setText(discoveredUrl);
                tvStatus.setTextColor(0xFF4CAF50);
                tvStatus.setText("API: " + discoveredUrl + "  |  Device: " + devIp);
            });
        }

        @Override
        public void onScanFailed(int errorCode) {
            Log.w(TAG, "BLE scan failed: " + errorCode);
            uiHandler.post(() -> tvStatus.setText("BLE scan failed — enter API URL manually."));
        }
    };

    // ── Lifecycle ────────────────────────────────────────────────────────────

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        etUsername = findViewById(R.id.etUsername);
        etPassword = findViewById(R.id.etPassword);
        etApiUrl   = findViewById(R.id.etApiUrl);
        btnLogin   = findViewById(R.id.btnLogin);
        tvStatus   = findViewById(R.id.tvLoginStatus);

        // Restore last-used API URL while scan runs
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        etApiUrl.setText(prefs.getString(KEY_API_URL, DEFAULT_API));

        btnLogin.setOnClickListener(v -> attemptLogin());

        // Request BLE permissions then start discovery scan
        if (hasBlePermissions()) {
            startBleScan();
        } else {
            ActivityCompat.requestPermissions(this, new String[]{
                    Manifest.permission.BLUETOOTH_SCAN,
                    Manifest.permission.BLUETOOTH_CONNECT,
                    Manifest.permission.ACCESS_FINE_LOCATION
            }, REQ_PERMISSIONS);
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(requestCode, permissions, results);
        if (requestCode == REQ_PERMISSIONS) {
            if (hasBlePermissions()) startBleScan();
            else tvStatus.setText("BLE permission denied — enter API URL manually.");
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        stopBleScan();
        executor.shutdownNow();
    }

    // ── BLE discovery ────────────────────────────────────────────────────────

    private void startBleScan() {
        BluetoothManager bm = (BluetoothManager) getSystemService(BLUETOOTH_SERVICE);
        if (bm == null) return;
        BluetoothAdapter adapter = bm.getAdapter();
        if (adapter == null || !adapter.isEnabled()) {
            tvStatus.setText("Bluetooth off — enter API URL manually.");
            return;
        }
        bleScanner = adapter.getBluetoothLeScanner();
        if (bleScanner == null) return;

        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_SCAN)
                != PackageManager.PERMISSION_GRANTED) return;

        scanning = true;
        tvStatus.setText("Scanning for CareOtter_HR…");
        bleScanner.startScan(scanCallback);

        // Stop scan after timeout regardless
        uiHandler.postDelayed(() -> {
            if (scanning) {
                stopBleScan();
                String current = etApiUrl.getText().toString().trim();
                if (current.isEmpty() || current.equals(DEFAULT_API)) {
                    tvStatus.setText("Device not found — using default or enter URL manually.");
                }
            }
        }, SCAN_TIMEOUT_MS);
    }

    private void stopBleScan() {
        if (!scanning || bleScanner == null) return;
        scanning = false;
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_SCAN)
                == PackageManager.PERMISSION_GRANTED) {
            bleScanner.stopScan(scanCallback);
        }
    }

    private boolean hasBlePermissions() {
        return ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_SCAN)
                == PackageManager.PERMISSION_GRANTED
            && ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
                == PackageManager.PERMISSION_GRANTED;
    }

    // ── Login ────────────────────────────────────────────────────────────────

    private void attemptLogin() {
        String username = etUsername.getText().toString().trim();
        String password = etPassword.getText().toString();
        String apiUrl   = etApiUrl.getText().toString().trim();
        if (apiUrl.isEmpty()) apiUrl = DEFAULT_API;

        if (username.isEmpty() || password.isEmpty()) {
            tvStatus.setText("Username and password are required.");
            return;
        }

        stopBleScan();
        setUiEnabled(false);
        tvStatus.setText("Authenticating…");

        final String finalApiUrl = apiUrl;
        executor.execute(() -> {
            try {
                String result = doLogin(finalApiUrl, username, password);
                JSONObject json = new JSONObject(result);

                if (json.has("token")) {
                    String token = json.getString("token");
                    String role  = json.optString("role", "patient");
                    String uname = json.optString("username", username);

                    // VULNERABILITY: JWT stored unencrypted in SharedPreferences
                    getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit()
                            .putString(KEY_TOKEN,    token)
                            .putString(KEY_ROLE,     role)
                            .putString(KEY_USERNAME, uname)
                            .putString(KEY_API_URL,  finalApiUrl)
                            .apply();

                    uiHandler.post(() -> routeByRole(role));
                } else {
                    String error = json.optString("error", "Login failed");
                    uiHandler.post(() -> {
                        tvStatus.setText(error);
                        tvStatus.setTextColor(0xFFE53935);
                        setUiEnabled(true);
                    });
                }
            } catch (Exception e) {
                Log.e(TAG, "Login error", e);
                uiHandler.post(() -> {
                    tvStatus.setText("Connection error: " + e.getMessage());
                    tvStatus.setTextColor(0xFFE53935);
                    setUiEnabled(true);
                });
            }
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
        byte[] payload = body.toString().getBytes(StandardCharsets.UTF_8);
        try (OutputStream os = conn.getOutputStream()) { os.write(payload); }

        int code = conn.getResponseCode();
        java.io.InputStream is = (code < 400) ? conn.getInputStream() : conn.getErrorStream();
        return new String(is.readAllBytes(), StandardCharsets.UTF_8);
    }

    private void routeByRole(String role) {
        startActivity(new Intent(this, "admin".equals(role)
                ? AdminActivity.class : MainActivity.class));
        finish();
    }

    private void setUiEnabled(boolean enabled) {
        btnLogin.setEnabled(enabled);
        etUsername.setEnabled(enabled);
        etPassword.setEnabled(enabled);
        etApiUrl.setEnabled(enabled);
    }
}
