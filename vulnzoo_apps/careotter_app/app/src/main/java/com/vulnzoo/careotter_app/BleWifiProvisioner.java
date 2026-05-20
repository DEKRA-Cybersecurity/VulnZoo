package com.vulnzoo.careotter_app;

import android.Manifest;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanRecord;
import android.bluetooth.le.ScanResult;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.core.app.ActivityCompat;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * BleWifiProvisioner — standalone BLE client for provisioning WiFi credentials
 * via the hidden Factory Provisioning service (0xFF10).
 *
 * VULNERABILITY: uses hardcoded PIN "6767" (P3) and trusts the device name
 * without cryptographic identity verification.
 */
public class BleWifiProvisioner {

    private static final UUID PROV_SERVICE = UUID.fromString("0000ff10-0000-1000-8000-00805f9b34fb");
    private static final UUID PROV_CONFIG  = UUID.fromString("0000ff11-0000-1000-8000-00805f9b34fb");
    private static final UUID PROV_AUTH    = UUID.fromString("0000ff12-0000-1000-8000-00805f9b34fb");

    private static final String DEVICE_NAME = "CareOtter_HR";
    private static final String PIN = "6767";
    private static final String TAG = "BleWifiProvisioner";

    public interface Callback {
        void onStatus(String message);
        void onComplete(boolean success, String message);
    }

    private final Context context;
    private final Handler uiHandler = new Handler(Looper.getMainLooper());
    private BluetoothAdapter bluetoothAdapter;
    private BluetoothLeScanner scanner;
    private BluetoothGatt gatt;
    private boolean scanning = false;
    private ScanCallback activeScanCallback;
    private static final long SCAN_TIMEOUT_MS = 15000;

    private Callback callback;
    private String pendingSsid;
    private String pendingPsk;

    private enum State { IDLE, SCANNING, CONNECTING, DISCOVERING, WRITING_PIN, WRITING_WIFI, DONE }
    private State state = State.IDLE;

    private final Runnable scanTimeout = () -> {
        if (state == State.SCANNING) {
            stopScan();
            reportComplete(false, "Timed out — " + DEVICE_NAME + " not found");
            cleanup();
        }
    };

    public BleWifiProvisioner(Context context) {
        this.context = context.getApplicationContext();
        this.bluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
    }

    /**
     * Start the full provisioning flow: scan → connect → auth → write WiFi.
     *
     * @param ssid WiFi SSID
     * @param psk  WiFi passphrase (PSK)
     * @param cb   callback for status updates and completion
     */
    public void provision(String ssid, String psk, Callback cb) {
        if (state != State.IDLE) {
            cb.onComplete(false, "Provisioning already in progress");
            return;
        }
        if (bluetoothAdapter == null || !bluetoothAdapter.isEnabled()) {
            cb.onComplete(false, "Bluetooth is disabled");
            return;
        }
        this.pendingSsid = ssid;
        this.pendingPsk = psk;
        this.callback = cb;
        this.state = State.SCANNING;
        reportStatus("Scanning for " + DEVICE_NAME + "…");
        startScan();
    }

    public boolean isBusy() {
        return state != State.IDLE;
    }

    // ── Scan ─────────────────────────────────────────────────────────────────

    private void startScan() {
        if (!hasPermission(Manifest.permission.BLUETOOTH_SCAN)) {
            reportComplete(false, "Missing BLUETOOTH_SCAN permission");
            return;
        }
        if (scanning) return;
        scanner = bluetoothAdapter.getBluetoothLeScanner();
        if (scanner == null) {
            reportComplete(false, "BLE scanner unavailable");
            return;
        }
        scanning = true;
        activeScanCallback = new ScanCallback() {
            @Override
            public void onScanResult(int callbackType, ScanResult result) {
                if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) return;
                BluetoothDevice device = result.getDevice();
                // Prefer the advertised name from the scan record: for a
                // never-bonded LE device, device.getName() is usually null
                // (the name lives in the scan response, not the device cache).
                String name = null;
                ScanRecord rec = result.getScanRecord();
                if (rec != null) name = rec.getDeviceName();
                if (name == null) name = device.getName();
                if (DEVICE_NAME.equals(name)) {
                    uiHandler.removeCallbacks(scanTimeout);
                    stopScan();
                    reportStatus("Found " + name + " [" + device.getAddress() + "]");
                    connect(device.getAddress());
                }
            }

            @Override
            public void onScanFailed(int errorCode) {
                uiHandler.removeCallbacks(scanTimeout);
                reportComplete(false, "Scan failed: error " + errorCode);
                cleanup();
            }
        };
        // Use the exact proven call that BleMonitorClient (the working patient
        // monitor) uses on this hardware: the 1-arg startScan with default
        // settings. The 3-arg form with SCAN_MODE_LOW_LATENCY did NOT deliver
        // results on this Redmi/MIUI device.
        scanner.startScan(activeScanCallback);
        uiHandler.postDelayed(scanTimeout, SCAN_TIMEOUT_MS);
    }

    private void stopScan() {
        if (!scanning || scanner == null) return;
        if (!hasPermission(Manifest.permission.BLUETOOTH_SCAN)) return;
        scanner.stopScan(activeScanCallback != null ? activeScanCallback : new ScanCallback() {});
        scanning = false;
    }

    // ── Connect ──────────────────────────────────────────────────────────────

    private void connect(String address) {
        if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) {
            reportComplete(false, "Missing BLUETOOTH_CONNECT permission");
            return;
        }
        stopScan();
        state = State.CONNECTING;
        BluetoothDevice device = bluetoothAdapter.getRemoteDevice(address);
        gatt = device.connectGatt(context, false, gattCallback);
        Log.d(TAG, "connectGatt issued for " + address);
        reportStatus("Connecting…");
    }

    private void disconnect() {
        if (gatt == null) return;
        if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) return;
        gatt.disconnect();
    }

    private void closeGatt() {
        if (gatt != null && hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) {
            gatt.close();
            gatt = null;
        }
    }

    // ── GATT Callback ────────────────────────────────────────────────────────

    private final BluetoothGattCallback gattCallback = new BluetoothGattCallback() {

        @Override
        public void onConnectionStateChange(BluetoothGatt g, int status, int newState) {
            Log.d(TAG, "onConnectionStateChange status=" + status + " newState=" + newState);
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                state = State.DISCOVERING;
                reportStatus("Connected — discovering services…");
                g.discoverServices();
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                if (state != State.DONE) {
                    reportComplete(false, "Disconnected unexpectedly (status=" + status + ")");
                }
                cleanup();
            }
        }

        @Override
        public void onServicesDiscovered(BluetoothGatt g, int status) {
            Log.d(TAG, "onServicesDiscovered status=" + status);
            if (status != BluetoothGatt.GATT_SUCCESS) {
                reportComplete(false, "Service discovery failed: " + status);
                disconnect();
                return;
            }

            BluetoothGattService svc = g.getService(PROV_SERVICE);
            if (svc == null) {
                reportComplete(false, "Hidden provisioning service (0xFF10) not found");
                disconnect();
                return;
            }

            BluetoothGattCharacteristic authChr = svc.getCharacteristic(PROV_AUTH);
            if (authChr == null) {
                reportComplete(false, "Auth characteristic (0xFF12) not found");
                disconnect();
                return;
            }

            state = State.WRITING_PIN;
            authChr.setValue(PIN.getBytes(StandardCharsets.UTF_8));
            reportStatus("Authenticating with PIN…");
            boolean ok = g.writeCharacteristic(authChr);
            Log.d(TAG, "PIN write enqueued=" + ok);
        }

        @Override
        public void onCharacteristicWrite(BluetoothGatt g, BluetoothGattCharacteristic c, int status) {
            UUID uuid = c.getUuid();
            Log.d(TAG, "onCharacteristicWrite uuid=" + uuid + " status=" + status);

            if (uuid.equals(PROV_AUTH)) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    reportComplete(false, "PIN write rejected (status=" + status + ")");
                    disconnect();
                    return;
                }
                reportStatus("PIN accepted — writing WiFi credentials…");

                BluetoothGattService svc = g.getService(PROV_SERVICE);
                if (svc == null) {
                    reportComplete(false, "Provisioning service lost after auth");
                    disconnect();
                    return;
                }
                BluetoothGattCharacteristic cfgChr = svc.getCharacteristic(PROV_CONFIG);
                if (cfgChr == null) {
                    reportComplete(false, "Config characteristic (0xFF11) not found");
                    disconnect();
                    return;
                }

                String json = "{\"cmd\":\"wifi_set\",\"ssid\":\"" + escapeJson(pendingSsid)
                        + "\",\"psk\":\"" + escapeJson(pendingPsk) + "\"}";
                cfgChr.setValue(json.getBytes(StandardCharsets.UTF_8));
                state = State.WRITING_WIFI;
                boolean ok = g.writeCharacteristic(cfgChr);
                Log.d(TAG, "WiFi write enqueued=" + ok + " json=" + json);

            } else if (uuid.equals(PROV_CONFIG)) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    reportComplete(false, "WiFi config write failed (status=" + status + ")");
                    disconnect();
                    return;
                }
                reportStatus("WiFi credentials written to device");
                state = State.DONE;
                reportComplete(true, "WiFi configured: SSID=" + pendingSsid);
                disconnect();
            }
        }
    };

    // ── Helpers ──────────────────────────────────────────────────────────────

    private void reportStatus(String msg) {
        Log.d(TAG, msg);
        Callback cb = callback;
        // Snapshot the reference: the field can be nulled by reportComplete()
        // before this posted runnable executes on the UI thread.
        if (cb != null) {
            uiHandler.post(() -> cb.onStatus(msg));
        }
    }

    private void reportComplete(boolean success, String msg) {
        Log.d(TAG, "COMPLETE success=" + success + " msg=" + msg);
        if (callback != null) {
            Callback cb = callback;
            // Clear callback so only one completion fires
            callback = null;
            uiHandler.post(() -> cb.onComplete(success, msg));
        }
    }

    private void cleanup() {
        uiHandler.removeCallbacks(scanTimeout);
        stopScan();
        closeGatt();
        state = State.IDLE;
    }

    private boolean hasPermission(String permission) {
        return ActivityCompat.checkSelfPermission(context, permission)
                == PackageManager.PERMISSION_GRANTED;
    }

    /** Minimal JSON string escape for SSID/PSK values. */
    private static String escapeJson(String raw) {
        return raw.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\b", "\\b")
                  .replace("\f", "\\f")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }
}
