package com.vulnzoo.careotter_app;

import android.Manifest;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.core.app.ActivityCompat;

import org.json.JSONException;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * BleWifiProvisioner — BLE client for the hidden Factory Provisioning service
 * (0xFF10). Two-phase API:
 *
 *   1. startScan(cb) → emits onDeviceFound for every distinct device seen
 *      (name may be null). User picks one in the UI.
 *   2. provision(address, ssid, psk, cb) → connect → discover →
 *      write PIN to 0xFF12 → write WiFi JSON to 0xFF11 → disconnect.
 *
 * Every step calls cb.onLog(...) so the UI console can show exactly where the
 * flow is, instead of an opaque "Scanning…" forever.
 *
 * VULNERABILITY: uses hardcoded PIN "6767" (P3) and trusts the device name
 * without cryptographic identity verification.
 */
public class BleWifiProvisioner {

    private static final UUID PROV_SERVICE = UUID.fromString("0000ff10-0000-1000-8000-00805f9b34fb");
    private static final UUID PROV_CONFIG  = UUID.fromString("0000ff11-0000-1000-8000-00805f9b34fb");
    private static final UUID PROV_AUTH    = UUID.fromString("0000ff12-0000-1000-8000-00805f9b34fb");
    private static final UUID CCC_DESCRIPTOR = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");

    public  static final String DEVICE_NAME       = "CareOtter_HR";
    private static final String PIN               = "6767";
    private static final String TAG               = "BleWifiProvisioner";
    private static final long   SCAN_TIMEOUT_MS   = 20_000;
    // Wait window for the device's post-provisioning IP notification on 0xFF11.
    // The device polls up to ~15s for the DHCP lease after 'wifi reload', so this
    // must exceed that. Fall back to a plain success (no IP) after this.
    private static final long   IP_REPORT_TIMEOUT_MS = 20_000;

    public interface Callback {
        /** Plain text log line for every observable step. */
        void onLog(String message);
        /** Fired once per distinct MAC discovered while scanning. */
        void onDeviceFound(String name, String address, int rssi);
        /** Scan loop ended (timeout, manual stop, or error). */
        void onScanStopped(String reason);
        /** State message intended for a small status label. */
        void onStatus(String message);
        /** Terminal callback: provisioning attempt finished. */
        void onComplete(boolean success, String message);
    }

    private final Context context;
    private final Handler uiHandler = new Handler(Looper.getMainLooper());
    private final BluetoothAdapter bluetoothAdapter;
    private BluetoothLeScanner scanner;
    private BluetoothGatt gatt;

    private boolean scanning = false;
    private ScanCallback activeScanCallback;
    private final Set<String> seenAddresses = new HashSet<>();

    private Callback callback;
    private String pendingSsid;
    private String pendingPsk;
    private String pendingCloudUrl;
    // JSON written to 0xFF11 after PIN auth (wifi_set or cloud_set).
    private String pendingJson;
    // wifi_set expects the device to report its IP back on 0xFF11; cloud_set does not.
    private boolean expectIpReport;

    private enum State { IDLE, SCANNING, CONNECTING, DISCOVERING, WRITING_PIN, WRITING_WIFI, WAITING_IP, DONE }
    // volatile: written from UI thread, the BLE binder thread (gattCallback)
    // and the Handler thread (scanTimeoutTask). Without volatile the strict
    // state-guard in startScan() could read a stale value and reject a tap.
    private volatile State state = State.IDLE;

    private final Runnable scanTimeoutTask = () -> {
        if (state == State.SCANNING) {
            log("Scan timeout reached (" + (SCAN_TIMEOUT_MS / 1000) + "s) — stopping");
            stopScan("timeout");
        }
    };

    private final Runnable ipTimeoutTask = () -> {
        if (state == State.WAITING_IP) {
            log("Device result timed out — no wifi_set result received");
            BleWifiProvisioner.this.state = State.DONE;
            // The device reports ok/error within ~15s; a timeout means the result
            // never arrived (BLE link lost or ble_server not responding). Surface
            // it as a failure so the admin does not read a silent no-op as success.
            reportComplete(false, "No result from device — WiFi state unknown (check the BLE link)");
            disconnect();
        }
    };

    // NOTE: no connect timeout. BleMonitorClient (the working patient path)
    // does not impose one — on Cypress BCM43430 the first connectGatt after a
    // fresh advertisement can take 5–20 s, and a 15 s timeout was racing the
    // real STATE_CONNECTED callback and closing the GATT prematurely.

    public BleWifiProvisioner(Context context) {
        // Match BleMonitorClient: keep the Activity context directly.
        this.context = context;
        this.bluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
    }

    public boolean isScanning() { return state == State.SCANNING; }
    public boolean isBusy()     { return state != State.IDLE; }

    // ── Scan ─────────────────────────────────────────────────────────────────

    /**
     * Start an open BLE scan and emit every device through {@link Callback#onDeviceFound}.
     * Caller is responsible for stopping the scan and then calling
     * {@link #provision(String, String, String, Callback)} with the chosen MAC.
     */
    public void startScan(Callback cb) {
        // Mirror BleMonitorClient: only block re-entry while a scan is already
        // running. If a prior provision attempt left the state machine half-
        // baked (CONNECTING/DISCOVERING with no terminal callback), force a
        // hard reset here so the user can always re-scan.
        if (scanning) {
            cb.onComplete(false, "Scan already in progress");
            return;
        }
        if (state != State.IDLE) {
            log("Forcing state reset (was " + state + ") before new scan");
            try { if (gatt != null) gatt.close(); } catch (Exception ignored) {}
            gatt = null;
            state = State.IDLE;
        }
        if (bluetoothAdapter == null) {
            cb.onComplete(false, "BluetoothAdapter unavailable");
            return;
        }
        if (!bluetoothAdapter.isEnabled()) {
            cb.onComplete(false, "Bluetooth is disabled — enable it in system settings");
            return;
        }
        if (!hasPermission(Manifest.permission.BLUETOOTH_SCAN)) {
            cb.onComplete(false, "Missing BLUETOOTH_SCAN runtime permission");
            return;
        }
        scanner = bluetoothAdapter.getBluetoothLeScanner();
        if (scanner == null) {
            cb.onComplete(false, "BLE scanner unavailable");
            return;
        }

        this.callback = cb;
        this.state = State.SCANNING;
        seenAddresses.clear();
        scanning = true;

        log("Starting BLE scan — emitting every device for " + (SCAN_TIMEOUT_MS / 1000) + "s");
        status("Scanning…");

        activeScanCallback = new ScanCallback() {
            @Override
            public void onScanResult(int callbackType, ScanResult result) {
                BluetoothDevice device = result.getDevice();
                if (device == null) return;
                String addr = device.getAddress();
                if (addr == null) return;

                String name = null;
                if (hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) {
                    name = device.getName();
                }
                if (name == null && result.getScanRecord() != null) {
                    name = result.getScanRecord().getDeviceName();
                }
                // Filter: only surface advertisers whose name matches the
                // CareOtter monitor. Everything else (other BLE peripherals
                // nearby, devices with no advertised name) is ignored.
                if (!DEVICE_NAME.equals(name)) return;
                if (!seenAddresses.add(addr)) return; // dedupe

                int rssi = result.getRssi();
                log("Device found: " + name + "  " + addr + "  rssi=" + rssi + "dBm");
                final String fname = name;
                uiHandler.post(() -> {
                    Callback c = callback;
                    if (c != null) c.onDeviceFound(fname, addr, rssi);
                });
            }

            @Override
            public void onScanFailed(int errorCode) {
                log("Scan FAILED — errorCode=" + errorCode);
                stopScan("error " + errorCode);
            }
        };

        // Cold-discovery fix. The default startScan(callback) runs in
        // SCAN_MODE_LOW_POWER (~10% radio duty), which in practice missed every
        // advertisement / scan-response from CareOtter_HR inside the 20s window
        // (logcat: two cold attempts → "Devices seen=0"). Only after a patient
        // GATT connect warmed the device state did the admin scan surface it in
        // ~1.7s. LOW_LATENCY listens continuously, so an advertising peripheral
        // is caught in ~1-2s without needing the patient path to prime it.
        // Name matching stays in onScanResult (it already resolves once a packet
        // arrives), so no hardware ScanFilter is added — a name filter could
        // match nothing if the local name rides in the scan response here.
        ScanSettings settings = new ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
                .build();
        scanner.startScan(null, settings, activeScanCallback);
        uiHandler.postDelayed(scanTimeoutTask, SCAN_TIMEOUT_MS);
    }

    /** Stop the discovery loop. Safe to call repeatedly. */
    public void stopScan() {
        stopScan("manual");
    }

    private void stopScan(String reason) {
        uiHandler.removeCallbacks(scanTimeoutTask);
        if (!scanning) {
            // Still inform the listener so the UI button can flip back.
            Callback c = callback;
            if (c != null) uiHandler.post(() -> c.onScanStopped(reason));
            return;
        }
        if (scanner != null && hasPermission(Manifest.permission.BLUETOOTH_SCAN)) {
            try {
                scanner.stopScan(activeScanCallback != null ? activeScanCallback : new ScanCallback() {});
            } catch (Exception e) {
                log("scanner.stopScan threw: " + e.getMessage());
            }
        }
        scanning = false;
        if (state == State.SCANNING) state = State.IDLE;
        log("Scan stopped (" + reason + "). Devices seen=" + seenAddresses.size());
        Callback c = callback;
        if (c != null) uiHandler.post(() -> c.onScanStopped(reason));
    }

    // ── Provision (connect + auth + write) ───────────────────────────────────

    /**
     * Connect to the chosen device by MAC and run the provisioning sequence.
     * The caller must have stopped the scan beforehand (or it will be stopped
     * here as a safety net).
     */
    public void provision(String address, String ssid, String psk, Callback cb) {
        if (!preflight(address, cb)) return;
        if (ssid == null || ssid.isEmpty()) {
            cb.onComplete(false, "SSID is required");
            return;
        }
        this.callback = cb;
        this.pendingSsid = ssid;
        this.pendingPsk = psk != null ? psk : "";
        this.pendingJson = "{\"cmd\":\"wifi_set\",\"ssid\":\""
                + escapeJson(ssid) + "\",\"psk\":\""
                + escapeJson(this.pendingPsk) + "\"}";
        this.expectIpReport = true;
        this.state = State.CONNECTING;
        log("Provisioning WiFi target: " + address + " ssid='" + ssid + "'");
        connectAndProvision(address);
    }

    /**
     * Connect to the chosen device and set the Cloud API endpoint the device
     * pushes vitals to (BLE provisioning cloud_set on 0xFF11). Same PIN auth as
     * {@link #provision}; no IP report is expected back.
     */
    public void provisionCloud(String address, String cloudUrl, Callback cb) {
        if (!preflight(address, cb)) return;
        if (cloudUrl == null || cloudUrl.isEmpty()) {
            cb.onComplete(false, "Cloud URL is required");
            return;
        }
        this.callback = cb;
        this.pendingCloudUrl = cloudUrl;
        this.pendingPsk = "";   // nothing secret to mask in the cloud_set log line
        this.pendingJson = "{\"cmd\":\"cloud_set\",\"url\":\""
                + escapeJson(cloudUrl) + "\"}";
        this.expectIpReport = false;
        this.state = State.CONNECTING;
        log("Provisioning Cloud endpoint: " + address + " url='" + cloudUrl + "'");
        connectAndProvision(address);
    }

    /** Shared preflight: stop any scan, reset a stuck state, check perm + address. */
    private boolean preflight(String address, Callback cb) {
        if (state == State.SCANNING) {
            stopScan("provision-start");
        }
        // Same permissive policy as startScan: if the previous attempt left
        // state stuck, blow it away instead of refusing the user's tap.
        if (state != State.IDLE) {
            try { if (gatt != null) gatt.close(); } catch (Exception ignored) {}
            gatt = null;
            state = State.IDLE;
        }
        if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) {
            cb.onComplete(false, "Missing BLUETOOTH_CONNECT permission");
            return false;
        }
        if (address == null || address.isEmpty()) {
            cb.onComplete(false, "No device selected");
            return false;
        }
        return true;
    }

    /** Shared connect: kick off the GATT connection; the callback drives the rest. */
    private void connectAndProvision(String address) {
        status("Connecting to " + address + "…");
        BluetoothDevice device = bluetoothAdapter.getRemoteDevice(address);
        gatt = device.connectGatt(context, false, gattCallback);
        log("connectGatt() issued");
    }

    private void disconnect() {
        if (gatt == null) return;
        if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) return;
        try { gatt.disconnect(); } catch (Exception ignored) {}
    }

    private void cleanupGatt() {
        uiHandler.removeCallbacks(ipTimeoutTask);
        if (gatt != null && hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) {
            try { gatt.close(); } catch (Exception ignored) {}
            gatt = null;
        }
        state = State.IDLE;
    }

    // ── GATT Callback ────────────────────────────────────────────────────────

    private final BluetoothGattCallback gattCallback = new BluetoothGattCallback() {

        @Override
        public void onConnectionStateChange(BluetoothGatt g, int status, int newState) {
            log("GATT state status=" + status + " newState=" + newState);
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                BleWifiProvisioner.this.state = State.DISCOVERING;
                status("Connected — discovering services…");
                if (hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) {
                    g.discoverServices();
                }
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                if (BleWifiProvisioner.this.state != State.DONE) {
                    reportComplete(false, "Disconnected (gatt status=" + status + ")");
                }
                cleanupGatt();
            }
        }

        @Override
        public void onServicesDiscovered(BluetoothGatt g, int status) {
            log("Services discovered status=" + status);
            if (status != BluetoothGatt.GATT_SUCCESS) {
                reportComplete(false, "Service discovery failed: " + status);
                disconnect();
                return;
            }
            BluetoothGattService svc = g.getService(PROV_SERVICE);
            if (svc == null) {
                StringBuilder names = new StringBuilder();
                for (BluetoothGattService s : g.getServices()) {
                    names.append("\n  ").append(s.getUuid());
                }
                log("Services available:" + names);
                reportComplete(false, "Hidden provisioning service 0xFF10 not exposed");
                disconnect();
                return;
            }
            BluetoothGattCharacteristic authChr = svc.getCharacteristic(PROV_AUTH);
            if (authChr == null) {
                reportComplete(false, "Auth characteristic 0xFF12 not found");
                disconnect();
                return;
            }
            BleWifiProvisioner.this.state = State.WRITING_PIN;
            status("Authenticating with PIN…");
            authChr.setValue(PIN.getBytes(StandardCharsets.UTF_8));
            boolean ok = false;
            if (hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) {
                ok = g.writeCharacteristic(authChr);
            }
            log("PIN write enqueued=" + ok);
        }

        @Override
        public void onCharacteristicWrite(BluetoothGatt g, BluetoothGattCharacteristic c, int status) {
            UUID uuid = c.getUuid();
            log("onCharacteristicWrite " + uuid + " status=" + status);

            if (uuid.equals(PROV_AUTH)) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    reportComplete(false, "PIN write rejected (status=" + status + ")");
                    disconnect();
                    return;
                }
                BluetoothGattService svc = g.getService(PROV_SERVICE);
                BluetoothGattCharacteristic cfgChr =
                        svc != null ? svc.getCharacteristic(PROV_CONFIG) : null;
                if (cfgChr == null) {
                    reportComplete(false, "Config characteristic 0xFF11 missing after auth");
                    disconnect();
                    return;
                }
                // cloud_set does not expect an IP report — write straight away.
                if (!expectIpReport) {
                    writeConfig(g);
                    return;
                }
                // wifi_set: subscribe to 0xFF11 notifications BEFORE writing so the
                // device's post-provisioning IP report is not missed. The WiFi write
                // itself is issued from onDescriptorWrite once the CCCD write completes.
                boolean notifyOk = hasPermission(Manifest.permission.BLUETOOTH_CONNECT)
                        && g.setCharacteristicNotification(cfgChr, true);
                BluetoothGattDescriptor cccd = cfgChr.getDescriptor(CCC_DESCRIPTOR);
                if (notifyOk && cccd != null) {
                    cccd.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
                    status("Enabling result notifications…");
                    log("CCCD write enqueued=" + g.writeDescriptor(cccd));
                } else {
                    log("Notify subscribe unavailable (notifyOk=" + notifyOk
                            + ", cccd=" + (cccd != null) + ") — writing config without IP report");
                    writeConfig(g);
                }

            } else if (uuid.equals(PROV_CONFIG)) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    reportComplete(false, "Config write failed (status=" + status + ")");
                    disconnect();
                    return;
                }
                if (!expectIpReport) {
                    // cloud_set: no IP report, complete on write success.
                    BleWifiProvisioner.this.state = State.DONE;
                    reportComplete(true, "Cloud endpoint set: " + pendingCloudUrl);
                    disconnect();
                    return;
                }
                // wifi_set: wait briefly for the device to report the IP it obtained
                // (0xFF11 notification), then complete. The fallback task guarantees
                // the flow always terminates if no notification arrives.
                BleWifiProvisioner.this.state = State.WAITING_IP;
                status("Waiting for device IP…");
                uiHandler.removeCallbacks(ipTimeoutTask);
                uiHandler.postDelayed(ipTimeoutTask, IP_REPORT_TIMEOUT_MS);
            }
        }

        @Override
        public void onDescriptorWrite(BluetoothGatt g, BluetoothGattDescriptor descriptor, int status) {
            log("onDescriptorWrite chr=" + descriptor.getCharacteristic().getUuid() + " status=" + status);
            // Notifications enabled (or the write failed) — either way proceed to
            // send the config. A failed CCCD just means no IP report arrives.
            writeConfig(g);
        }

        @Override
        public void onCharacteristicChanged(BluetoothGatt g, BluetoothGattCharacteristic c) {
            if (!PROV_CONFIG.equals(c.getUuid()) || state != State.WAITING_IP) return;
            String status = "", ip = "", reason = "";
            byte[] value = c.getValue();
            if (value != null) {
                try {
                    JSONObject o = new JSONObject(new String(value, StandardCharsets.UTF_8));
                    status = o.optString("status", "");
                    ip     = o.optString("ip", "");
                    reason = o.optString("reason", "");
                } catch (JSONException ignored) {}
            }
            log("wifi_set result: status=" + status + " ip=" + ip
                    + (reason.isEmpty() ? "" : " reason=" + reason));
            uiHandler.removeCallbacks(ipTimeoutTask);
            BleWifiProvisioner.this.state = State.DONE;
            if ("error".equals(status)) {
                reportComplete(false, "WiFi failed: "
                        + (reason.isEmpty() ? "unknown reason" : reason));
            } else {
                boolean ipOk = !ip.isEmpty() && !"0.0.0.0".equals(ip);
                reportComplete(true, "WiFi configured: SSID=" + pendingSsid
                        + (ipOk ? ", IP=" + ip : ""));
            }
            disconnect();
        }
    };

    /** Write the pending provisioning JSON (wifi_set or cloud_set) to 0xFF11.
     *  Shared by the notify-enabled path (onDescriptorWrite) and the direct path. */
    private void writeConfig(BluetoothGatt g) {
        BluetoothGattService svc = g.getService(PROV_SERVICE);
        BluetoothGattCharacteristic cfgChr =
                svc != null ? svc.getCharacteristic(PROV_CONFIG) : null;
        if (cfgChr == null) {
            reportComplete(false, "Config characteristic 0xFF11 missing");
            disconnect();
            return;
        }
        // Mask the PSK in the log only when there is one (empty replace() would
        // splice the mask between every character).
        String logJson = (pendingPsk != null && !pendingPsk.isEmpty())
                ? pendingJson.replace(pendingPsk, "***") : pendingJson;
        log("Writing config: " + logJson);
        cfgChr.setValue(pendingJson.getBytes(StandardCharsets.UTF_8));
        BleWifiProvisioner.this.state = State.WRITING_WIFI;
        status("Writing configuration…");
        boolean ok = hasPermission(Manifest.permission.BLUETOOTH_CONNECT)
                && g.writeCharacteristic(cfgChr);
        log("Config write enqueued=" + ok);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private void log(String msg) {
        Log.d(TAG, msg);
        Callback c = callback;
        if (c != null) uiHandler.post(() -> c.onLog("[BLE] " + msg));
    }

    private void status(String msg) {
        Log.d(TAG, "STATUS " + msg);
        Callback c = callback;
        if (c != null) uiHandler.post(() -> c.onStatus(msg));
    }

    private void reportComplete(boolean success, String msg) {
        Log.d(TAG, "COMPLETE success=" + success + " msg=" + msg);
        Callback c = callback;
        callback = null;
        if (c != null) uiHandler.post(() -> c.onComplete(success, msg));
    }

    private boolean hasPermission(String permission) {
        return ActivityCompat.checkSelfPermission(context, permission)
                == PackageManager.PERMISSION_GRANTED;
    }

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
