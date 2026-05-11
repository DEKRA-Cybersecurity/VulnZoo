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
import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Log;

import androidx.core.app.ActivityCompat;

import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.Queue;
import java.util.UUID;

/**
 * BleMonitorClient — BLE scan, connect, GATT callbacks, characteristic read/write.
 *
 * VULNERABILITY #1: No BLE pairing or bonding enforced — connects to any device
 * advertising the matching name without authentication.
 * VULNERABILITY #5: BLE channel has no encryption, data transmitted in plaintext.
 */
public class BleMonitorClient {

    // Standard GATT UUIDs
    public static final UUID HR_SERVICE        = UUID.fromString("0000180d-0000-1000-8000-00805f9b34fb");
    public static final UUID HR_MEASUREMENT    = UUID.fromString("00002a37-0000-1000-8000-00805f9b34fb");
    public static final UUID PLX_SERVICE       = UUID.fromString("00001822-0000-1000-8000-00805f9b34fb");
    public static final UUID PLX_CONTINUOUS    = UUID.fromString("00002a5f-0000-1000-8000-00805f9b34fb");
    public static final UUID DEVINFO_SERVICE   = UUID.fromString("0000180a-0000-1000-8000-00805f9b34fb");
    public static final UUID MANUFACTURER_NAME = UUID.fromString("00002a29-0000-1000-8000-00805f9b34fb");
    public static final UUID MODEL_NUMBER      = UUID.fromString("00002a24-0000-1000-8000-00805f9b34fb");
    public static final UUID ALERT_SERVICE     = UUID.fromString("0000ff00-0000-1000-8000-00805f9b34fb");
    public static final UUID ALERT_THRESHOLD   = UUID.fromString("0000ff01-0000-1000-8000-00805f9b34fb");

    // Factory Provisioning Service (hidden — not advertised, discoverable via GATT enumeration)
    public static final UUID PROV_SERVICE      = UUID.fromString("0000ff10-0000-1000-8000-00805f9b34fb");
    public static final UUID PROV_CONFIG       = UUID.fromString("0000ff11-0000-1000-8000-00805f9b34fb");
    public static final UUID PROV_AUTH         = UUID.fromString("0000ff12-0000-1000-8000-00805f9b34fb");

    // Standard CCC descriptor for enabling notifications
    private static final UUID CCC_DESCRIPTOR   = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");

    // Device name to scan for
    public static final String DEVICE_NAME = "CareOtter_HR";

    public interface Listener {
        void onScanResult(String deviceName, String address);
        void onConnected(String deviceName, String address);
        void onDisconnected();
        void onBpmUpdated(int bpm);
        void onSpo2Updated(int spo2);
        void onManufacturerRead(String value);
        void onModelRead(String value);
        void onThresholdRead(String jsonValue);
        void onProvisioningStateRead(String jsonValue);
        void onLog(String message);
    }

    private final Context context;
    private final Listener listener;
    private BluetoothAdapter bluetoothAdapter;
    private BluetoothLeScanner scanner;
    private static final String TAG = "BleMonitorClient";

    private BluetoothGatt gatt;
    private boolean scanning = false;

    // Descriptor-write queue to serialise CCC writes and avoid Android BLE stack collisions
    private final Queue<NotifyRequest> notifyQueue = new LinkedList<>();
    private boolean descriptorWritePending = false;

    private static class NotifyRequest {
        final UUID serviceUuid;
        final UUID chrUuid;
        NotifyRequest(UUID s, UUID c) { this.serviceUuid = s; this.chrUuid = c; }
    }

    public BleMonitorClient(Context context, Listener listener) {
        this.context = context;
        this.listener = listener;
        this.bluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
    }

    // ── Scan ─────────────────────────────────────────────────────────────────

    /**
     * Scans for BLE devices and auto-connects to the first one named DEVICE_NAME.
     * The scan stops immediately on match — other devices are ignored and never
     * surfaced to the UI.
     *
     * VULNERABILITY: device identity is verified only by advertised name, which any
     * rogue BLE peripheral can spoof. An attacker broadcasting "CareOtter_HR" will
     * cause this app to connect and receive/send fabricated vitals data with no
     * further authentication check.
     */
    public void startScan() {
        if (!hasPermission(Manifest.permission.BLUETOOTH_SCAN)) return;
        if (scanning) return;
        scanner = bluetoothAdapter.getBluetoothLeScanner();
        if (scanner == null) return;
        scanning = true;
        listener.onLog("Buscando " + DEVICE_NAME + "…");

        activeScanCallback = new ScanCallback() {
            @Override
            public void onScanResult(int callbackType, ScanResult result) {
                if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) return;
                BluetoothDevice device = result.getDevice();
                String name = device.getName();
                // Only react to the exact target name — but name is attacker-controlled
                if (DEVICE_NAME.equals(name)) {
                    stopScan();
                    listener.onLog("Encontrado: " + name + " [" + device.getAddress() + "] — conectando…");
                    connect(device.getAddress());
                }
            }
        };
        scanner.startScan(activeScanCallback);
    }

    private ScanCallback activeScanCallback = null;

    public void stopScan() {
        if (!scanning || scanner == null) return;
        if (!hasPermission(Manifest.permission.BLUETOOTH_SCAN)) return;
        scanner.stopScan(activeScanCallback != null ? activeScanCallback : new ScanCallback() {});
        scanning = false;
        listener.onLog("Scan detenido");
    }

    // ── Connect ───────────────────────────────────────────────────────────────

    /** Connect by MAC address. VULNERABILITY: no pairing, no bonding. */
    public void connect(String address) {
        if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) return;
        stopScan();
        BluetoothDevice device = bluetoothAdapter.getRemoteDevice(address);
        // AUTOCONNECT = false, no bonding enforced
        gatt = device.connectGatt(context, false, gattCallback);
        Log.d(TAG, "connectGatt issued for " + address);
        listener.onLog("Connecting to " + address + "…");
    }

    public void disconnect() {
        if (gatt == null) return;
        if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) return;
        notifyQueue.clear();
        descriptorWritePending = false;
        gatt.disconnect();
        Log.d(TAG, "disconnect() called");
    }

    // ── Characteristic read/write ─────────────────────────────────────────────

    public void readThreshold() {
        if (gatt == null) { Log.w(TAG, "readThreshold: gatt is null"); return; }
        BluetoothGattCharacteristic chr = findCharacteristic(ALERT_SERVICE, ALERT_THRESHOLD);
        if (chr == null) { listener.onLog("ALERT_THRESHOLD characteristic not found"); return; }
        if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) return;
        boolean ok = gatt.readCharacteristic(chr);
        Log.d(TAG, "readThreshold enqueued=" + ok);
    }

    /**
     * Read the Factory Provisioning Config characteristic (0xFF11).
     * Returns JSON with wifi_ssid, wifi_psk, cloud_url, uptime_sec, provision_expired.
     * VULNERABILITY P5: ReadValue returns WiFi PSK in plaintext.
     */
    public void readProvisioningConfig() {
        if (gatt == null) { Log.w(TAG, "readProvisioningConfig: gatt is null"); return; }
        BluetoothGattCharacteristic chr = findCharacteristic(PROV_SERVICE, PROV_CONFIG);
        if (chr == null) { listener.onLog("PROV_CONFIG characteristic not found"); return; }
        if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) return;
        boolean ok = gatt.readCharacteristic(chr);
        Log.d(TAG, "readProvisioningConfig enqueued=" + ok);
    }

    /**
     * VULNERABILITY #2: raw bytes written directly with no validation.
     * Whatever string is passed (including malformed/injected JSON) goes straight
     * to the characteristic.
     */
    public void writeThreshold(String rawJson) {
        if (gatt == null) { Log.w(TAG, "writeThreshold: gatt is null"); return; }
        BluetoothGattCharacteristic chr = findCharacteristic(ALERT_SERVICE, ALERT_THRESHOLD);
        if (chr == null) { listener.onLog("ALERT_THRESHOLD characteristic not found"); return; }
        if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) return;
        chr.setValue(rawJson.getBytes(StandardCharsets.UTF_8));
        boolean ok = gatt.writeCharacteristic(chr);
        Log.d(TAG, "writeThreshold enqueued=" + ok + " val=" + rawJson);
        listener.onLog("WriteThreshold → " + rawJson);
    }

    /** Re-issue enableNotify for HR and PLX without reconnecting. Useful for recovery. */
    public void resubscribeNotifications() {
        if (gatt == null) { Log.w(TAG, "resubscribe: gatt is null"); return; }
        Log.d(TAG, "resubscribeNotifications()");
        listener.onLog("Re-subscribing notifications…");
        enqueueNotify(HR_SERVICE, HR_MEASUREMENT);
        enqueueNotify(PLX_SERVICE, PLX_CONTINUOUS);
        processNotifyQueue();
    }

    // ── GATT Callback ─────────────────────────────────────────────────────────

    private final BluetoothGattCallback gattCallback = new BluetoothGattCallback() {

        @Override
        public void onConnectionStateChange(BluetoothGatt g, int status, int newState) {
            Log.d(TAG, "onConnectionStateChange status=" + status + " newState=" + newState);
            if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) {
                Log.w(TAG, "Missing BLUETOOTH_CONNECT permission");
                return;
            }
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                String name = g.getDevice().getName();
                String addr = g.getDevice().getAddress();
                Log.d(TAG, "STATE_CONNECTED name=" + name + " addr=" + addr);
                listener.onConnected(name != null ? name : addr, addr);
                listener.onLog("Connected — discovering services…");
                boolean ok = g.discoverServices();
                Log.d(TAG, "discoverServices() enqueued=" + ok);
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                Log.d(TAG, "STATE_DISCONNECTED");
                notifyQueue.clear();
                descriptorWritePending = false;
                listener.onDisconnected();
                listener.onLog("Disconnected");
            }
        }

        @Override
        public void onServicesDiscovered(BluetoothGatt g, int status) {
            Log.d(TAG, "onServicesDiscovered status=" + status);
            if (status != BluetoothGatt.GATT_SUCCESS) {
                listener.onLog("Service discovery failed: " + status);
                Log.e(TAG, "Service discovery failed: " + status);
                return;
            }
            listener.onLog("Services discovered — enabling notifications");
            if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) {
                Log.w(TAG, "Missing BLUETOOTH_CONNECT permission");
                return;
            }

            // Queue both notification subscriptions and process serially
            enqueueNotify(HR_SERVICE, HR_MEASUREMENT);
            enqueueNotify(PLX_SERVICE, PLX_CONTINUOUS);
            processNotifyQueue();

            // Read device info
            readChrc(g, DEVINFO_SERVICE, MANUFACTURER_NAME);
            readChrc(g, DEVINFO_SERVICE, MODEL_NUMBER);

            // Read provisioning config if the hidden service is present
            BluetoothGattService provSvc = g.getService(PROV_SERVICE);
            if (provSvc != null) {
                listener.onLog("Hidden provisioning service (0xFF10) found — reading config…");
                readChrc(g, PROV_SERVICE, PROV_CONFIG);
            }
        }

        @Override
        public void onDescriptorWrite(BluetoothGatt g, BluetoothGattDescriptor descriptor, int status) {
            UUID chrUuid = descriptor.getCharacteristic().getUuid();
            Log.d(TAG, "onDescriptorWrite chr=" + chrUuid + " status=" + status + " desc=" + descriptor.getUuid());
            descriptorWritePending = false;
            if (status != BluetoothGatt.GATT_SUCCESS) {
                Log.e(TAG, "Descriptor write FAILED for " + chrUuid + " status=" + status);
                listener.onLog("Descriptor write FAILED: " + chrUuid + " err=" + status);
            } else {
                Log.d(TAG, "Descriptor write OK for " + chrUuid);
                listener.onLog("Descriptor write OK: " + chrUuid);
            }
            processNotifyQueue();
        }

        @Override
        public void onCharacteristicRead(BluetoothGatt g, BluetoothGattCharacteristic c, int status) {
            Log.d(TAG, "onCharacteristicRead uuid=" + c.getUuid() + " status=" + status);
            if (status != BluetoothGatt.GATT_SUCCESS) {
                Log.w(TAG, "Characteristic read failed status=" + status);
                return;
            }
            UUID uuid = c.getUuid();
            String value = new String(c.getValue(), StandardCharsets.UTF_8);

            if (uuid.equals(MANUFACTURER_NAME)) listener.onManufacturerRead(value);
            else if (uuid.equals(MODEL_NUMBER))  listener.onModelRead(value);
            else if (uuid.equals(ALERT_THRESHOLD)) listener.onThresholdRead(value);
            else if (uuid.equals(PROV_CONFIG)) listener.onProvisioningStateRead(value);
        }

        @Override
        public void onCharacteristicChanged(BluetoothGatt g, BluetoothGattCharacteristic c) {
            UUID uuid = c.getUuid();
            byte[] value = c.getValue();
            Log.d(TAG, "onCharacteristicChanged uuid=" + uuid + " len=" + (value == null ? "null" : value.length));
            if (value == null) { Log.w(TAG, "Changed characteristic value is null"); return; }

            if (uuid.equals(HR_MEASUREMENT) && value.length >= 2) {
                int bpm = value[1] & 0xFF;
                Log.d(TAG, "HR notify: " + bpm + " BPM  raw=" + bytesToHex(value));
                listener.onBpmUpdated(bpm);
                VitalsLogger.log(bpm, -1); // VULNERABILITY #3: plaintext log
            } else if (uuid.equals(PLX_CONTINUOUS) && value.length >= 2) {
                int spo2 = value[1] & 0xFF;
                Log.d(TAG, "SpO2 notify: " + spo2 + "%  raw=" + bytesToHex(value));
                listener.onSpo2Updated(spo2);
                VitalsLogger.log(-1, spo2);
            } else {
                Log.w(TAG, "Unhandled characteristic changed: " + uuid);
            }
        }

        @Override
        public void onCharacteristicWrite(BluetoothGatt g, BluetoothGattCharacteristic c, int status) {
            Log.d(TAG, "onCharacteristicWrite uuid=" + c.getUuid() + " status=" + status);
            listener.onLog("WriteThreshold result: " + (status == BluetoothGatt.GATT_SUCCESS ? "OK" : "FAIL " + status));
        }
    };

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void enqueueNotify(UUID serviceUuid, UUID chrUuid) {
        notifyQueue.offer(new NotifyRequest(serviceUuid, chrUuid));
    }

    private void processNotifyQueue() {
        if (descriptorWritePending || notifyQueue.isEmpty()) return;
        NotifyRequest req = notifyQueue.poll();
        if (req == null) return;
        if (gatt == null) { Log.w(TAG, "processNotifyQueue: gatt is null"); return; }
        enableNotify(gatt, req.serviceUuid, req.chrUuid);
    }

    private void enableNotify(BluetoothGatt g, UUID serviceUuid, UUID chrUuid) {
        if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) {
            Log.w(TAG, "enableNotify: missing BLUETOOTH_CONNECT");
            return;
        }
        Log.d(TAG, "enableNotify service=" + serviceUuid + " chr=" + chrUuid);
        BluetoothGattCharacteristic chr = findCharacteristic(serviceUuid, chrUuid);
        if (chr == null) {
            Log.e(TAG, "enableNotify FAILED: characteristic not found " + chrUuid);
            listener.onLog("EnableNotify FAILED: chr not found " + chrUuid);
            return;
        }
        boolean notifyOk = g.setCharacteristicNotification(chr, true);
        Log.d(TAG, "setCharacteristicNotification(" + chrUuid + ")=" + notifyOk);
        BluetoothGattDescriptor desc = chr.getDescriptor(CCC_DESCRIPTOR);
        if (desc != null) {
            desc.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
            boolean writeOk = g.writeDescriptor(desc);
            descriptorWritePending = writeOk;
            Log.d(TAG, "writeDescriptor(" + chrUuid + ") enqueued=" + writeOk);
        } else {
            Log.w(TAG, "enableNotify: CCC descriptor missing for " + chrUuid);
        }
    }

    private void readChrc(BluetoothGatt g, UUID serviceUuid, UUID chrUuid) {
        if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) return;
        BluetoothGattCharacteristic chr = findCharacteristic(serviceUuid, chrUuid);
        if (chr != null) {
            boolean ok = g.readCharacteristic(chr);
            Log.d(TAG, "readChrc(" + chrUuid + ") enqueued=" + ok);
        } else {
            Log.w(TAG, "readChrc: chr not found " + chrUuid);
        }
    }

    private BluetoothGattCharacteristic findCharacteristic(UUID serviceUuid, UUID chrUuid) {
        if (gatt == null) { Log.w(TAG, "findCharacteristic: gatt is null"); return null; }
        BluetoothGattService svc = gatt.getService(serviceUuid);
        if (svc == null) {
            Log.w(TAG, "findCharacteristic: service not found " + serviceUuid);
            return null;
        }
        BluetoothGattCharacteristic chr = svc.getCharacteristic(chrUuid);
        if (chr == null) {
            Log.w(TAG, "findCharacteristic: characteristic not found " + chrUuid);
        }
        return chr;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X ", b));
        return sb.toString().trim();
    }

    private boolean hasPermission(String permission) {
        return ActivityCompat.checkSelfPermission(context, permission)
                == PackageManager.PERMISSION_GRANTED;
    }

    public void close() {
        if (gatt != null && hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) {
            gatt.close();
            gatt = null;
            Log.d(TAG, "gatt.close() called");
        }
    }
}
