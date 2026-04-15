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

import androidx.core.app.ActivityCompat;

import java.nio.charset.StandardCharsets;
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
        void onLog(String message);
    }

    private final Context context;
    private final Listener listener;
    private BluetoothAdapter bluetoothAdapter;
    private BluetoothLeScanner scanner;
    private BluetoothGatt gatt;
    private boolean scanning = false;

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
        listener.onLog("Connecting to " + address + "…");
    }

    public void disconnect() {
        if (gatt == null) return;
        if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) return;
        gatt.disconnect();
    }

    // ── Characteristic read/write ─────────────────────────────────────────────

    public void readThreshold() {
        if (gatt == null) return;
        BluetoothGattCharacteristic chr = findCharacteristic(ALERT_SERVICE, ALERT_THRESHOLD);
        if (chr == null) { listener.onLog("ALERT_THRESHOLD characteristic not found"); return; }
        if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) return;
        gatt.readCharacteristic(chr);
    }

    /**
     * VULNERABILITY #2: raw bytes written directly with no validation.
     * Whatever string is passed (including malformed/injected JSON) goes straight
     * to the characteristic.
     */
    public void writeThreshold(String rawJson) {
        if (gatt == null) return;
        BluetoothGattCharacteristic chr = findCharacteristic(ALERT_SERVICE, ALERT_THRESHOLD);
        if (chr == null) { listener.onLog("ALERT_THRESHOLD characteristic not found"); return; }
        if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) return;
        chr.setValue(rawJson.getBytes(StandardCharsets.UTF_8));
        gatt.writeCharacteristic(chr);
        listener.onLog("WriteThreshold → " + rawJson);
    }

    // ── GATT Callback ─────────────────────────────────────────────────────────

    private final BluetoothGattCallback gattCallback = new BluetoothGattCallback() {

        @Override
        public void onConnectionStateChange(BluetoothGatt g, int status, int newState) {
            if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) return;
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                String name = g.getDevice().getName();
                String addr = g.getDevice().getAddress();
                listener.onConnected(name != null ? name : addr, addr);
                listener.onLog("Connected — discovering services…");
                g.discoverServices();
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                listener.onDisconnected();
                listener.onLog("Disconnected");
            }
        }

        @Override
        public void onServicesDiscovered(BluetoothGatt g, int status) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                listener.onLog("Service discovery failed: " + status);
                return;
            }
            listener.onLog("Services discovered — enabling notifications");
            if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) return;

            enableNotify(g, HR_SERVICE, HR_MEASUREMENT);
            enableNotify(g, PLX_SERVICE, PLX_CONTINUOUS);

            // Read device info
            readChrc(g, DEVINFO_SERVICE, MANUFACTURER_NAME);
            readChrc(g, DEVINFO_SERVICE, MODEL_NUMBER);
        }

        @Override
        public void onCharacteristicRead(BluetoothGatt g, BluetoothGattCharacteristic c, int status) {
            if (status != BluetoothGatt.GATT_SUCCESS) return;
            UUID uuid = c.getUuid();
            String value = new String(c.getValue(), StandardCharsets.UTF_8);

            if (uuid.equals(MANUFACTURER_NAME)) listener.onManufacturerRead(value);
            else if (uuid.equals(MODEL_NUMBER))  listener.onModelRead(value);
            else if (uuid.equals(ALERT_THRESHOLD)) listener.onThresholdRead(value);
        }

        @Override
        public void onCharacteristicChanged(BluetoothGatt g, BluetoothGattCharacteristic c) {
            UUID uuid = c.getUuid();
            byte[] value = c.getValue();
            if (value == null) return;

            if (uuid.equals(HR_MEASUREMENT) && value.length >= 2) {
                int bpm = value[1] & 0xFF;
                listener.onBpmUpdated(bpm);
                VitalsLogger.log(bpm, -1); // VULNERABILITY #3: plaintext log
            } else if (uuid.equals(PLX_CONTINUOUS) && value.length >= 2) {
                int spo2 = value[1] & 0xFF;
                listener.onSpo2Updated(spo2);
                VitalsLogger.log(-1, spo2);
            }
        }

        @Override
        public void onCharacteristicWrite(BluetoothGatt g, BluetoothGattCharacteristic c, int status) {
            listener.onLog("WriteThreshold result: " + (status == BluetoothGatt.GATT_SUCCESS ? "OK" : "FAIL " + status));
        }
    };

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void enableNotify(BluetoothGatt g, UUID serviceUuid, UUID chrUuid) {
        if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) return;
        BluetoothGattCharacteristic chr = findCharacteristic(serviceUuid, chrUuid);
        if (chr == null) return;
        g.setCharacteristicNotification(chr, true);
        BluetoothGattDescriptor desc = chr.getDescriptor(CCC_DESCRIPTOR);
        if (desc != null) {
            desc.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
            g.writeDescriptor(desc);
        }
    }

    private void readChrc(BluetoothGatt g, UUID serviceUuid, UUID chrUuid) {
        if (!hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) return;
        BluetoothGattCharacteristic chr = findCharacteristic(serviceUuid, chrUuid);
        if (chr != null) g.readCharacteristic(chr);
    }

    private BluetoothGattCharacteristic findCharacteristic(UUID serviceUuid, UUID chrUuid) {
        if (gatt == null) return null;
        BluetoothGattService svc = gatt.getService(serviceUuid);
        return (svc != null) ? svc.getCharacteristic(chrUuid) : null;
    }

    private boolean hasPermission(String permission) {
        return ActivityCompat.checkSelfPermission(context, permission)
                == PackageManager.PERMISSION_GRANTED;
    }

    public void close() {
        if (gatt != null && hasPermission(Manifest.permission.BLUETOOTH_CONNECT)) {
            gatt.close();
            gatt = null;
        }
    }
}
