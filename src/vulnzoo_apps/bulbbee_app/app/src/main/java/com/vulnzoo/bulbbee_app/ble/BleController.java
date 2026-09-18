package com.vulnzoo.bulbbee_app.ble;

import android.annotation.SuppressLint;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelUuid;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Queue;
import java.util.UUID;

/**
 * BLE transport for the BulbBee controller. Scans for the peripheral, connects
 * with no bonding (the client side of BULB-02 / BULB-03: unauthenticated and
 * unencrypted control), and serializes GATT operations through a one-at-a-time
 * queue (GATT allows a single outstanding operation).
 *
 * Permissions (BLUETOOTH_SCAN / BLUETOOTH_CONNECT) are requested by MainActivity
 * before any method here is called, so the class-level suppression is the
 * documented contract rather than a missing check.
 */
@SuppressLint("MissingPermission")
public class BleController {

    private static final String TAG = "BulbBee";

    static final UUID LIGHT_SERVICE = UUID.fromString("0000ff30-0000-1000-8000-00805f9b34fb");
    static final UUID CONTROL_CHAR  = UUID.fromString("0000ff31-0000-1000-8000-00805f9b34fb");
    static final UUID STATE_CHAR    = UUID.fromString("0000ff32-0000-1000-8000-00805f9b34fb");
    static final UUID PROV_SERVICE  = UUID.fromString("0000ff40-0000-1000-8000-00805f9b34fb");
    static final UUID PROV_AUTH     = UUID.fromString("0000ff41-0000-1000-8000-00805f9b34fb");
    static final UUID PROV_CONFIG   = UUID.fromString("0000ff42-0000-1000-8000-00805f9b34fb");
    static final UUID CCCD          = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");

    public interface Listener {
        void onConnectionChange(boolean connected, String message);
        void onStateJson(String json);
        void onProvisionResult(boolean ok, String message);
        void onInfo(String message);
    }

    private final Context appContext;
    private final BluetoothAdapter adapter;
    private final Listener listener;
    private final Handler main = new Handler(Looper.getMainLooper());

    private BluetoothGatt gatt;
    private BluetoothLeScanner scanner;
    private boolean scanning = false;

    private final Queue<Runnable> gattQueue = new ArrayDeque<>();
    private boolean gattBusy = false;

    public BleController(Context context, Listener listener) {
        this.appContext = context.getApplicationContext();
        this.listener = listener;
        BluetoothManager bm = (BluetoothManager) appContext.getSystemService(Context.BLUETOOTH_SERVICE);
        this.adapter = bm != null ? bm.getAdapter() : null;
        this.scanTimeout = () -> {
            if (scanning) {
                stopScan();
                listener.onConnectionChange(false, "BulbBee not found");
            }
        };
    }

    public boolean isBluetoothReady() {
        return adapter != null && adapter.isEnabled();
    }

    // ── scan + connect ────────────────────────────────────────────────

    public void scanAndConnect() {
        if (!isBluetoothReady()) {
            listener.onInfo("Bluetooth off");
            return;
        }
        if (scanning) return;
        scanner = adapter.getBluetoothLeScanner();
        ScanFilter filter = new ScanFilter.Builder()
                .setServiceUuid(new ParcelUuid(LIGHT_SERVICE))
                .build();
        ScanSettings settings = new ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .build();
        scanning = true;
        scanner.startScan(Collections.singletonList(filter), settings, scanCallback);
        main.postDelayed(scanTimeout, 12000);
    }

    private final Runnable scanTimeout;

    private void stopScan() {
        if (scanning && scanner != null) {
            scanner.stopScan(scanCallback);
        }
        scanning = false;
        main.removeCallbacks(scanTimeout);
    }

    private final ScanCallback scanCallback = new ScanCallback() {
        @Override
        public void onScanResult(int callbackType, ScanResult result) {
            if (!scanning) return;
            stopScan();
            BluetoothDevice device = result.getDevice();
            listener.onConnectionChange(false, "Connecting…");
            gatt = device.connectGatt(appContext, false, gattCallback);
        }

        @Override
        public void onScanFailed(int errorCode) {
            stopScan();
            listener.onConnectionChange(false, "Scan failed (" + errorCode + ")");
        }
    };

    // ── GATT ──────────────────────────────────────────────────────────

    private final BluetoothGattCallback gattCallback = new BluetoothGattCallback() {
        @Override
        public void onConnectionStateChange(BluetoothGatt g, int status, int newState) {
            if (newState == BluetoothGatt.STATE_CONNECTED) {
                g.discoverServices();
            } else if (newState == BluetoothGatt.STATE_DISCONNECTED) {
                clearQueue();
                g.close();
                gatt = null;
                main.post(() -> listener.onConnectionChange(false, "Disconnected"));
            }
        }

        @Override
        public void onServicesDiscovered(BluetoothGatt g, int status) {
            enableStateNotifications(g);
            main.post(() -> listener.onConnectionChange(true, "Connected to BulbBee"));
        }

        @Override
        public void onCharacteristicWrite(BluetoothGatt g, BluetoothGattCharacteristic c, int status) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                main.post(() -> listener.onInfo("Write failed (" + status + ")"));
            }
            opDone();
        }

        @Override
        public void onDescriptorWrite(BluetoothGatt g, BluetoothGattDescriptor d, int status) {
            opDone();
        }

        @Override
        public void onCharacteristicChanged(BluetoothGatt g, BluetoothGattCharacteristic c) {
            if (STATE_CHAR.equals(c.getUuid())) {
                byte[] v = c.getValue();
                if (v != null) {
                    final String json = new String(v, StandardCharsets.UTF_8);
                    main.post(() -> listener.onStateJson(json));
                }
            }
        }
    };

    private void enableStateNotifications(BluetoothGatt g) {
        BluetoothGattCharacteristic state = characteristic(g, LIGHT_SERVICE, STATE_CHAR);
        if (state == null) return;
        g.setCharacteristicNotification(state, true);
        BluetoothGattDescriptor cccd = state.getDescriptor(CCCD);
        if (cccd == null) return;
        enqueue(() -> {
            cccd.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
            g.writeDescriptor(cccd);
        });
    }

    // ── public control API ────────────────────────────────────────────

    /** Write a JSON command to the Control characteristic, e.g. {"scene":"rainbow"}. */
    public void sendControl(String json) {
        BluetoothGatt g = gatt;
        if (g == null) return;
        BluetoothGattCharacteristic c = characteristic(g, LIGHT_SERVICE, CONTROL_CHAR);
        if (c == null) return;
        enqueue(() -> {
            c.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
            c.setValue(json.getBytes(StandardCharsets.UTF_8));
            g.writeCharacteristic(c);
        });
    }

    /**
     * Onboard the device: unlock with the factory PIN, then push the WiFi creds.
     * The link is not bonded, so the PIN is the only gate (BULB-01).
     */
    public void provision(String pin, String ssid, String psk) {
        BluetoothGatt g = gatt;
        if (g == null) {
            listener.onProvisionResult(false, "Not connected");
            return;
        }
        BluetoothGattCharacteristic auth = characteristic(g, PROV_SERVICE, PROV_AUTH);
        BluetoothGattCharacteristic cfg = characteristic(g, PROV_SERVICE, PROV_CONFIG);
        if (auth == null || cfg == null) {
            listener.onProvisionResult(false, "Provisioning service not available");
            return;
        }
        enqueue(() -> {
            auth.setValue(pin.getBytes(StandardCharsets.UTF_8));   // BULB-01: factory PIN
            g.writeCharacteristic(auth);
        });
        String body = "{\"cmd\":\"wifi_set\",\"ssid\":\"" + ssid + "\",\"psk\":\"" + psk + "\"}";
        enqueue(() -> {
            cfg.setValue(body.getBytes(StandardCharsets.UTF_8));
            g.writeCharacteristic(cfg);
        });
        enqueue(() -> {
            main.post(() -> listener.onProvisionResult(true, "WiFi sent to BulbBee"));
            opDone();
        });
    }

    public void disconnect() {
        stopScan();
        BluetoothGatt g = gatt;
        if (g != null) {
            g.disconnect();
        }
    }

    // ── GATT operation queue (one outstanding op at a time) ───────────

    private synchronized void enqueue(Runnable op) {
        gattQueue.add(op);
        if (!gattBusy) nextOp();
    }

    private synchronized void nextOp() {
        if (gattBusy) return;
        Runnable op = gattQueue.poll();
        if (op == null) return;
        gattBusy = true;
        main.post(op);
    }

    private synchronized void opDone() {
        gattBusy = false;
        nextOp();
    }

    private synchronized void clearQueue() {
        gattQueue.clear();
        gattBusy = false;
    }

    private static BluetoothGattCharacteristic characteristic(BluetoothGatt g, UUID service, UUID chrc) {
        if (g.getService(service) == null) return null;
        return g.getService(service).getCharacteristic(chrc);
    }
}
