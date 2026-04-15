package com.example.careotter_app;

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
import android.bluetooth.le.ScanResult;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

import java.util.UUID;

/**
 * MainActivity — CareOtter Admin App
 *
 * IGP v4 administration panel (TCP :9999) + BLE status indicator.
 * New commands:
 *   0x0B DEFIBRILLATE — format string sink on device log
 *   0x0C EMERGENCY_ALERT — OS command injection via system(curl)
 */
public class MainActivity extends AppCompatActivity {

    private static final int REQUEST_BLE_PERMISSIONS = 1;
    private static final UUID ALERT_THRESHOLD_UUID =
            UUID.fromString("0000ff01-0000-1000-8000-00805f9b34fb");
    private static final UUID HR_MEASUREMENT_UUID =
            UUID.fromString("00002a37-0000-1000-8000-00805f9b34fb");

    // IGP client
    private CareOtterClient client;

    // BLE
    private BluetoothAdapter bluetoothAdapter;
    private BluetoothLeScanner bleScanner;
    private BluetoothGatt bluetoothGatt;
    private boolean bleConnected = false;
    private boolean scanning = false;

    // UI
    private EditText etIpAddress;
    private EditText etModuleName;
    private TextView tvAuthStatus;
    private TextView tvBleStatus;
    private TextView tvOutput;
    private ScrollView scrollOutput;

    private final Handler uiHandler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Bind views
        etIpAddress   = findViewById(R.id.etIpAddress);
        etModuleName  = findViewById(R.id.etModuleName);
        tvAuthStatus  = findViewById(R.id.tvAuthStatus);
        tvBleStatus   = findViewById(R.id.tvBleStatus);
        tvOutput      = findViewById(R.id.tvOutput);
        scrollOutput  = findViewById(R.id.scrollOutput);

        // ── IGP buttons ───────────────────────────────────────────
        findViewById(R.id.btnConnect).setOnClickListener(v -> {
            client = null; // force reconnect with new IP
            runIgp(() -> {
                String r = getClient().getSystemInfo();
                appendOutput("SYS_INFO: " + r);
            });
        });

        findViewById(R.id.btnCheckStatus).setOnClickListener(v -> {
            // Full flow: sysinfo → auth → wifi config
            runIgp(() -> {
                CareOtterClient c = getClient();
                String info = c.getSystemInfo();
                appendOutput("SYS_INFO: " + info);
                String authResult = c.authenticate();
                appendOutput("AUTH: " + authResult);
                if (authResult.contains("AUTH_SUCCESS")) {
                    uiHandler.post(() -> tvAuthStatus.setText("Estado: Autenticado ✓"));
                    String wifi = c.getWifiConfig();
                    appendOutput("WIFI_CONFIG:\n" + wifi);
                }
            });
        });

        findViewById(R.id.btnSysInfo).setOnClickListener(v ->
                runIgp(() -> appendOutput("SYS_INFO: " + getClient().getSystemInfo())));

        findViewById(R.id.btnAuthenticate).setOnClickListener(v -> runIgp(() -> {
            String r = getClient().authenticate();
            appendOutput("AUTH: " + r);
            if (r.contains("AUTH_SUCCESS"))
                uiHandler.post(() -> tvAuthStatus.setText("Estado: Autenticado ✓"));
        }));

        findViewById(R.id.btnWifiConfig).setOnClickListener(v ->
                runIgp(() -> appendOutput("WIFI_CONFIG:\n" + getClient().getWifiConfig())));

        findViewById(R.id.btnSetTheme).setOnClickListener(v -> {
            String theme = etModuleName.getText().toString().trim();
            if (theme.isEmpty()) theme = "DarkMode";
            final String t = theme;
            runIgp(() -> appendOutput("SET_THEME(" + t + "): " + getClient().setAppTheme(t)));
        });

        findViewById(R.id.btnStatus).setOnClickListener(v -> {
            String module = etModuleName.getText().toString().trim();
            if (module.isEmpty()) module = "CareOtter";
            final String m = module;
            runIgp(() -> appendOutput("STATUS(" + m + "):\n" + getClient().verifyStatus(m)));
        });

        findViewById(R.id.btnFormatString).setOnClickListener(v ->
                runIgp(() -> appendOutput("FMT_STRING_LEAK:\n" +
                        getClient().verifyStatus("%x.%x.%x.%x"))));

        findViewById(R.id.btnUnderflow).setOnClickListener(v ->
                runIgp(() -> appendOutput("UNDERFLOW: " + getClient().exploitUnderflow())));

        // ── New commands ──────────────────────────────────────────

        findViewById(R.id.btnDefibrillate).setOnClickListener(v ->
                runIgp(() -> appendOutput("DEFIBRILLATE: " + getClient().triggerDefibrillator())));

        findViewById(R.id.btnEmergencyAlert).setOnClickListener(v -> {
            String msg = etModuleName.getText().toString().trim();
            if (msg.isEmpty()) msg = "patient alert";
            final String m = msg;
            runIgp(() -> appendOutput("EMERGENCY_ALERT: " + getClient().sendEmergencyAlert(m)));
        });

        findViewById(R.id.btnCmdInjection).setOnClickListener(v ->
                runIgp(() -> appendOutput("CMD_INJECTION:\n" +
                        getClient().exploitCommandInjection())));

        findViewById(R.id.btnClear).setOnClickListener(v -> tvOutput.setText(""));

        // ── BLE ───────────────────────────────────────────────────
        bluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
        if (bluetoothAdapter != null) {
            requestBlePermissions();
        } else {
            if (tvBleStatus != null)
                tvBleStatus.setText("BLE: No disponible en este dispositivo");
        }
    }

    // ── Helpers ───────────────────────────────────────────────────

    private CareOtterClient getClient() {
        if (client == null) {
            String ip = etIpAddress.getText().toString().trim();
            if (ip.isEmpty()) ip = "192.168.2.1";
            client = new CareOtterClient(ip, 9999);
        }
        return client;
    }

    private void runIgp(IgpTask task) {
        new Thread(() -> {
            try {
                task.run();
            } catch (Exception e) {
                appendOutput("ERROR: " + e.getMessage());
            }
        }).start();
    }

    private void appendOutput(String text) {
        uiHandler.post(() -> {
            String current = tvOutput.getText().toString();
            tvOutput.setText(current.isEmpty() ? text : current + "\n─\n" + text);
            scrollOutput.post(() -> scrollOutput.fullScroll(View.FOCUS_DOWN));
        });
    }

    @FunctionalInterface
    interface IgpTask {
        void run() throws Exception;
    }

    // ── BLE permissions & scan ────────────────────────────────────

    private void requestBlePermissions() {
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_SCAN)
                != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, new String[]{
                    Manifest.permission.BLUETOOTH_SCAN,
                    Manifest.permission.BLUETOOTH_CONNECT,
                    Manifest.permission.ACCESS_FINE_LOCATION
            }, REQUEST_BLE_PERMISSIONS);
        } else {
            startBleScan();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(requestCode, permissions, results);
        if (requestCode == REQUEST_BLE_PERMISSIONS) {
            boolean granted = results.length > 0 &&
                    results[0] == PackageManager.PERMISSION_GRANTED;
            if (granted) startBleScan();
            else Toast.makeText(this, "Permisos BLE denegados", Toast.LENGTH_SHORT).show();
        }
    }

    private void startBleScan() {
        if (bluetoothAdapter == null || !bluetoothAdapter.isEnabled()) return;
        bleScanner = bluetoothAdapter.getBluetoothLeScanner();
        if (bleScanner == null) return;
        if (scanning) return;
        scanning = true;

        if (tvBleStatus != null)
            uiHandler.post(() -> tvBleStatus.setText("BLE: Buscando CareOtter_HR…"));

        bleScanner.startScan(new ScanCallback() {
            @Override
            public void onScanResult(int callbackType, ScanResult result) {
                BluetoothDevice device = result.getDevice();
                String name = ActivityCompat.checkSelfPermission(MainActivity.this,
                        Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED
                        ? device.getName() : null;
                if ("CareOtter_HR".equals(name)) {
                    bleScanner.stopScan(this);
                    scanning = false;
                    connectBle(device);
                }
            }
        });
    }

    private void connectBle(BluetoothDevice device) {
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT)
                != PackageManager.PERMISSION_GRANTED) return;

        bluetoothGatt = device.connectGatt(this, false, new BluetoothGattCallback() {

            @Override
            public void onConnectionStateChange(BluetoothGatt gatt, int status, int newState) {
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    bleConnected = true;
                    String addr = ActivityCompat.checkSelfPermission(MainActivity.this,
                            Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED
                            ? device.getAddress() : "?";
                    uiHandler.post(() -> {
                        if (tvBleStatus != null) {
                            tvBleStatus.setText("BLE: Conectado — " + addr);
                            tvBleStatus.setTextColor(0xFF4CAF50);
                        }
                    });
                    if (ActivityCompat.checkSelfPermission(MainActivity.this,
                            Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED)
                        gatt.discoverServices();

                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    bleConnected = false;
                    uiHandler.post(() -> {
                        if (tvBleStatus != null) {
                            tvBleStatus.setText("BLE: Desconectado");
                            tvBleStatus.setTextColor(0xFFFF6B6B);
                        }
                    });
                }
            }

            @Override
            public void onServicesDiscovered(BluetoothGatt gatt, int status) {
                if (status != BluetoothGatt.GATT_SUCCESS) return;
                if (ActivityCompat.checkSelfPermission(MainActivity.this,
                        Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED)
                    return;
                for (BluetoothGattService svc : gatt.getServices()) {
                    BluetoothGattCharacteristic hr =
                            svc.getCharacteristic(HR_MEASUREMENT_UUID);
                    if (hr != null) {
                        gatt.setCharacteristicNotification(hr, true);
                    }
                }
            }

            @Override
            public void onCharacteristicChanged(BluetoothGatt gatt,
                                                BluetoothGattCharacteristic characteristic) {
                byte[] value = characteristic.getValue();
                if (value == null || value.length < 2) return;
                int bpm = value[1] & 0xFF;
                uiHandler.post(() -> {
                    if (tvBleStatus != null)
                        tvBleStatus.setText("BLE: Conectado — " + bpm + " BPM");
                });
            }
        });
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (bluetoothGatt != null) {
            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT)
                    == PackageManager.PERMISSION_GRANTED)
                bluetoothGatt.close();
            bluetoothGatt = null;
        }
    }
}
