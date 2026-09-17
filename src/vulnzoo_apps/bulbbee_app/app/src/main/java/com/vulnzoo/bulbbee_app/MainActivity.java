package com.vulnzoo.bulbbee_app;

import android.Manifest;
import android.bluetooth.BluetoothAdapter;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.materialswitch.MaterialSwitch;
import com.google.android.material.slider.Slider;
import com.google.android.material.textfield.TextInputEditText;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * BulbBee Android controller (BULB-APP). BLE client of the BulbBee lighting
 * service: connect, drive the WS2812 ring, and onboard the device onto WiFi.
 * Intentionally vulnerable, this is training code.
 *
 * VULNERABILITY M1 (Improper Credential Usage) / CWE-798: the factory pairing
 *   PIN is hardcoded here, so it is extractable from the shipped APK and is the
 *   same on every device (this is the client side of BULB-01).
 * VULNERABILITY M9 (Insecure Data Storage) / CWE-312: the home WiFi PSK and the
 *   cloud pairing token are stored in plaintext SharedPreferences and written to
 *   Logcat (the client side of BULB-05).
 */
public class MainActivity extends AppCompatActivity implements BleController.Listener {

    private static final String TAG = "BulbBee";

    // VULNERABILITY M1 / CWE-798: hardcoded factory pairing PIN, identical on
    // every unit, recoverable by unzipping the APK.
    private static final String PAIRING_PIN = "8080";
    // Cloud pairing token shipped with the app (stored in the clear, M9).
    private static final String CLOUD_TOKEN = "cloud-token-abc";

    private BleController ble;
    private boolean connected = false;

    private TextView statusText, liveState, provStatus;
    private MaterialButton connectButton, provisionButton;
    private MaterialSwitch powerSwitch;
    private Slider brightnessSlider, redSlider, greenSlider, blueSlider;
    private View colorPreview, lightCard, provCard;
    private TextInputEditText pinInput, ssidInput, pskInput;

    private final ActivityResultLauncher<String[]> permLauncher =
            registerForActivityResult(new ActivityResultContracts.RequestMultiplePermissions(), granted -> {
                for (Boolean g : granted.values()) {
                    if (!Boolean.TRUE.equals(g)) {
                        statusText.setText("Bluetooth permissions denied");
                        return;
                    }
                }
                startScan();
            });

    private final ActivityResultLauncher<Intent> enableBtLauncher =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), r -> onConnectClicked());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        statusText = findViewById(R.id.statusText);
        liveState = findViewById(R.id.liveState);
        provStatus = findViewById(R.id.provStatus);
        connectButton = findViewById(R.id.connectButton);
        provisionButton = findViewById(R.id.provisionButton);
        powerSwitch = findViewById(R.id.powerSwitch);
        brightnessSlider = findViewById(R.id.brightnessSlider);
        redSlider = findViewById(R.id.redSlider);
        greenSlider = findViewById(R.id.greenSlider);
        blueSlider = findViewById(R.id.blueSlider);
        colorPreview = findViewById(R.id.colorPreview);
        lightCard = findViewById(R.id.lightCard);
        provCard = findViewById(R.id.provCard);
        pinInput = findViewById(R.id.pinInput);
        ssidInput = findViewById(R.id.ssidInput);
        pskInput = findViewById(R.id.pskInput);

        // M1: prefill the shared factory PIN so onboarding "just works".
        pinInput.setText(PAIRING_PIN);

        ble = new BleController(this, this);

        connectButton.setOnClickListener(v -> {
            if (connected) ble.disconnect(); else onConnectClicked();
        });

        powerSwitch.setOnClickListener(v ->
                sendControl("{\"power\":" + powerSwitch.isChecked() + "}"));

        brightnessSlider.addOnSliderTouchListener(new Slider.OnSliderTouchListener() {
            @Override public void onStartTrackingTouch(@NonNull Slider s) { }
            @Override public void onStopTrackingTouch(@NonNull Slider s) {
                sendControl("{\"brightness\":" + (int) s.getValue() + "}");
            }
        });

        Slider.OnSliderTouchListener colorRelease = new Slider.OnSliderTouchListener() {
            @Override public void onStartTrackingTouch(@NonNull Slider s) { }
            @Override public void onStopTrackingTouch(@NonNull Slider s) { sendColor(); }
        };
        Slider.OnChangeListener preview = (s, value, fromUser) -> updateColorPreview();
        for (Slider s : new Slider[]{redSlider, greenSlider, blueSlider}) {
            s.addOnChangeListener(preview);
            s.addOnSliderTouchListener(colorRelease);
        }
        updateColorPreview();

        findViewById(R.id.sceneSolid).setOnClickListener(v -> sendControl("{\"scene\":\"solid\"}"));
        findViewById(R.id.sceneRainbow).setOnClickListener(v -> sendControl("{\"scene\":\"rainbow\"}"));
        findViewById(R.id.sceneBreathe).setOnClickListener(v -> sendControl("{\"scene\":\"breathe\"}"));
        findViewById(R.id.sceneOff).setOnClickListener(v -> sendControl("{\"scene\":\"off\"}"));

        provisionButton.setOnClickListener(v -> onProvisionClicked());

        setControlsEnabled(false);
    }

    // ── connection ────────────────────────────────────────────────────

    private void onConnectClicked() {
        BluetoothAdapter adapter = ((android.bluetooth.BluetoothManager)
                getSystemService(Context.BLUETOOTH_SERVICE)).getAdapter();
        if (adapter == null) {
            statusText.setText("This device has no Bluetooth");
            return;
        }
        if (!adapter.isEnabled()) {
            enableBtLauncher.launch(new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE));
            return;
        }
        String[] needed = requiredPermissions();
        if (allGranted(needed)) startScan();
        else permLauncher.launch(needed);
    }

    private void startScan() {
        statusText.setText(R.string.status_scanning);
        ble.scanAndConnect();
    }

    private String[] requiredPermissions() {
        List<String> perms = new ArrayList<>();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            perms.add(Manifest.permission.BLUETOOTH_SCAN);
            perms.add(Manifest.permission.BLUETOOTH_CONNECT);
        } else {
            perms.add(Manifest.permission.ACCESS_FINE_LOCATION);
        }
        return perms.toArray(new String[0]);
    }

    private boolean allGranted(String[] perms) {
        for (String p : perms) {
            if (ContextCompat.checkSelfPermission(this, p) != PackageManager.PERMISSION_GRANTED) {
                return false;
            }
        }
        return true;
    }

    // ── light control ─────────────────────────────────────────────────

    private void sendControl(String json) {
        if (connected) ble.sendControl(json);
    }

    private void sendColor() {
        sendControl("{\"color\":[" + (int) redSlider.getValue() + ","
                + (int) greenSlider.getValue() + "," + (int) blueSlider.getValue() + "]}");
    }

    private void updateColorPreview() {
        colorPreview.setBackgroundColor(Color.rgb(
                (int) redSlider.getValue(), (int) greenSlider.getValue(), (int) blueSlider.getValue()));
    }

    private void setControlsEnabled(boolean enabled) {
        float alpha = enabled ? 1f : 0.4f;
        lightCard.setAlpha(alpha);
        provCard.setAlpha(alpha);
        for (View v : new View[]{powerSwitch, brightnessSlider, redSlider, greenSlider, blueSlider,
                findViewById(R.id.sceneSolid), findViewById(R.id.sceneRainbow),
                findViewById(R.id.sceneBreathe), findViewById(R.id.sceneOff),
                provisionButton, pinInput, ssidInput, pskInput}) {
            v.setEnabled(enabled);
        }
    }

    // ── WiFi provisioning ─────────────────────────────────────────────

    private void onProvisionClicked() {
        String pin = pinInput.getText() != null ? pinInput.getText().toString() : "";
        String ssid = ssidInput.getText() != null ? ssidInput.getText().toString() : "";
        String psk = pskInput.getText() != null ? pskInput.getText().toString() : "";
        if (ssid.isEmpty()) {
            provStatus.setText("Enter the SSID");
            return;
        }
        provStatus.setText("Sending…");
        ble.provision(pin, ssid, psk);
    }

    /** VULNERABILITY M9 / CWE-312: cleartext credential storage + Logcat leak. */
    private void storeCredentials(String ssid, String psk, String cloudToken) {
        SharedPreferences prefs = getSharedPreferences("bulbbee", Context.MODE_PRIVATE);
        prefs.edit()
                .putString("wifi_ssid", ssid)
                .putString("wifi_psk", psk)          // plaintext at rest
                .putString("cloud_token", cloudToken)
                .apply();
        Log.d(TAG, "stored creds ssid=" + ssid + " psk=" + psk + " token=" + cloudToken); // leaked to Logcat
    }

    // ── BleController.Listener ─────────────────────────────────────────

    @Override
    public void onConnectionChange(boolean isConnected, String message) {
        connected = isConnected;
        statusText.setText(message);
        connectButton.setText(isConnected ? R.string.disconnect : R.string.connect);
        setControlsEnabled(isConnected);
        if (!isConnected) liveState.setText("");
    }

    @Override
    public void onStateJson(String json) {
        try {
            JSONObject o = new JSONObject(json);
            JSONArray c = o.optJSONArray("color");
            String color = c != null ? c.optInt(0) + "," + c.optInt(1) + "," + c.optInt(2) : "?";
            liveState.setText(getString(R.string.state_label) + ": power=" + o.optBoolean("power")
                    + "  brightness=" + o.optInt("brightness")
                    + "  color=[" + color + "]"
                    + "  scene=" + o.optString("scene")
                    + (o.optBoolean("simulated") ? "  (sim)" : "  (hw)"));
        } catch (Exception e) {
            liveState.setText(json);
        }
    }

    @Override
    public void onProvisionResult(boolean ok, String message) {
        provStatus.setText(message);
        if (ok) {
            // M9: persist and log the creds we just pushed, in cleartext.
            String ssid = ssidInput.getText() != null ? ssidInput.getText().toString() : "";
            String psk = pskInput.getText() != null ? pskInput.getText().toString() : "";
            storeCredentials(ssid, psk, CLOUD_TOKEN);
        }
    }

    @Override
    public void onInfo(String message) {
        statusText.setText(message);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        ble.disconnect();
    }
}
