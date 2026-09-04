package com.vulnzoo.bulbbee_app;

import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * BulbBee Android controller (BULB-APP). Minimal BLE client of the BulbBee
 * Lighting Control service. Intentionally vulnerable, this is training code.
 *
 * VULNERABILITY M1 (Improper Credential Usage) / CWE-798: the factory pairing
 *   PIN is hardcoded here, so it is extractable from the shipped APK and is the
 *   same on every device (this is the client side of BULB-01).
 * VULNERABILITY M9 (Insecure Data Storage) / CWE-312: the home WiFi PSK and the
 *   cloud pairing token are stored in plaintext SharedPreferences and written to
 *   Logcat (the client side of BULB-05).
 */
public class MainActivity extends Activity {

    private static final String TAG = "BulbBee";

    // Lighting Control service and characteristics (match the device, 0xFF3x).
    private static final UUID CONTROL = UUID.fromString("0000ff31-0000-1000-8000-00805f9b34fb");
    private static final UUID STATE   = UUID.fromString("0000ff32-0000-1000-8000-00805f9b34fb");
    private static final UUID AUTH    = UUID.fromString("0000ff41-0000-1000-8000-00805f9b34fb");
    private static final UUID CONFIG  = UUID.fromString("0000ff42-0000-1000-8000-00805f9b34fb");

    // VULNERABILITY M1 / CWE-798: hardcoded factory pairing PIN, identical on
    // every unit, recoverable by unzipping the APK.
    private static final String PAIRING_PIN = "8080";

    private BluetoothGatt gatt;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // (layout omitted for the training skeleton)
    }

    /** Connect to the advertised BulbBee peripheral (no bonding, matches the device). */
    public void connect(BluetoothDevice device) {
        gatt = device.connectGatt(this, false, new BluetoothGattCallback() {
            @Override
            public void onServicesDiscovered(BluetoothGatt g, int status) {
                unlockAndProvision(g, "HomeWiFi", "hunter2-psk", "cloud-token-abc");
            }
        });
    }

    /** Write a lighting command, e.g. {"scene":"rainbow"}. */
    public void setScene(String scene) {
        BluetoothGattCharacteristic c = characteristic(CONTROL);
        if (c == null) return;
        c.setValue(("{\"scene\":\"" + scene + "\"}").getBytes(StandardCharsets.UTF_8));
        gatt.writeCharacteristic(c);
    }

    /** Onboard the device: unlock with the hardcoded PIN, then push WiFi creds. */
    public void unlockAndProvision(BluetoothGatt g, String ssid, String psk, String cloudToken) {
        BluetoothGattCharacteristic auth = g.getService(
                UUID.fromString("0000ff40-0000-1000-8000-00805f9b34fb")).getCharacteristic(AUTH);
        auth.setValue(PAIRING_PIN.getBytes(StandardCharsets.UTF_8));   // M1: hardcoded PIN
        g.writeCharacteristic(auth);

        BluetoothGattCharacteristic cfg = g.getService(
                UUID.fromString("0000ff40-0000-1000-8000-00805f9b34fb")).getCharacteristic(CONFIG);
        String body = "{\"cmd\":\"wifi_set\",\"ssid\":\"" + ssid + "\",\"psk\":\"" + psk + "\"}";
        cfg.setValue(body.getBytes(StandardCharsets.UTF_8));
        g.writeCharacteristic(cfg);

        storeCredentials(ssid, psk, cloudToken);
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

    private BluetoothGattCharacteristic characteristic(UUID uuid) {
        if (gatt == null) return null;
        return gatt.getService(UUID.fromString("0000ff30-0000-1000-8000-00805f9b34fb"))
                .getCharacteristic(uuid);
    }
}
