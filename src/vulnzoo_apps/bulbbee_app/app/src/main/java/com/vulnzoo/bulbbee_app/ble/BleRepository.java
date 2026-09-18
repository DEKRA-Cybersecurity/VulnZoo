package com.vulnzoo.bulbbee_app.ble;

import android.content.Context;

import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Single owner of the BLE transport, exposed to the UI as LiveData. Fragments and
 * the {@code LightViewModel} observe this instead of holding a GATT callback each,
 * so there is one connection and one lighting state across every screen.
 *
 * The GATT plumbing itself stays in {@link BleController}. The intentional
 * vulnerabilities live in the UI layer (the hardcoded PIN and the plaintext
 * credential store in {@code SetupFragment}), not here.
 */
public class BleRepository implements BleController.Listener {

    /** Result of a provisioning attempt, observed by the setup screen. */
    public static final class ProvResult {
        public final boolean ok;
        public final String message;
        ProvResult(boolean ok, String message) { this.ok = ok; this.message = message; }
    }

    private static volatile BleRepository instance;

    private final BleController ble;

    private final MutableLiveData<Boolean> connected = new MutableLiveData<>(false);
    private final MutableLiveData<String> status = new MutableLiveData<>("");
    private final MutableLiveData<String> stateJson = new MutableLiveData<>();
    private final MutableLiveData<ProvResult> provResult = new MutableLiveData<>();
    private final MutableLiveData<String> writeLog = new MutableLiveData<>("");

    private final Deque<String> recentWrites = new ArrayDeque<>();

    private BleRepository(Context context) {
        this.ble = new BleController(context.getApplicationContext(), this);
    }

    public static BleRepository get(Context context) {
        if (instance == null) {
            synchronized (BleRepository.class) {
                if (instance == null) instance = new BleRepository(context);
            }
        }
        return instance;
    }

    // ── observable state ──────────────────────────────────────────────

    public LiveData<Boolean> connected() { return connected; }
    public LiveData<String> status() { return status; }
    public LiveData<String> stateJson() { return stateJson; }
    public LiveData<ProvResult> provResult() { return provResult; }
    /** The last few Control (0xFF31) writes, newest last, for the "bulb is doing" log. */
    public LiveData<String> writeLog() { return writeLog; }

    public boolean isBluetoothReady() { return ble.isBluetoothReady(); }

    // ── commands ──────────────────────────────────────────────────────

    public void scanAndConnect() { ble.scanAndConnect(); }

    public void disconnect() { ble.disconnect(); }

    /** Write a JSON command to Control (0xFF31), e.g. {"scene":"rainbow"}. */
    public void sendControl(String json) {
        recordWrite(json);
        ble.sendControl(json);
    }

    /** Onboard over BLE. The PIN is the caller's (the hardcoded factory PIN, M1). */
    public void provision(String pin, String ssid, String psk) {
        ble.provision(pin, ssid, psk);
    }

    private void recordWrite(String json) {
        recentWrites.addLast(json);
        while (recentWrites.size() > 4) recentWrites.pollFirst();
        writeLog.postValue(String.join("\n", recentWrites));
    }

    // ── BleController.Listener (background threads -> LiveData) ────────

    @Override
    public void onConnectionChange(boolean isConnected, String message) {
        connected.postValue(isConnected);
        status.postValue(message);
    }

    @Override
    public void onStateJson(String json) { stateJson.postValue(json); }

    @Override
    public void onProvisionResult(boolean ok, String message) {
        provResult.postValue(new ProvResult(ok, message));
    }

    @Override
    public void onInfo(String message) { status.postValue(message); }
}
