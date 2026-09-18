package com.vulnzoo.bulbbee_app.ui;

import android.app.Application;
import android.graphics.Color;

import androidx.annotation.NonNull;
import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;

import com.vulnzoo.bulbbee_app.ble.BleRepository;

/**
 * Shared, activity-scoped view model over {@link BleRepository}. Every fragment
 * (Light, Scenes, Setup, Scan) resolves the same instance with
 * {@code new ViewModelProvider(requireActivity())}, so the connection and the
 * lighting state are one thing across the bottom-nav tabs.
 */
public class LightViewModel extends AndroidViewModel {

    private final BleRepository repo;

    public LightViewModel(@NonNull Application app) {
        super(app);
        this.repo = BleRepository.get(app);
    }

    // ── observable ────────────────────────────────────────────────────
    public LiveData<Boolean> connected() { return repo.connected(); }
    public LiveData<String> status() { return repo.status(); }
    public LiveData<String> stateJson() { return repo.stateJson(); }
    public LiveData<BleRepository.ProvResult> provResult() { return repo.provResult(); }
    public LiveData<String> writeLog() { return repo.writeLog(); }
    public boolean isBluetoothReady() { return repo.isBluetoothReady(); }

    // ── commands ──────────────────────────────────────────────────────
    public void scanAndConnect() { repo.scanAndConnect(); }
    public void disconnect() { repo.disconnect(); }

    /** Raw JSON to Control (0xFF31), same shape as the HTTP /set + /scene API. */
    public void write(String json) { repo.sendControl(json); }

    /** Convenience: an ARGB int -> {"color":[r,g,b]}. */
    public void writeColor(int color) {
        repo.sendControl("{\"color\":[" + Color.red(color) + ","
                + Color.green(color) + "," + Color.blue(color) + "]}");
    }

    public void writeBrightness(int value) {
        repo.sendControl("{\"brightness\":" + value + "}");
    }

    public void writePower(boolean on) {
        repo.sendControl("{\"power\":" + on + "}");
    }

    public void writeScene(String scene) {
        repo.sendControl("{\"scene\":\"" + scene + "\"}");
    }

    /** Onboard the device (the PIN is passed in by the setup screen, M1). */
    public void provision(String pin, String ssid, String psk) {
        repo.provision(pin, ssid, psk);
    }
}
