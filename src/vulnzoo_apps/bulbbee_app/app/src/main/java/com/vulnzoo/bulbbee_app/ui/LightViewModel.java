package com.vulnzoo.bulbbee_app.ui;

import android.app.Application;
import android.graphics.Color;
import android.os.Handler;
import android.os.Looper;

import androidx.annotation.NonNull;
import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MediatorLiveData;

import com.vulnzoo.bulbbee_app.ble.BleRepository;
import com.vulnzoo.bulbbee_app.cloud.CloudRepository;
import com.vulnzoo.bulbbee_app.local.LocalClient;
import com.vulnzoo.bulbbee_app.local.LocalRepository;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Shared, activity-scoped view model over the three transports: {@link BleRepository}
 * (local BLE), {@link LocalRepository} (direct LAN, BULB-R5) and {@link CloudRepository}
 * (remote, BULB-R4). The control calls route to the active {@link TransportSelector.Transport},
 * so the UI stays transport-agnostic.
 *
 * {@link #autoSelect} implements the failover policy (LAN -> Cloud -> BLE): it
 * probes reachability and switches, gating the local probe and BLE scan when it
 * goes remote. BLE is the default before a selection.
 */
public class LightViewModel extends AndroidViewModel {

    private static final int LAN_PORT = 6668;

    private final BleRepository repo;
    private final CloudRepository cloud;
    private final LocalRepository local;

    private final ExecutorService bg = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());

    private volatile TransportSelector.Transport transport = TransportSelector.Transport.BLE;
    private volatile boolean scansGated = false;

    /** Merged live state from whichever transport is active (BLE / cloud / local),
     *  so the UI reflects the bulb over any leg, not just BLE. */
    private final MediatorLiveData<String> stateJson = new MediatorLiveData<>();

    public LightViewModel(@NonNull Application app) {
        super(app);
        this.repo = BleRepository.get(app);
        this.cloud = CloudRepository.get(app);
        this.local = LocalRepository.get();
        stateJson.addSource(repo.stateJson(), stateJson::setValue);
        stateJson.addSource(cloud.stateJson(), stateJson::setValue);
        stateJson.addSource(local.stateJson(), stateJson::setValue);
    }

    // ── observable ────────────────────────────────────────────────────
    public LiveData<Boolean> connected() { return repo.connected(); }
    public LiveData<String> status() { return repo.status(); }
    public LiveData<String> stateJson() { return stateJson; }
    public LiveData<BleRepository.ProvResult> provResult() { return repo.provResult(); }
    public LiveData<String> writeLog() { return repo.writeLog(); }
    public LiveData<String> deviceId() { return repo.deviceId(); }
    public boolean isBluetoothReady() { return repo.isBluetoothReady(); }

    public LiveData<Boolean> cloudConnected() { return cloud.connected(); }
    public LiveData<String> cloudStatus() { return cloud.status(); }
    public LiveData<String> cloudStateJson() { return cloud.stateJson(); }
    public LiveData<Boolean> localConnected() { return local.connected(); }
    public LiveData<String> localStateJson() { return local.stateJson(); }

    public TransportSelector.Transport transport() { return transport; }
    public boolean scansGated() { return scansGated; }

    // ── transport selection (BULB-R5) ─────────────────────────────────

    /** Log in to the cloud (plain http base) and mark the remote leg usable. */
    public void cloudConnect(String base, String bulbId, String user) {
        cloud.connect(base, bulbId, user);
        transport = TransportSelector.Transport.CLOUD;
    }

    /** BULB-R6: sign in with user + password without BLE, resolve the account's
     *  bulb, and control it over the cloud. */
    public void cloudSignIn(String base, String user, String password) {
        cloud.signIn(base, user, password);
        transport = TransportSelector.Transport.CLOUD;
    }

    /** BULB-R6: fetch a claim token to bind a bulb to the signed-in account. */
    public void fetchClaim(java.util.function.Consumer<String> cb) {
        cloud.fetchClaim(cb);
    }

    /** Point the direct-LAN leg at the bulb and use it. */
    public void localConnect(String host) {
        local.connect(host);
        transport = TransportSelector.Transport.LOCAL;
    }

    public void useBle() { transport = TransportSelector.Transport.BLE; }

    /**
     * Failover: prefer the direct LAN plane (lowest latency), then the cloud,
     * then BLE. Probes reachability off the main thread, then switches. When the
     * choice is remote, the local probe and the BLE scan are gated off.
     */
    public void autoSelect(String localHost) {
        bg.execute(() -> {
            boolean localUp = localHost != null && LocalClient.reachable(localHost, LAN_PORT, 800);
            boolean cloudUp = Boolean.TRUE.equals(cloud.connected().getValue());
            boolean bleUp = Boolean.TRUE.equals(repo.connected().getValue());
            TransportSelector.Transport t = TransportSelector.choose(localUp, cloudUp, bleUp);
            main.post(() -> {
                transport = t;
                scansGated = !TransportSelector.scansEnabled(t);
                if (t == TransportSelector.Transport.LOCAL) local.connect(localHost);
            });
        });
    }

    // ── commands (routed to the active transport) ─────────────────────
    public void scanAndConnect() {
        if (scansGated) return;          // BULB-R5: no BLE scan while remote
        transport = TransportSelector.Transport.BLE;   // pairing over BLE selects the BLE leg
        repo.scanAndConnect();
    }

    public void disconnect() { repo.disconnect(); }

    /** Raw JSON command, same shape as the HTTP /set + /scene API, to the active transport. */
    public void write(String json) {
        switch (transport) {
            case LOCAL: local.sendControl(json); break;
            case CLOUD: cloud.sendControl(json); break;
            default: repo.sendControl(json);
        }
    }

    public void writeColor(int color) {
        write("{\"color\":[" + Color.red(color) + ","
                + Color.green(color) + "," + Color.blue(color) + "]}");
    }

    public void writeBrightness(int value) { write("{\"brightness\":" + value + "}"); }

    public void writePower(boolean on) { write("{\"power\":" + on + "}"); }

    public void writeScene(String scene) {
        switch (transport) {
            case LOCAL: local.sendScene(scene); break;
            case CLOUD: cloud.sendScene(scene); break;
            default: repo.sendControl("{\"scene\":\"" + scene + "\"}");
        }
    }

    /** Onboard the device (the PIN is passed in by the setup screen, M1). The cloud
     *  host is written into the bulb's config; claimToken binds it to the account. */
    public void provision(String pin, String ssid, String psk, String cloudHost, String claimToken) {
        repo.provision(pin, ssid, psk, cloudHost, claimToken);
    }
}
