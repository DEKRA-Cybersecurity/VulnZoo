package com.vulnzoo.bulbbee_app.ui;

import android.app.Application;
import android.graphics.Color;
import android.os.Handler;
import android.os.Looper;

import androidx.annotation.NonNull;
import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MediatorLiveData;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.Observer;

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
    private volatile boolean bleActive = false;   // BLE is the active, connected transport

    /** Merged live state from whichever transport is active (BLE / cloud / local),
     *  so the UI reflects the bulb over any leg, not just BLE. */
    private final MediatorLiveData<String> stateJson = new MediatorLiveData<>();

    /** BULB-U2/U3/U4: the control screen's state, computed by {@link #enterControl}. */
    public enum ControlState { CONNECTING, CONNECTED, OFFLINE, UNLINKED }
    private final MutableLiveData<ControlState> controlState =
            new MutableLiveData<>(ControlState.CONNECTING);

    /** Watches the BLE link: if it was the active transport and drops, fail over to
     *  the cloud instead of appearing connected but dead (no re-login needed). */
    private final Observer<Boolean> bleWatch = c -> {
        if (Boolean.FALSE.equals(c) && bleActive) {
            bleActive = false;
            failoverToCloud();
        }
    };

    public LightViewModel(@NonNull Application app) {
        super(app);
        this.repo = BleRepository.get(app);
        this.cloud = CloudRepository.get(app);
        this.local = LocalRepository.get();
        stateJson.addSource(repo.stateJson(), stateJson::setValue);
        stateJson.addSource(cloud.stateJson(), stateJson::setValue);
        stateJson.addSource(local.stateJson(), stateJson::setValue);
        repo.connected().observeForever(bleWatch);
    }

    @Override
    protected void onCleared() {
        repo.connected().removeObserver(bleWatch);
        super.onCleared();
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

    public LiveData<ControlState> controlState() { return controlState; }
    public String cloudUser() { return cloud.currentUser(); }

    // ── session lifecycle (BULB-U1) ───────────────────────────────────

    /** BULB-U1: auto-resume a stored cloud session (skips login when a token exists). */
    public boolean resumeSession() { return cloud.resumeSession(); }

    /** BULB-U1: end the session, drop BLE, and let the login gate take over. */
    public void signOut() {
        bleActive = false;              // an intentional drop, do not fail over
        cloud.signOut();
        repo.disconnect();
        transport = TransportSelector.Transport.BLE;
        controlState.postValue(ControlState.UNLINKED);
    }

    /** "Forget device": drop the app's memory of the provisioned device (client-side)
     *  and BLE, and show the unlinked state so the user can re-link. The session stays. */
    public void forgetDevice() {
        bleActive = false;              // an intentional drop, do not fail over
        cloud.forgetDevice();
        repo.disconnect();
        transport = TransportSelector.Transport.BLE;
        controlState.postValue(ControlState.UNLINKED);
    }

    // ── automatic transport for the control screen (BULB-U2/U3/U4) ────

    /**
     * Decide the control screen's channel and state (Decision U-1: BLE proximity
     * then Cloud). Resolves the account's bound bulb: none -> UNLINKED. Else, when
     * BLE is ready, scan/connect for ~6 s -> BLE CONNECTED. Otherwise read the
     * bulb's cloud liveness (BULB-U3) -> CLOUD CONNECTED, or OFFLINE. Runs off the
     * main thread. The LAN {@code :6668} plane stays a built capability, out of
     * this automatic decision (Decision U-1).
     */
    public void enterControl(boolean bleReady) {
        controlState.postValue(ControlState.CONNECTING);
        bg.execute(() -> {
            String bulb = cloud.resolveBulbBlocking();
            if (bulb == null) { bleActive = false; controlState.postValue(ControlState.UNLINKED); return; }
            if (bleReady) {
                main.post(() -> { transport = TransportSelector.Transport.BLE; repo.scanAndConnect(); });
                for (int i = 0; i < 20; i++) {                 // ~6 s BLE probe window
                    if (Boolean.TRUE.equals(repo.connected().getValue())) {
                        transport = TransportSelector.Transport.BLE;
                        bleActive = true;                       // BLE is now the active leg
                        controlState.postValue(ControlState.CONNECTED);
                        return;
                    }
                    try { Thread.sleep(300); } catch (InterruptedException ignored) { return; }
                }
            }
            bleActive = false;
            boolean online = cloud.bulbOnlineBlocking(bulb);   // BULB-U3 device liveness
            transport = TransportSelector.Transport.CLOUD;
            controlState.postValue(online ? ControlState.CONNECTED : ControlState.OFFLINE);
        });
    }

    /** BLE-drop failover (BULB-U2): BLE was the active transport and dropped, so try
     *  the cloud for the same account bulb, keeping the app usable without a re-login. */
    private void failoverToCloud() {
        controlState.postValue(ControlState.CONNECTING);
        bg.execute(() -> {
            String bulb = cloud.resolveBulbBlocking();
            if (bulb == null) { controlState.postValue(ControlState.UNLINKED); return; }
            boolean online = cloud.bulbOnlineBlocking(bulb);
            transport = TransportSelector.Transport.CLOUD;
            controlState.postValue(online ? ControlState.CONNECTED : ControlState.OFFLINE);
        });
    }

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
