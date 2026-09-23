package com.vulnzoo.bulbbee_app.local;

import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Direct-LAN transport owner (BULB-R5), singleton like
 * {@link com.vulnzoo.bulbbee_app.ble.BleRepository} and
 * {@link com.vulnzoo.bulbbee_app.cloud.CloudRepository}. Wraps {@link LocalClient}
 * (AES-CCM {@code :6668}) on a background executor and exposes the connection and
 * the reply state as LiveData.
 *
 * VULNERABILITY (client side of BULB-P03 / BULB-P06): the local key is the static
 * firmware key baked into {@link LocalClient}, so being on the LAN is control.
 */
public class LocalRepository {

    private static final String TAG = "BulbBee";
    private static final int PORT = 6668;

    private static volatile LocalRepository instance;

    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private final LocalClient client = new LocalClient();   // static firmware key (BULB-P03)

    private final MutableLiveData<Boolean> connected = new MutableLiveData<>(false);
    private final MutableLiveData<String> status = new MutableLiveData<>("");
    private final MutableLiveData<String> stateJson = new MutableLiveData<>();

    private String host;

    private LocalRepository() { }

    public static LocalRepository get() {
        if (instance == null) {
            synchronized (LocalRepository.class) {
                if (instance == null) instance = new LocalRepository();
            }
        }
        return instance;
    }

    public LiveData<Boolean> connected() { return connected; }
    public LiveData<String> status() { return status; }
    public LiveData<String> stateJson() { return stateJson; }

    /** Point at the bulb's LAN address and update reachability. */
    public void connect(String host) {
        this.host = host;
        io.execute(() -> {
            boolean up = LocalClient.reachable(host, PORT, 800);
            main.post(() -> {
                connected.setValue(up);
                status.setValue(up ? "local: " + host : "local: unreachable");
            });
        });
    }

    /** Blocking reachability probe for the selector (call off the main thread). */
    public boolean isReachable() {
        return host != null && LocalClient.reachable(host, PORT, 800);
    }

    public void sendControl(String json) {
        if (host == null) return;
        io.execute(() -> {
            try {
                String reply = client.send(host, PORT, json);
                if (reply != null) main.post(() -> stateJson.setValue(reply));
            } catch (Exception e) {
                Log.w(TAG, "local control failed", e);
            }
        });
    }

    public void sendScene(String scene) {
        sendControl("{\"scene\":\"" + scene + "\"}");
    }
}
