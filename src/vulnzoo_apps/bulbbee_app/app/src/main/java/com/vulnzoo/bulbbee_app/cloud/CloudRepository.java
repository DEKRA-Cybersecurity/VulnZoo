package com.vulnzoo.bulbbee_app.cloud;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Remote transport (BULB-R4): drives the bulb through the BulbBee cloud API
 * instead of BLE, over the same control JSON the BLE path uses. Singleton like
 * {@link com.vulnzoo.bulbbee_app.ble.BleRepository}, exposing the connection and
 * the live state (BULB-R3) as LiveData.
 *
 * VULNERABILITY M9 / CWE-312 + insecure transport (client side of BULB-CLD): the
 * cloud base URL is plain HTTP (no TLS), and the bearer JWT is stored in plaintext
 * SharedPreferences and logged to Logcat, the same "bulbbee" prefs the setup
 * screen already leaks into.
 */
public class CloudRepository {

    private static final String TAG = "BulbBee";
    private static final String PREFS = "bulbbee";

    private static volatile CloudRepository instance;

    private final SharedPreferences prefs;
    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());

    private final MutableLiveData<Boolean> connected = new MutableLiveData<>(false);
    private final MutableLiveData<String> status = new MutableLiveData<>("");
    private final MutableLiveData<String> stateJson = new MutableLiveData<>();

    private CloudClient client;   // set on connect / resume
    private String bulbId;

    private CloudRepository(Context ctx) {
        this.prefs = ctx.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public static CloudRepository get(Context ctx) {
        if (instance == null) {
            synchronized (CloudRepository.class) {
                if (instance == null) instance = new CloudRepository(ctx);
            }
        }
        return instance;
    }

    // ── observable state (mirrors BleRepository) ──────────────────────

    public LiveData<Boolean> connected() { return connected; }
    public LiveData<String> status() { return status; }
    public LiveData<String> stateJson() { return stateJson; }

    // ── session ───────────────────────────────────────────────────────

    /**
     * Log in to the cloud and bind this session to a bulb. {@code base} is a
     * plain {@code http://host:5004} URL (no TLS, intentionally).
     */
    public void connect(String base, String bulbId, String user) {
        this.bulbId = bulbId;
        io.execute(() -> {
            try {
                CloudClient c = new CloudClient(base);
                String jwt = c.login(user);
                // M9: store the bearer token in the clear and log it.
                prefs.edit().putString("cloud_jwt", jwt).apply();
                Log.d(TAG, "cloud login user=" + user + " jwt=" + jwt);
                this.client = c;
                main.post(() -> {
                    connected.setValue(true);
                    status.setValue("cloud: " + user);
                });
                refresh();
            } catch (Exception e) {
                main.post(() -> {
                    connected.setValue(false);
                    status.setValue("cloud login failed");
                });
            }
        });
    }

    /**
     * BULB-R6: sign in with user + password (default ignores the password), resolve
     * the account's bulb from {@code /api/mybulbs}, and mark the session usable, so
     * the app controls the bulb over the cloud without Bluetooth.
     */
    public void signIn(String base, String user, String password) {
        io.execute(() -> {
            CloudClient c = new CloudClient(base);
            CloudClient.LoginResult r;
            try {
                r = c.loginResult(user, password);
            } catch (Exception e) {
                Log.w(TAG, "cloud login unreachable", e);      // real cause in logcat
                fail("Cannot reach the cloud server");        // network / bad URL / cleartext
                return;
            }
            if (!r.ok()) {
                fail(loginError(r));                          // distinct message per API response
                return;
            }
            // M9: store the bearer token in the clear and log it.
            prefs.edit().putString("cloud_jwt", r.token).apply();
            Log.d(TAG, "cloud login user=" + user + " jwt=" + r.token);
            String bulb = null;
            try {
                // BULB-R6: if a device serial was captured over BLE during onboarding,
                // register it to this account and control THAT bulb (not the first seeded one).
                String serial = prefs.getString("cloud_device_id", null);
                bulb = (serial != null && !serial.isEmpty()) ? c.register(serial) : c.firstBulbId();
            } catch (Exception ignored) {
            }
            this.client = c;
            this.bulbId = bulb;
            final String b = bulb;
            main.post(() -> {
                connected.setValue(true);
                status.setValue(b != null ? "cloud: " + user + " (" + b + ")"
                                          : "cloud: " + user + " (no bulb yet)");
            });
            if (bulb != null) refresh();
        });
    }

    /** Map the API login response to a user-facing message. */
    private static String loginError(CloudClient.LoginResult r) {
        if ("unknown user".equals(r.error) || r.status == 404) {
            return "Unknown user";
        }
        if ("bad credentials".equals(r.error) || r.status == 401) {
            return "Wrong password";
        }
        return r.error != null ? r.error : "Login failed (" + r.status + ")";
    }

    /** BULB-R6: fetch a single-use claim token for onboarding (bind a bulb to the
     *  signed-in account). Delivers null on the main thread if not signed in. */
    public void fetchClaim(java.util.function.Consumer<String> cb) {
        CloudClient c = client;
        if (c == null) { main.post(() -> cb.accept(null)); return; }
        io.execute(() -> {
            String claim = null;
            try { claim = c.claim(); } catch (Exception ignored) { }
            final String f = claim;
            main.post(() -> cb.accept(f));
        });
    }

    private void fail(String msg) {
        main.post(() -> { connected.setValue(false); status.setValue(msg); });
    }

    /** Reuse a stored JWT without a fresh login (M9: reads the plaintext token). */
    public void resume(String base, String bulbId) {
        this.bulbId = bulbId;
        String jwt = prefs.getString("cloud_jwt", null);
        if (jwt == null) return;
        CloudClient c = new CloudClient(base);
        c.setToken(jwt);
        this.client = c;
        connected.setValue(true);
        refresh();
    }

    public void disconnect() {
        client = null;
        connected.postValue(false);
    }

    // ── commands (same control JSON as the BLE path) ──────────────────

    public void sendControl(String json) {
        CloudClient c = client;
        if (c == null || bulbId == null) return;
        io.execute(() -> {
            try { c.control(bulbId, json); refresh(); }
            catch (Exception e) { Log.w(TAG, "cloud control failed", e); }
        });
    }

    public void sendScene(String scene) {
        CloudClient c = client;
        if (c == null || bulbId == null) return;
        io.execute(() -> {
            try { c.scene(bulbId, scene); refresh(); }
            catch (Exception e) { Log.w(TAG, "cloud scene failed", e); }
        });
    }

    /** Pull the live state (BULB-R3) and publish it like the BLE stateJson. */
    public void refresh() {
        CloudClient c = client;
        if (c == null || bulbId == null) return;
        io.execute(() -> {
            try {
                String s = c.getState(bulbId);
                main.post(() -> stateJson.setValue(s));
            } catch (Exception ignored) { }
        });
    }
}
