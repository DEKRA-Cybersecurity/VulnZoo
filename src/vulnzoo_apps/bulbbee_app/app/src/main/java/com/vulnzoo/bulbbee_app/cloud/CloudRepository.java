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
    private String base;          // BULB-U1: persisted session, for resume + re-probe
    private String user;

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
            // M9: store the bearer token + session (base/user) in the clear and log it.
            // BULB-U1: the persisted session is what auto-resumes on the next launch.
            prefs.edit()
                    .putString("cloud_jwt", r.token)
                    .putString("cloud_base", base)
                    .putString("cloud_user", user)
                    .apply();
            Log.d(TAG, "cloud login user=" + user + " jwt=" + r.token);
            this.base = base;
            this.user = user;
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
            rememberDevice(user, bulb);   // BULB-U1: per-user device profile
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

    /** BULB-U1: auto-resume a stored session without a fresh login (M9: reads the
     *  plaintext jwt + base + user). Returns true if a session was restored. Call
     *  on the main thread. */
    public boolean resumeSession() {
        String jwt = prefs.getString("cloud_jwt", null);
        String b = prefs.getString("cloud_base", null);
        String u = prefs.getString("cloud_user", null);
        if (jwt == null || b == null) return false;
        this.base = b;
        this.user = u;
        CloudClient c = new CloudClient(b);
        c.setToken(jwt);
        this.client = c;
        connected.setValue(true);
        status.setValue("cloud: " + (u != null ? u : ""));
        io.execute(() -> {
            String bulb = null;
            try { bulb = c.firstBulbId(); } catch (Exception ignored) { }
            this.bulbId = bulb;
            rememberDevice(u, bulb);
        });
        return true;
    }

    /** BULB-U1: end the session until the next sign-in. Clears the persisted bearer
     *  and session (the per-user device list is kept as a profile). */
    public void signOut() {
        prefs.edit().remove("cloud_jwt").remove("cloud_base").remove("cloud_user").apply();
        client = null;
        bulbId = null;
        base = null;
        user = null;
        connected.postValue(false);
        status.postValue("signed out");
    }

    public String currentUser() { return user; }
    public String bulbId() { return bulbId; }

    /** "Forget device": drop the app's memory of the provisioned device (the real
     *  serial + the per-user list), so the control screen no longer targets it.
     *  Client-side only, the cloud binding is unchanged. */
    public void forgetDevice() {
        SharedPreferences.Editor e = prefs.edit().remove("cloud_device_id");
        if (user != null) e.remove("devices_" + user);
        e.apply();
        bulbId = null;
    }

    /** BULB-U2: resolve the account's bound bulb synchronously (call off the main
     *  thread). Prefers the real device serial captured over BLE (`cloud_device_id`)
     *  so control targets the provisioned device, not the first (possibly seeded)
     *  bulb the account owns, mirroring {@link #signIn}. Falls back to the first
     *  bulb. Returns null when the account has none. */
    public String resolveBulbBlocking() {
        CloudClient c = client;
        if (c == null) return bulbId;
        try {
            String serial = prefs.getString("cloud_device_id", null);
            String b = (serial != null && !serial.isEmpty())
                    ? c.register(serial)            // the provisioned device
                    : preferOnline(c.myBulbs());    // else an online bulb, not an offline seed
            this.bulbId = b;
            rememberDevice(user, b);
            return b;
        } catch (Exception e) {
            return bulbId;
        }
    }

    /** Pick an online bulb from the mybulbs object, else the first, else null, so a
     *  seeded but offline bulb the account owns does not shadow a live one. */
    private static String preferOnline(String myBulbsJson) {
        try {
            org.json.JSONObject o = new org.json.JSONObject(myBulbsJson);
            String first = null;
            for (java.util.Iterator<String> it = o.keys(); it.hasNext(); ) {
                String id = it.next();
                if (first == null) first = id;
                if (o.getJSONObject(id).optBoolean("online", false)) return id;
            }
            return first;
        } catch (Exception e) {
            return null;
        }
    }

    /** BULB-U3: is the bound bulb reporting live device state (online) over the cloud?
     *  The REST API always answers, so this reads the last_seen-derived online flag.
     *  Call off the main thread. */
    public boolean bulbOnlineBlocking(String bulb) {
        CloudClient c = client;
        if (c == null || bulb == null) return false;
        try {
            String s = c.getState(bulb);
            return new org.json.JSONObject(s).optBoolean("online", false);
        } catch (Exception e) {
            return false;
        }
    }

    /** BULB-U1: remember which bulbs this user configures (per-user device profile,
     *  plaintext prefs). */
    private void rememberDevice(String user, String bulb) {
        if (user == null || bulb == null || bulb.isEmpty()) return;
        String key = "devices_" + user;
        java.util.Set<String> set = new java.util.HashSet<>(
                prefs.getStringSet(key, java.util.Collections.emptySet()));
        if (set.add(bulb)) prefs.edit().putStringSet(key, set).apply();
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
