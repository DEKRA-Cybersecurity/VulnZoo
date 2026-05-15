package com.vulnzoo.careotter_app;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.StrictMode;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

/**
 * AdminActivity — IGP v4 device administration panel.
 *
 * Connects via TCP to the CareOtter admin service on port 9999.
 * Exposes all IGP v4 commands plus intentional exploit helpers.
 *
 * Auth flow for protected commands (auth → cmd → deauth):
 *   Each protected action calls execProtected(), which:
 *     1. Sends IGP 0x02 AUTHENTICATE (authenticated=1 on device)
 *     2. Executes the selected command
 *     3. Sends IGP 0x0D DEAUTHENTICATE (authenticated=0 on device)
 *   The deauth runs in a finally block — it executes even if the command fails.
 *
 * VULNERABILITIES (inherited from careotter_admin):
 * 1. StrictMode.ThreadPolicy permits main-thread network I/O
 * 2. Hardcoded XOR-obfuscated admin token in IgpClient
 * 3. No input sanitisation on module/message fields
 * 4. Plaintext TCP — credentials and responses travel unencrypted
 * 5. Three separate TCP connections per protected operation — race window
 *    between them is exploitable by direct TCP attackers on :9999
 */
public class AdminActivity extends AppCompatActivity {

    private EditText  etIp;
    private EditText  etPort;
    private EditText  etModuleName;
    private TextView  tvOutput;
    private ScrollView scrollOutput;

    private Button tabInfo, tabConfig, tabDiag, tabCritical;
    private View panelInfo, panelConfig, panelDiag, panelCritical;
    private Button btnAuthenticate;

    // Tracks whether the last explicit AUTHENTICATE command succeeded.
    // Used only for the manual AUTH button display — protected commands
    // authenticate automatically via execProtected().
    private boolean isAuthenticated = false;

    // Prevents overlapping network operations (UX guard, not a security control).
    private volatile boolean isBusy = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        // VULNERABILITY: allow network operations on main thread
        StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder()
                .permitNetwork()
                .build());

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_admin);

        etIp         = findViewById(R.id.etIp);
        etPort       = findViewById(R.id.etPort);
        etModuleName = findViewById(R.id.etModuleName);
        tvOutput     = findViewById(R.id.tvAdminOutput);
        scrollOutput = findViewById(R.id.scrollAdminOutput);

        // Pre-fill device IP discovered via BLE advertising
        SharedPreferences prefs = getSharedPreferences("careotter_prefs", MODE_PRIVATE);
        String deviceIp = prefs.getString("device_ip", "192.168.2.1");
        etIp.setText(deviceIp);

        String username = prefs.getString("username", "admin");
        appendOutput("[SESSION] Logged in as: " + username + " (admin)");

        Button btnAdminLogout    = findViewById(R.id.btnAdminLogout);
        Button btnSysInfo        = findViewById(R.id.btnSysInfo);
        btnAuthenticate          = findViewById(R.id.btnAuthenticate);
        Button btnWifiConfig     = findViewById(R.id.btnWifiConfig);
        Button btnStatus         = findViewById(R.id.btnStatus);
        Button btnFormatString   = findViewById(R.id.btnFormatString);
        Button btnUnderflow      = findViewById(R.id.btnUnderflow);
        Button btnDefibrillate   = findViewById(R.id.btnDefibrillate);
        Button btnEmergencyAlert = findViewById(R.id.btnEmergencyAlert);
        Button btnCmdInjection   = findViewById(R.id.btnCmdInjection);
        Button btnCheckStatus    = findViewById(R.id.btnCheckStatus);
        Button btnSetTheme       = findViewById(R.id.btnSetTheme);
        Button btnGetThreshold   = findViewById(R.id.btnGetThreshold);
        Button btnSetThreshold   = findViewById(R.id.btnSetThreshold);
        EditText etBpmMin        = findViewById(R.id.etBpmMin);
        EditText etBpmMax        = findViewById(R.id.etBpmMax);
        EditText etSpo2Min       = findViewById(R.id.etSpo2Min);

        tabInfo     = findViewById(R.id.tabInfo);
        tabConfig   = findViewById(R.id.tabConfig);
        tabDiag     = findViewById(R.id.tabDiag);
        tabCritical = findViewById(R.id.tabCritical);

        panelInfo     = findViewById(R.id.panelInfo);
        panelConfig   = findViewById(R.id.panelConfig);
        panelDiag     = findViewById(R.id.panelDiag);
        panelCritical = findViewById(R.id.panelCritical);

        tabInfo.setOnClickListener(v -> showPanel(0));
        tabConfig.setOnClickListener(v -> showPanel(1));
        tabDiag.setOnClickListener(v -> showPanel(2));
        tabCritical.setOnClickListener(v -> showPanel(3));
        showPanel(0);

        btnAdminLogout.setOnClickListener(v -> logout());

        // ── Public commands (no auth required) ─────────────────────────────

        btnSysInfo.setOnClickListener(v ->
                runCommandAsync("SYS_INFO", () -> igp().sysInfo()));

        btnStatus.setOnClickListener(v -> {
            String module = etModuleName.getText().toString();
            if (module.isEmpty()) module = "CareOtter";
            final String mod = module;
            runCommandAsync("VERIFY_STATUS", () -> igp().verifyStatus(mod));
        });

        btnFormatString.setOnClickListener(v ->
                runCommandAsync("FMT_STRING", () -> igp().exploitFormatString()));

        // ── Toggle AUTH / DEAUTH button ─────────────────────────────────────
        // Toggles between IGP 0x02 AUTHENTICATE and 0x0D DEAUTHENTICATE.
        // Runs in its own background thread to avoid freezing the UI.
        btnAuthenticate.setOnClickListener(v -> {
            if (isBusy) {
                appendOutput("[BUSY] Operation already in progress");
                return;
            }
            isBusy = true;
            new Thread(() -> {
                try {
                    if (!isAuthenticated) {
                        String resp = igp().authenticate();
                        if (resp.contains("AUTH_SUCCESS")) {
                            appendOutput("[OK] Token: " + IgpClient.decodeToken() + "\nResponse: " + resp);
                            setAuthButtonState(true);
                        } else {
                            appendOutput("[ERR] Auth failed: " + resp);
                        }
                    } else {
                        String resp = igp().deauthenticate();
                        appendOutput("[OK] DEAUTH response: " + resp);
                        setAuthButtonState(false);
                    }
                } catch (Exception e) {
                    appendOutput("[ERR] " + e.getMessage());
                } finally {
                    isBusy = false;
                }
            }).start();
        });

        // ── Protected commands (auth → cmd → deauth) ────────────────────────

        btnWifiConfig.setOnClickListener(v ->
                runCommandAsync("GET_NETWORK", () -> execProtected(() -> igp().getNetwork())));

        btnUnderflow.setOnClickListener(v ->
                runCommandAsync("UNDERFLOW", () -> execProtected(() -> igp().exploitUnderflow())));

        btnDefibrillate.setOnClickListener(v ->
                runCommandAsync("DEFIBRILLATE", () -> execProtected(() -> igp().defibrillate())));

        btnEmergencyAlert.setOnClickListener(v -> {
            String msg = etModuleName.getText().toString();
            if (msg.isEmpty()) msg = "TEST_ALERT";
            final String m = msg;
            runCommandAsync("EMERGENCY_ALERT", () -> execProtected(() -> igp().sendEmergencyAlert(m)));
        });

        btnCmdInjection.setOnClickListener(v ->
                runCommandAsync("CMD_INJECT", () -> execProtected(() -> igp().exploitCommandInjection())));

        btnSetTheme.setOnClickListener(v ->
                runCommandAsync("SET_THEME", () -> execProtected(() -> igp().setTheme())));

        // ── 0x0E GET_THRESHOLD / 0x08 SET_THRESHOLD ─────────────────────────
        // Read current thresholds from the device and populate the UI fields.
        btnGetThreshold.setOnClickListener(v -> runCommandAsync("GET_THRESHOLD", () -> {
            String resp = igp().getThresholds();
            for (String line : resp.split("\n")) {
                String[] parts = line.split("=", 2);
                if (parts.length == 2) {
                    final String key = parts[0].trim();
                    final String value = parts[1].trim();
                    runOnUiThread(() -> {
                        if (key.equals("bpm_min"))  etBpmMin.setText(value);
                        else if (key.equals("bpm_max"))  etBpmMax.setText(value);
                        else if (key.equals("spo2_min")) etSpo2Min.setText(value);
                    });
                }
            }
            return resp;
        }));

        // Server (parse_thresholds in careservice.c) accepts the values without
        // any clinical-range validation: (0, 65535, 0) suppresses every alert.
        btnSetThreshold.setOnClickListener(v -> {
            int bpmMin, bpmMax, spo2Min;
            try {
                bpmMin  = Integer.parseInt(etBpmMin.getText().toString().trim());
                bpmMax  = Integer.parseInt(etBpmMax.getText().toString().trim());
                spo2Min = Integer.parseInt(etSpo2Min.getText().toString().trim());
            } catch (NumberFormatException nfe) {
                appendOutput("[ERR] thresholds must be integers");
                return;
            }
            runCommandAsync("SET_THRESHOLD",
                    () -> execProtected(() -> igp().setThreshold(bpmMin, bpmMax, spo2Min)));
        });

        // ── Full diagnostic chain ───────────────────────────────────────────
        btnCheckStatus.setOnClickListener(v -> runCommandAsync("FULL_DIAG", () -> {
            String info = igp().sysInfo();
            String net  = execProtected(() -> igp().getNetwork());
            return "SYS: " + info + "\nNET (via execProtected): " + net;
        }));
    }

    // ── IGP client factory ──────────────────────────────────────────────────

    private IgpClient igp() {
        String ip   = etIp.getText().toString().trim();
        int    port = 9999;
        try { port = Integer.parseInt(etPort.getText().toString().trim()); } catch (Exception ignored) {}
        return new IgpClient(ip.isEmpty() ? "192.168.2.1" : ip, port);
    }

    // ── Auth → cmd → deauth ─────────────────────────────────────────────────

    /**
     * Executes a protected IGP command ONLY if the user has manually
     * authenticated via the toggle button. This makes the manual auth/deauth
     * control meaningful while preserving the race-window vulnerability:
     *   1. protectedCmd.run()     → executes the selected command
     *   2. IGP 0x0D DEAUTHENTICATE → authenticated=0 on device (finally)
     *
     * The deauthenticate step runs even if the command throws an exception.
     * Each step opens a new TCP connection — the global auth state in careservice
     * makes the pattern work, but leaves a race window between connections.
     */
    private String execProtected(NetworkTask protectedCmd) throws Exception {
        if (!isAuthenticated) {
            throw new Exception("Not authenticated. Tap 'Authenticate' first.");
        }
        try {
            String result = protectedCmd.run();
            appendOutput("[DEAUTH] → sending 0x0D");
            return result;
        } finally {
            try {
                igp().deauthenticate();
                setAuthButtonState(false);
            } catch (Exception ignored) {
                // deauth is best-effort — do not mask the original command result
            }
        }
    }

    // ── UI helpers ──────────────────────────────────────────────────────────

    /** Run a network command on the main thread (StrictMode override — intentional vuln). */
    private void runCommand(NetworkTask task) {
        try {
            String result = task.run();
            appendOutput("[OK] " + result);
        } catch (Exception e) {
            appendOutput("[ERR] " + e.getMessage());
        }
    }

    /** Run a network command on a background thread and post results to the UI. */
    private void runCommandAsync(String label, NetworkTask task) {
        if (isBusy) {
            appendOutput("[BUSY] Operation already in progress");
            return;
        }
        isBusy = true;
        appendOutput("[NET] " + label + " → " + etIp.getText().toString().trim() + ":" + etPort.getText().toString().trim());
        new Thread(() -> {
            try {
                String result = task.run();
                appendOutput("[OK] " + result);
            } catch (Exception e) {
                appendOutput("[ERR] " + e.getMessage());
            } finally {
                isBusy = false;
            }
        }).start();
    }

    private void appendOutput(String msg) {
        runOnUiThread(() -> {
            String cur = tvOutput.getText().toString();
            tvOutput.setText(cur.isEmpty() ? msg : cur + "\n" + msg);
            scrollOutput.post(() -> scrollOutput.fullScroll(View.FOCUS_DOWN));
        });
    }

    private void logout() {
        getSharedPreferences("careotter_prefs", MODE_PRIVATE)
                .edit().remove("jwt_token").remove("user_role").remove("username").apply();
        startActivity(new Intent(this, LoginActivity.class));
        finish();
    }

    private void showPanel(int index) {
        panelInfo.setVisibility(index == 0 ? View.VISIBLE : View.GONE);
        panelConfig.setVisibility(index == 1 ? View.VISIBLE : View.GONE);
        panelDiag.setVisibility(index == 2 ? View.VISIBLE : View.GONE);
        panelCritical.setVisibility(index == 3 ? View.VISIBLE : View.GONE);

        resetTab(tabInfo);
        resetTab(tabConfig);
        resetTab(tabDiag);
        resetTab(tabCritical);

        Button active = index == 0 ? tabInfo : index == 1 ? tabConfig : index == 2 ? tabDiag : tabCritical;
        active.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFF2563EB));
        active.setTextColor(0xFFFFFFFF);
    }

    private void resetTab(Button btn) {
        btn.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFFFFFFFF));
        btn.setTextColor(0xFF64748B);
    }

    /** Updates the Authenticate/Deauthenticate toggle button UI (thread-safe). */
    private void setAuthButtonState(boolean authenticated) {
        isAuthenticated = authenticated;
        runOnUiThread(() -> {
            if (authenticated) {
                btnAuthenticate.setText("Deauthenticate");
                btnAuthenticate.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFFDC2626));
            } else {
                btnAuthenticate.setText("Authenticate");
                btnAuthenticate.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFF16A34A));
            }
        });
    }

    @FunctionalInterface
    interface NetworkTask {
        String run() throws Exception;
    }
}
