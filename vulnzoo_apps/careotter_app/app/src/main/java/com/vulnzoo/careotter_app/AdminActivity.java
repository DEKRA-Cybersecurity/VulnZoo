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

    // Tracks whether the last explicit AUTHENTICATE command succeeded.
    // Used only for the manual AUTH button display — protected commands
    // authenticate automatically via execProtected().
    private boolean isAuthenticated = false;

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
        Button btnAuthenticate   = findViewById(R.id.btnAuthenticate);
        Button btnWifiConfig     = findViewById(R.id.btnWifiConfig);
        Button btnStatus         = findViewById(R.id.btnStatus);
        Button btnFormatString   = findViewById(R.id.btnFormatString);
        Button btnUnderflow      = findViewById(R.id.btnUnderflow);
        Button btnDefibrillate   = findViewById(R.id.btnDefibrillate);
        Button btnEmergencyAlert = findViewById(R.id.btnEmergencyAlert);
        Button btnCmdInjection   = findViewById(R.id.btnCmdInjection);
        Button btnCheckStatus    = findViewById(R.id.btnCheckStatus);
        Button btnSetTheme       = findViewById(R.id.btnSetTheme);

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
                runCommand(() -> igp().sysInfo()));

        btnStatus.setOnClickListener(v -> {
            String module = etModuleName.getText().toString();
            if (module.isEmpty()) module = "CareOtter";
            final String mod = module;
            runCommand(() -> igp().verifyStatus(mod));
        });

        btnFormatString.setOnClickListener(v ->
                runCommand(() -> igp().exploitFormatString()));

        // ── Manual AUTH button — demo / pentest only ────────────────────────
        // Shows the decoded hardcoded token and records auth state.
        // Protected commands use execProtected() automatically — this button
        // is only needed to demonstrate the hardcoded-credential vulnerability.
        btnAuthenticate.setOnClickListener(v -> runCommand(() -> {
            String resp = igp().authenticate();
            if (resp.contains("AUTH_SUCCESS")) isAuthenticated = true;
            return "Token: " + IgpClient.decodeToken() + "\nResponse: " + resp;
        }));

        // ── Protected commands (auth → cmd → deauth) ────────────────────────

        btnWifiConfig.setOnClickListener(v ->
                runCommand(() -> execProtected(() -> igp().getNetwork())));

        btnUnderflow.setOnClickListener(v ->
                runCommand(() -> execProtected(() -> igp().exploitUnderflow())));

        btnDefibrillate.setOnClickListener(v ->
                runCommand(() -> execProtected(() -> igp().defibrillate())));

        btnEmergencyAlert.setOnClickListener(v -> {
            String msg = etModuleName.getText().toString();
            if (msg.isEmpty()) msg = "TEST_ALERT";
            final String m = msg;
            runCommand(() -> execProtected(() -> igp().sendEmergencyAlert(m)));
        });

        btnCmdInjection.setOnClickListener(v ->
                runCommand(() -> execProtected(() -> igp().exploitCommandInjection())));

        btnSetTheme.setOnClickListener(v ->
                runCommand(() -> execProtected(() -> igp().setTheme())));

        // ── Full diagnostic chain ───────────────────────────────────────────
        // Demonstrates the complete IGP flow: public info, then a protected
        // operation with automatic auth/deauth around GET_NETWORK.
        btnCheckStatus.setOnClickListener(v -> runCommand(() -> {
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
     * Executes a protected IGP command following the auth → cmd → deauth cycle:
     *   1. IGP 0x02 AUTHENTICATE  → authenticated=1 on device
     *   2. protectedCmd.run()     → executes the selected command
     *   3. IGP 0x0D DEAUTHENTICATE → authenticated=0 on device (finally)
     *
     * The deauthenticate step runs even if the command throws an exception.
     * Each step opens a new TCP connection — the global auth state in careservice
     * makes the pattern work, but leaves a race window between connections.
     */
    private String execProtected(NetworkTask protectedCmd) throws Exception {
        IgpClient client = igp();
        String authResp = client.authenticate();
        if (!authResp.contains("AUTH_SUCCESS")) {
            throw new Exception("IGP auth failed: " + authResp);
        }
        appendOutput("[AUTH] → AUTH_SUCCESS");
        try {
            String result = protectedCmd.run();
            appendOutput("[DEAUTH] → sending 0x0D");
            return result;
        } finally {
            try {
                igp().deauthenticate();
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

    private void appendOutput(String msg) {
        String cur = tvOutput.getText().toString();
        tvOutput.setText(cur.isEmpty() ? msg : cur + "\n" + msg);
        scrollOutput.post(() -> scrollOutput.fullScroll(View.FOCUS_DOWN));
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

    @FunctionalInterface
    interface NetworkTask {
        String run() throws Exception;
    }
}
