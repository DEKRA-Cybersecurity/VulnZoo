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
 * VULNERABILITIES (inherited from careotter_admin):
 * 1. StrictMode.ThreadPolicy permits main-thread network I/O
 * 2. Hardcoded XOR-obfuscated admin token in IgpClient
 * 3. No input sanitisation on module/message fields
 * 4. Plaintext TCP — credentials and responses travel unencrypted
 */
public class AdminActivity extends AppCompatActivity {

    private EditText  etIp;
    private EditText  etPort;
    private EditText  etModuleName;
    private TextView  tvOutput;
    private ScrollView scrollOutput;

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

        btnAdminLogout.setOnClickListener(v -> logout());

        btnSysInfo.setOnClickListener(v -> runCommand(() ->
                igp().sysInfo()));

        btnAuthenticate.setOnClickListener(v -> runCommand(() -> {
            String resp = igp().authenticate();
            if (resp.contains("AUTH_SUCCESS")) isAuthenticated = true;
            return "Token: " + IgpClient.decodeToken() + "\nResponse: " + resp;
        }));

        btnWifiConfig.setOnClickListener(v -> {
            if (!checkAuth()) return;
            runCommand(() -> igp().getNetwork());
        });

        btnStatus.setOnClickListener(v -> {
            String module = etModuleName.getText().toString();
            if (module.isEmpty()) module = "CareOtter";
            final String mod = module;
            runCommand(() -> igp().verifyStatus(mod));
        });

        btnFormatString.setOnClickListener(v ->
                runCommand(() -> igp().exploitFormatString()));

        btnUnderflow.setOnClickListener(v ->
                runCommand(() -> igp().exploitUnderflow()));

        btnDefibrillate.setOnClickListener(v -> {
            if (!checkAuth()) return;
            runCommand(() -> igp().defibrillate());
        });

        btnEmergencyAlert.setOnClickListener(v -> {
            if (!checkAuth()) return;
            String msg = etModuleName.getText().toString();
            if (msg.isEmpty()) msg = "TEST_ALERT";
            final String m = msg;
            runCommand(() -> igp().sendEmergencyAlert(m));
        });

        btnCmdInjection.setOnClickListener(v -> {
            if (!checkAuth()) return;
            runCommand(() -> igp().exploitCommandInjection());
        });

        btnCheckStatus.setOnClickListener(v -> runCommand(() -> {
            String info = igp().sysInfo();
            String auth = igp().authenticate();
            if (auth.contains("AUTH_SUCCESS")) isAuthenticated = true;
            String net  = igp().getNetwork();
            return "SYS: " + info + "\nAUTH: " + auth + "\nNET: " + net;
        }));

        btnSetTheme.setOnClickListener(v -> {
            if (!checkAuth()) return;
            runCommand(() -> igp().setTheme());
        });
    }

    private IgpClient igp() {
        String ip   = etIp.getText().toString().trim();
        int    port = 9999;
        try { port = Integer.parseInt(etPort.getText().toString().trim()); } catch (Exception ignored) {}
        return new IgpClient(ip.isEmpty() ? "192.168.2.1" : ip, port);
    }

    private boolean checkAuth() {
        if (!isAuthenticated) {
            appendOutput("[ERROR] Not authenticated — tap AUTHENTICATE first");
            return false;
        }
        return true;
    }

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

    @FunctionalInterface
    interface NetworkTask {
        String run() throws Exception;
    }
}
