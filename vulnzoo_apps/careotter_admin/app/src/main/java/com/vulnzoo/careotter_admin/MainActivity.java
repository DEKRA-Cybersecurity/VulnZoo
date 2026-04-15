package com.vulnzoo.careotter_admin;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

/**
 * MainActivity — CareOtter Admin App (IGP v4, TCP :9999 only)
 *
 * No BLE code. Connects exclusively via TCP to careservice on port 9999.
 * Uses StrictMode.permitNetwork workaround for network on main thread (intentional vuln).
 */
public class MainActivity extends AppCompatActivity {

    private CareOtterClient client;
    private EditText  etIpAddress;
    private EditText  etModuleName;
    private TextView  tvAuthStatus;
    private TextView  tvOutput;
    private ScrollView scrollOutput;

    private final Handler uiHandler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        etIpAddress  = findViewById(R.id.etIpAddress);
        etModuleName = findViewById(R.id.etModuleName);
        tvAuthStatus = findViewById(R.id.tvAuthStatus);
        tvOutput     = findViewById(R.id.tvOutput);
        scrollOutput = findViewById(R.id.scrollOutput);

        // ── Connect ───────────────────────────────────────────────
        findViewById(R.id.btnConnect).setOnClickListener(v -> {
            client = null;
            runIgp(() -> appendOutput("SYS_INFO: " + getClient().getSystemInfo()));
        });

        // ── Full flow ─────────────────────────────────────────────
        findViewById(R.id.btnCheckStatus).setOnClickListener(v -> runIgp(() -> {
            CareOtterClient c = getClient();
            appendOutput("SYS_INFO: " + c.getSystemInfo());
            String auth = c.authenticate();
            appendOutput("AUTH: " + auth);
            if (auth.contains("AUTH_SUCCESS")) {
                uiHandler.post(() -> tvAuthStatus.setText("Estado: Autenticado ✓"));
                appendOutput("WIFI_CONFIG:\n" + c.getWifiConfig());
            }
        }));

        // ── Individual commands ───────────────────────────────────
        findViewById(R.id.btnSysInfo).setOnClickListener(v ->
                runIgp(() -> appendOutput("SYS_INFO: " + getClient().getSystemInfo())));

        findViewById(R.id.btnAuthenticate).setOnClickListener(v -> runIgp(() -> {
            String r = getClient().authenticate();
            appendOutput("AUTH: " + r);
            if (r.contains("AUTH_SUCCESS"))
                uiHandler.post(() -> tvAuthStatus.setText("Estado: Autenticado ✓"));
        }));

        findViewById(R.id.btnWifiConfig).setOnClickListener(v ->
                runIgp(() -> appendOutput("WIFI_CONFIG:\n" + getClient().getWifiConfig())));

        findViewById(R.id.btnSetTheme).setOnClickListener(v -> {
            String t = getField(etModuleName, "DarkMode");
            runIgp(() -> appendOutput("SET_THEME(" + t + "): " + getClient().setAppTheme(t)));
        });

        findViewById(R.id.btnStatus).setOnClickListener(v -> {
            String m = getField(etModuleName, "CareOtter");
            runIgp(() -> appendOutput("STATUS(" + m + "):\n" + getClient().verifyStatus(m)));
        });

        findViewById(R.id.btnFormatString).setOnClickListener(v ->
                runIgp(() -> appendOutput("FMT_LEAK:\n" +
                        getClient().verifyStatus("%x.%x.%x.%x"))));

        findViewById(R.id.btnUnderflow).setOnClickListener(v ->
                runIgp(() -> appendOutput("UNDERFLOW: " + getClient().exploitUnderflow())));

        // ── New commands ──────────────────────────────────────────

        findViewById(R.id.btnDefibrillate).setOnClickListener(v ->
                runIgp(() -> appendOutput("DEFIBRILLATE: " +
                        getClient().triggerDefibrillator())));

        findViewById(R.id.btnEmergencyAlert).setOnClickListener(v -> {
            String msg = getField(etModuleName, "patient alert");
            runIgp(() -> appendOutput("EMERGENCY_ALERT: " +
                    getClient().sendEmergencyAlert(msg)));
        });

        findViewById(R.id.btnCmdInjection).setOnClickListener(v ->
                runIgp(() -> appendOutput("CMD_INJECTION:\n" +
                        getClient().exploitCommandInjection())));

        findViewById(R.id.btnClear).setOnClickListener(v -> tvOutput.setText(""));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private CareOtterClient getClient() {
        if (client == null) {
            String ip = etIpAddress.getText().toString().trim();
            if (ip.isEmpty()) ip = "192.168.2.1";
            client = new CareOtterClient(ip, 9999);
        }
        return client;
    }

    private String getField(EditText et, String defaultValue) {
        String v = et.getText().toString().trim();
        return v.isEmpty() ? defaultValue : v;
    }

    private void runIgp(IgpTask task) {
        new Thread(() -> {
            try { task.run(); }
            catch (Exception e) { appendOutput("ERROR: " + e.getMessage()); }
        }).start();
    }

    private void appendOutput(String text) {
        uiHandler.post(() -> {
            String cur = tvOutput.getText().toString();
            tvOutput.setText(cur.isEmpty() ? text : cur + "\n─\n" + text);
            scrollOutput.post(() -> scrollOutput.fullScroll(View.FOCUS_DOWN));
        });
    }

    @FunctionalInterface
    interface IgpTask { void run() throws Exception; }
}
