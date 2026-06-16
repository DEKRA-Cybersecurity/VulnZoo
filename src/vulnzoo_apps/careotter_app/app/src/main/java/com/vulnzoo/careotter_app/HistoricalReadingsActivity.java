package com.vulnzoo.careotter_app;

import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import java.net.HttpURLConnection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * HistoricalReadingsActivity — patient reading history.
 *
 * Fetches GET /api/vitals/readings?patient_id=<own id> and lists the patient's
 * past BPM / SpO2 readings. The numeric id is read from SharedPreferences
 * (stored at login) and sent verbatim as the patient_id query parameter.
 *
 * The backend builds that query by raw string concatenation, so patient_id is a
 * UNION-based SQL injection point (OWASP Mobile M4 / CWE-89). The app always
 * sends its own id; tampering happens at the network layer (Burp/curl). See
 * docs/CareOtter/Vulns/Mobile/M4_Insufficient_Input_Output_Validation.md.
 */
public class HistoricalReadingsActivity extends AppCompatActivity {

    private static final String TAG = "HistoryActivity";

    private final Handler uiHandler = new Handler(Looper.getMainLooper());
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private TextView     tvStatus;
    private LinearLayout llReadings;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_historical_readings);

        tvStatus   = findViewById(R.id.tvHistoryStatus);
        llReadings = findViewById(R.id.llReadings);

        findViewById(R.id.btnHistoryBack).setOnClickListener(v -> finish());

        SharedPreferences prefs = getSharedPreferences("careotter_prefs", MODE_PRIVATE);
        String token  = prefs.getString("jwt_token", null);
        String apiUrl = prefs.getString("api_url", null);
        int    userId = prefs.getInt("user_id", -1);

        if (token == null || apiUrl == null) {
            tvStatus.setText("Not logged in.");
            return;
        }
        if (userId < 0) {
            tvStatus.setText("No patient id on this session. Log in again.");
            return;
        }

        tvStatus.setText("Loading last hour for patient #" + userId + "…");
        loadReadings(apiUrl, token, userId);
    }

    private void loadReadings(String apiUrl, String token, int patientId) {
        executor.execute(() -> {
            try {
                URL url = new URL(apiUrl + "/api/vitals/readings?patient_id=" + patientId);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setRequestProperty("Authorization", "Bearer " + token);
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);

                int code = conn.getResponseCode();
                java.io.InputStream is = (code < 400) ? conn.getInputStream() : conn.getErrorStream();
                String body = new String(readAllBytesCompat(is), java.nio.charset.StandardCharsets.UTF_8);
                if (code >= 400) {
                    uiHandler.post(() -> tvStatus.setText("Server error (" + code + ")."));
                    Log.w(TAG, "readings http " + code + ": " + body);
                    return;
                }

                JSONObject json     = new JSONObject(body);
                JSONArray  readings = json.optJSONArray("readings");
                uiHandler.post(() -> renderReadings(readings));
            } catch (Exception e) {
                Log.w(TAG, "loadReadings failed: " + e.getMessage());
                uiHandler.post(() -> tvStatus.setText("Sync error: " + e.getMessage()));
            }
        });
    }

    private void renderReadings(JSONArray readings) {
        llReadings.removeAllViews();
        int n = (readings == null) ? 0 : readings.length();
        if (n == 0) {
            tvStatus.setText("No readings in the last hour.");
            return;
        }
        tvStatus.setText(n + " reading(s) · last hour");
        SimpleDateFormat fmt = new SimpleDateFormat("dd MMM HH:mm:ss", Locale.US);
        for (int i = 0; i < n; i++) {
            JSONObject r = readings.optJSONObject(i);
            if (r == null) continue;
            String bpm  = r.isNull("bpm")  ? "—" : r.optString("bpm", "—");
            String spo2 = r.isNull("spo2") ? "—" : r.optString("spo2", "—");
            String when;
            double ts = r.optDouble("timestamp", 0);
            when = (ts > 0) ? fmt.format(new Date((long) (ts * 1000))) : "—";
            llReadings.addView(rowView(when, bpm, spo2));
        }
    }

    private TextView rowView(String when, String bpm, String spo2) {
        TextView tv = new TextView(this);
        tv.setText(when + "    BPM: " + bpm + "    SpO2: " + spo2);
        tv.setTextSize(13);
        tv.setTextColor(Color.parseColor("#0F172A"));
        tv.setTypeface(android.graphics.Typeface.MONOSPACE);
        tv.setPadding(12, 12, 12, 12);
        tv.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = 6;
        tv.setLayoutParams(lp);
        tv.setBackgroundColor(Color.parseColor("#F4FBFF"));
        return tv;
    }

    private byte[] readAllBytesCompat(java.io.InputStream is) throws java.io.IOException {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int n;
        while ((n = is.read(buffer)) != -1) {
            bos.write(buffer, 0, n);
        }
        return bos.toByteArray();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdownNow();
    }
}
