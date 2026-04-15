package com.vulnzoo.careotter_app;

import android.os.Environment;

import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * VitalsLogger — writes BPM/SpO2 readings to /sdcard/careotter_vitals.log
 *
 * VULNERABILITY: plaintext logging to external storage with no encryption.
 * Any app with READ_EXTERNAL_STORAGE can access the full patient vitals history.
 * No permission check is performed beyond what Android enforces at install time.
 */
public class VitalsLogger {

    // VULNERABILITY: hardcoded path in external storage, world-readable on older Android
    private static final String LOG_PATH =
            Environment.getExternalStorageDirectory() + "/careotter_vitals.log";

    private static final SimpleDateFormat SDF =
            new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);

    /**
     * Appends a vitals reading to the plaintext log file.
     * No encryption, no access control, no integrity check.
     */
    public static void log(int bpm, int spo2) {
        String line = SDF.format(new Date()) + " BPM=" + bpm + " SpO2=" + spo2 + "\n";
        try (FileWriter fw = new FileWriter(LOG_PATH, true)) {
            fw.write(line);
        } catch (IOException ignored) {
            // Silently ignore — log errors are not surfaced to the user
        }
    }

    public static String getLogPath() {
        return LOG_PATH;
    }
}
