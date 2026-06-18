package com.vulnzoo.careotter_app;

import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Debug;
import android.util.Log;

import androidx.appcompat.app.AlertDialog;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.MessageDigest;

/**
 * SecurityGuard — startup runtime self-protection (RASP).
 *
 * Runs four checks at app entry: root, debugger, Frida/instrumentation, and a
 * signing-certificate integrity check. LoginActivity calls {@link #enforce} and
 * exits the app if the runtime is judged compromised.
 *
 * VULNERABILITY (OWASP M7 — Insufficient Binary Protection):
 *   Each control is present but deliberately weak (CWE-693, protection
 *   mechanism failure). Every check is a plain Java boolean with no native
 *   backing, so a single Frida hook on {@link #isCompromised} neutralises all
 *   of them before onCreate runs:
 *
 *     Java.use("com.vulnzoo.careotter_app.SecurityGuard")
 *         .isCompromised.implementation = function (ctx) { return false; };
 *
 *   - Root: a fixed list of su paths, no native check and no Magisk DenyList.
 *   - Debugger: Debug.isDebuggerConnected() only, no ptrace/native anti-debug.
 *   - Frida: a substring scan of /proc/self/maps, defeated by renaming the
 *     gadget or hooking the file read.
 *   - Integrity: computed and logged but NOT folded into the verdict
 *     (detection without response).
 */
public final class SecurityGuard {

    private static final String TAG = "SecurityGuard";

    // Expected release signing certificate SHA-256. Placeholder: on a self-built
    // or re-signed APK this will not match, and the result is logged, not acted on.
    private static final String EXPECTED_SIG_SHA256 =
            "0000000000000000000000000000000000000000000000000000000000000000";

    private SecurityGuard() { }

    /** Naive root check: look for common su binaries. No native, no Magisk awareness. */
    public static boolean isDeviceRooted() {
        final String[] paths = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/app/Superuser.apk", "/data/local/bin/su", "/data/local/xbin/su"
        };
        for (String p : paths) {
            if (new File(p).exists()) return true;
        }
        return false;
    }

    /** Debugger check: connected JDWP debugger only. */
    public static boolean isDebuggerAttached() {
        return Debug.isDebuggerConnected();
    }

    /** Frida / instrumentation check: substring scan of the process memory map. */
    public static boolean isFridaPresent() {
        try (BufferedReader r = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = r.readLine()) != null) {
                String l = line.toLowerCase();
                if (l.contains("frida") || l.contains("gum-js-loop") || l.contains("gadget")) {
                    return true;
                }
            }
        } catch (Exception ignored) {
            // maps unreadable — treat as clean
        }
        return false;
    }

    /** Integrity check: compare the signing certificate SHA-256 to the expected value. */
    public static boolean isSignatureValid(Context ctx) {
        try {
            PackageManager pm = ctx.getPackageManager();
            PackageInfo pi = pm.getPackageInfo(ctx.getPackageName(),
                    PackageManager.GET_SIGNING_CERTIFICATES);
            Signature[] sigs = pi.signingInfo.getApkContentsSigners();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(sigs[0].toByteArray());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            String actual = sb.toString();
            Log.w(TAG, "signing cert sha256=" + actual);
            return EXPECTED_SIG_SHA256.equalsIgnoreCase(actual);
        } catch (Exception e) {
            Log.w(TAG, "signature check failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Single attestation verdict. True if the runtime is considered compromised.
     *
     * VULNERABILITY (M7): the signature result is computed and logged but NOT
     * folded into the verdict — a detected re-sign is ignored. The whole verdict
     * is one hookable Java boolean.
     */
    public static boolean isCompromised(Context ctx) {
        boolean rooted   = isDeviceRooted();
        boolean debugger = isDebuggerAttached();
        boolean frida    = isFridaPresent();
        boolean sigOk    = isSignatureValid(ctx);
        Log.w(TAG, "attest root=" + rooted + " debugger=" + debugger
                + " frida=" + frida + " signatureValid=" + sigOk);
        return rooted || debugger || frida;
    }

    /**
     * Enforce the verdict at app entry. Shows a blocking dialog and exits if the
     * runtime is compromised. Returns true if blocked.
     *
     * Bypass (M7): spawn under Frida (frida -f) and hook isCompromised to return
     * false before this runs.
     */
    public static boolean enforce(final Activity activity) {
        if (!isCompromised(activity)) return false;
        new AlertDialog.Builder(activity)
                .setTitle("Security check failed")
                .setMessage("This device appears to be rooted, debugged, or instrumented. "
                        + "For patient safety the app cannot continue.")
                .setCancelable(false)
                .setPositiveButton("Exit", (d, w) -> activity.finishAffinity())
                .show();
        return true;
    }
}
