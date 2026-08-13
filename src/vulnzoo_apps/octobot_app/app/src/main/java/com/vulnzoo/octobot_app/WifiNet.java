package com.vulnzoo.octobot_app;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.util.Log;

/**
 * Pins the app's sockets to the WiFi interface.
 *
 * The lab AP has no internet, so Android keeps the default route on mobile data and
 * every plain new URL().openConnection() would egress via the SIM, unable to reach an
 * AP-only API address (e.g. 192.168.8.x). This resolves the WiFi transport network -
 * the same interface whose IP "Detect WiFi" reads - and binds the process to it, so
 * Test Connection, login and the control panel all go over WiFi regardless of whether
 * that WiFi has internet.
 *
 * Binding to the WiFi Network (not to the source IP string) is what actually redirects
 * the route: Android picks the egress interface from the network the socket is bound to,
 * not from the local address.
 */
final class WifiNet {

    private static final String TAG = "OctoBotWifiNet";

    private WifiNet() {}

    /** Bind the whole process to the connected WiFi network. Returns true if bound. */
    static boolean bindToWifi(Context ctx) {
        ConnectivityManager cm = (ConnectivityManager)
                ctx.getApplicationContext().getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return false;

        for (Network n : cm.getAllNetworks()) {
            NetworkCapabilities caps = cm.getNetworkCapabilities(n);
            if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                boolean ok = cm.bindProcessToNetwork(n);
                Log.i(TAG, "bound process to WiFi network: " + ok);
                return ok;
            }
        }
        // No WiFi found: leave the default network so behaviour is unchanged off-lab.
        Log.w(TAG, "no WiFi transport network found; leaving default network");
        return false;
    }
}
