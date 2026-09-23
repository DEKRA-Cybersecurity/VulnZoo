package com.vulnzoo.bulbbee_app.ui;

/**
 * The transport failover policy (BULB-R5). Pure decision so it is unit-checkable,
 * the reachability probes that feed it are the repositories' job.
 *
 * Priority is the real hybrid-bulb order: the same-LAN direct plane first (lowest
 * latency), then the cloud (remote control), then BLE in range as the backup.
 */
public final class TransportSelector {

    private TransportSelector() { }

    public enum Transport { LOCAL, CLOUD, BLE, NONE }

    public static Transport choose(boolean localReachable, boolean cloudReachable, boolean bleAvailable) {
        if (localReachable) return Transport.LOCAL;
        if (cloudReachable) return Transport.CLOUD;
        if (bleAvailable) return Transport.BLE;
        return Transport.NONE;
    }

    /** When the chosen transport is remote (cloud), the local probe and the BLE
     *  scan are pointless, gate them off. */
    public static boolean scansEnabled(Transport t) {
        return t != Transport.CLOUD;
    }

    public static void main(String[] args) {
        if (choose(true, true, true) != Transport.LOCAL) throw new AssertionError("local first");
        if (choose(false, true, true) != Transport.CLOUD) throw new AssertionError("cloud second");
        if (choose(false, false, true) != Transport.BLE) throw new AssertionError("ble backup");
        if (choose(false, false, false) != Transport.NONE) throw new AssertionError("none");
        if (scansEnabled(Transport.CLOUD)) throw new AssertionError("gate scans when remote");
        if (!scansEnabled(Transport.LOCAL)) throw new AssertionError("scans on when local");
        System.out.println("TransportSelector selfcheck OK");
    }
}
