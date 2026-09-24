package com.vulnzoo.bulbbee_app.ui;

import android.Manifest;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.textfield.TextInputEditText;
import com.vulnzoo.bulbbee_app.R;
import com.vulnzoo.bulbbee_app.ble.BleRepository;

import java.util.ArrayList;
import java.util.List;

/**
 * WiFi onboarding screen. The redesigned wizard only changes what it says and
 * asks for; the secrets still end up in the same insecure places.
 *
 * VULNERABILITY M1 (Improper Credential Usage) / CWE-798: the factory pairing PIN
 *   is hardcoded here, so it is extractable from the shipped APK and identical on
 *   every device (client side of BULB-01). It is prefilled so onboarding "just works".
 * VULNERABILITY M9 (Insecure Data Storage) / CWE-312: the home WiFi PSK and the
 *   cloud pairing token are stored in plaintext SharedPreferences and written to
 *   Logcat (client side of BULB-05).
 */
public class SetupFragment extends Fragment {

    private static final String TAG = "BulbBee";

    // VULNERABILITY M1 / CWE-798: hardcoded factory pairing PIN, identical on
    // every unit, recoverable by unzipping the APK.
    private static final String PAIRING_PIN = "8080";
    // Cloud pairing token shipped with the app (stored in the clear, M9).
    private static final String CLOUD_TOKEN = "cloud-token-abc";
    // Default cloud server IP, prefilled but editable (it depends on the network).
    private static final String DEFAULT_CLOUD_HOST = "192.168.2.10";

    private LightViewModel vm;
    private TextInputEditText pinInput, ssidInput, pskInput, cloudHostInput;
    private android.widget.TextView provStatus;
    private BleRepository.ProvResult handled;
    // True only between a provision started on this screen and its result, so the
    // sticky provResult LiveData does not re-fire (and re-navigate) on re-entry.
    private boolean awaitingResult = false;

    // BULB-U4: the link panel establishes the BLE link itself (the retired Scan
    // screen used to). Request the runtime permissions, then scan/connect.
    private final ActivityResultLauncher<String[]> permLauncher =
            registerForActivityResult(new ActivityResultContracts.RequestMultiplePermissions(), granted -> {
                for (Boolean g : granted.values()) {
                    if (!Boolean.TRUE.equals(g)) { provStatus.setText(R.string.perm_denied); return; }
                }
                startScan();
            });

    private final ActivityResultLauncher<Intent> enableBtLauncher =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), r -> ensureBleConnection());

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_setup, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View v, @Nullable Bundle savedInstanceState) {
        vm = new ViewModelProvider(requireActivity()).get(LightViewModel.class);
        pinInput = v.findViewById(R.id.pinInput);
        ssidInput = v.findViewById(R.id.ssidInput);
        pskInput = v.findViewById(R.id.pskInput);
        cloudHostInput = v.findViewById(R.id.cloudHostInput);
        provStatus = v.findViewById(R.id.provStatus);

        // M1: prefill the shared factory PIN so onboarding "just works".
        pinInput.setText(PAIRING_PIN);
        cloudHostInput.setText(DEFAULT_CLOUD_HOST);   // editable, depends on the network

        ((MaterialButton) v.findViewById(R.id.provisionButton))
                .setOnClickListener(x -> onProvisionClicked());

        vm.provResult().observe(getViewLifecycleOwner(), this::onProvisionResult);
        // BULB-R6: the device serial read over BLE, stashed so the cloud sign-in can
        // register this exact device to the account.
        vm.deviceId().observe(getViewLifecycleOwner(), this::onDeviceId);

        vm.connected().observe(getViewLifecycleOwner(), c -> {
            if (Boolean.TRUE.equals(c) && handled == null) provStatus.setText(R.string.setup_bulb_connected);
        });
        // BULB-U4: the link panel needs a live BLE link to provision over.
        ensureBleConnection();
    }

    /** BULB-U4: ensure a BLE connection to the bulb before provisioning. */
    private void ensureBleConnection() {
        if (Boolean.TRUE.equals(vm.connected().getValue())) return;
        BluetoothManager bm = (BluetoothManager) requireContext().getSystemService(Context.BLUETOOTH_SERVICE);
        BluetoothAdapter adapter = bm != null ? bm.getAdapter() : null;
        if (adapter == null) { provStatus.setText(R.string.no_bluetooth); return; }
        if (!adapter.isEnabled()) {
            enableBtLauncher.launch(new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE));
            return;
        }
        String[] needed = requiredPermissions();
        if (allGranted(needed)) startScan();
        else permLauncher.launch(needed);
    }

    private void startScan() {
        provStatus.setText(R.string.setup_connect_first);
        vm.scanAndConnect();
    }

    private String[] requiredPermissions() {
        List<String> perms = new ArrayList<>();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            perms.add(Manifest.permission.BLUETOOTH_SCAN);
            perms.add(Manifest.permission.BLUETOOTH_CONNECT);
        } else {
            perms.add(Manifest.permission.ACCESS_FINE_LOCATION);
        }
        return perms.toArray(new String[0]);
    }

    private boolean allGranted(String[] perms) {
        for (String p : perms) {
            if (ContextCompat.checkSelfPermission(requireContext(), p) != PackageManager.PERMISSION_GRANTED) {
                return false;
            }
        }
        return true;
    }

    private void onDeviceId(String deviceId) {
        if (deviceId == null || deviceId.isEmpty()) return;
        requireContext().getSharedPreferences("bulbbee", Context.MODE_PRIVATE)
                .edit().putString("cloud_device_id", deviceId).apply();
        Log.d(TAG, "device serial for cloud binding: " + deviceId);
    }

    private void onProvisionClicked() {
        String pin = text(pinInput);
        String ssid = text(ssidInput);
        String psk = text(pskInput);
        String cloudHost = text(cloudHostInput);
        if (ssid.isEmpty()) {
            provStatus.setText(R.string.setup_need_ssid);
            return;
        }
        // BULB-U4: provisioning rides an active BLE link, connect first if needed.
        if (!Boolean.TRUE.equals(vm.connected().getValue())) {
            provStatus.setText(R.string.setup_connect_first);
            ensureBleConnection();
            return;
        }
        provStatus.setText(R.string.setup_sending);
        awaitingResult = true;   // a result from now on is ours to act on
        // BULB-01: PIN is the only gate on an unbonded link. cloudHost is written
        // into the bulb's config.json. BULB-R6: if signed in, fetch a claim token so
        // the bulb binds to this account during onboarding.
        vm.fetchClaim(claim ->
                vm.provision(pin, ssid, psk, cloudHost, claim == null ? "" : claim));
    }

    private void onProvisionResult(BleRepository.ProvResult result) {
        if (result == null || result == handled) return;   // do not re-fire on re-observe
        handled = result;
        provStatus.setText(result.message);
        // provResult is sticky: a fresh SetupFragment re-observes the last success.
        // Only act on a result from a provision started on THIS screen, otherwise
        // every visit to Setup would re-store and bounce the user to Light.
        if (result.ok && awaitingResult) {
            awaitingResult = false;
            storeCredentials(text(ssidInput), text(pskInput), CLOUD_TOKEN);
            // BULB-U4: the bulb binds to the account on activation, drop into control
            // via the bottom nav (a clean tab switch, not a back-stack push).
            BottomNavigationView nav = requireActivity().findViewById(R.id.bottomNav);
            if (nav != null) nav.setSelectedItemId(R.id.lightFragment);
        }
    }

    /** VULNERABILITY M9 / CWE-312: cleartext credential storage + Logcat leak. */
    private void storeCredentials(String ssid, String psk, String cloudToken) {
        SharedPreferences prefs = requireContext()
                .getSharedPreferences("bulbbee", Context.MODE_PRIVATE);
        prefs.edit()
                .putString("wifi_ssid", ssid)
                .putString("wifi_psk", psk)          // plaintext at rest
                .putString("cloud_token", cloudToken)
                .apply();
        Log.d(TAG, "stored creds ssid=" + ssid + " psk=" + psk + " token=" + cloudToken); // leaked to Logcat
    }

    private static String text(TextInputEditText e) {
        return e.getText() != null ? e.getText().toString() : "";
    }
}
