package com.vulnzoo.bulbbee_app.ui;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.textfield.TextInputEditText;
import com.vulnzoo.bulbbee_app.R;
import com.vulnzoo.bulbbee_app.ble.BleRepository;

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
        provStatus.setText(R.string.setup_sending);
        // BULB-01: PIN is the only gate on an unbonded link. cloudHost is written
        // into the bulb's config.json. BULB-R6: if signed in, fetch a claim token so
        // the bulb binds to this account during onboarding.
        vm.fetchClaim(claim ->
                vm.provision(pin, ssid, psk, cloudHost, claim == null ? "" : claim));
    }

    private void onProvisionResult(BleRepository.ProvResult result) {
        if (result == null || result == handled) return;   // do not re-store on re-observe
        handled = result;
        provStatus.setText(result.message);
        if (result.ok) {
            storeCredentials(text(ssidInput), text(pskInput), CLOUD_TOKEN);
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
