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

    private LightViewModel vm;
    private TextInputEditText pinInput, ssidInput, pskInput;
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
        provStatus = v.findViewById(R.id.provStatus);

        // M1: prefill the shared factory PIN so onboarding "just works".
        pinInput.setText(PAIRING_PIN);

        ((MaterialButton) v.findViewById(R.id.provisionButton))
                .setOnClickListener(x -> onProvisionClicked());

        vm.provResult().observe(getViewLifecycleOwner(), this::onProvisionResult);
    }

    private void onProvisionClicked() {
        String pin = text(pinInput);
        String ssid = text(ssidInput);
        String psk = text(pskInput);
        if (ssid.isEmpty()) {
            provStatus.setText(R.string.setup_need_ssid);
            return;
        }
        provStatus.setText(R.string.setup_sending);
        vm.provision(pin, ssid, psk);   // BULB-01: PIN is the only gate on an unbonded link
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
