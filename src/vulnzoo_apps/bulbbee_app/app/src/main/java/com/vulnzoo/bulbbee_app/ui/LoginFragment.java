package com.vulnzoo.bulbbee_app.ui;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.textfield.TextInputEditText;
import com.vulnzoo.bulbbee_app.R;

/**
 * BULB-R6: cloud account sign-in screen, reached from Scan with no Bluetooth. On
 * success MainActivity switches to the Light tab (it gates on a cloud session as
 * well as a BLE connection). On failure the status line shows the error and the
 * screen stays open.
 */
public class LoginFragment extends Fragment {

    private LightViewModel vm;
    private TextInputEditText baseInput, userInput, passInput;
    private TextView status;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_login, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View v, @Nullable Bundle savedInstanceState) {
        vm = new ViewModelProvider(requireActivity()).get(LightViewModel.class);
        baseInput = v.findViewById(R.id.loginBase);
        userInput = v.findViewById(R.id.loginUser);
        passInput = v.findViewById(R.id.loginPassword);
        status = v.findViewById(R.id.loginStatus);
        baseInput.setText("http://192.168.2.10:5004");

        ((MaterialButton) v.findViewById(R.id.loginButton)).setOnClickListener(x -> onSignIn());
        vm.cloudStatus().observe(getViewLifecycleOwner(), s -> {
            if (s != null && !s.isEmpty()) status.setText(s);
        });
    }

    private void onSignIn() {
        status.setText(R.string.signing_in);
        vm.cloudSignIn(text(baseInput), text(userInput), text(passInput));
    }

    private static String text(TextInputEditText e) {
        return e.getText() != null ? e.getText().toString().trim() : "";
    }
}
