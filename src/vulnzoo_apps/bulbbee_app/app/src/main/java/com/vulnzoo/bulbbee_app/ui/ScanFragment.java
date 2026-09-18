package com.vulnzoo.bulbbee_app.ui;

import android.Manifest;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.google.android.material.button.MaterialButton;
import com.vulnzoo.bulbbee_app.R;

import java.util.ArrayList;
import java.util.List;

/**
 * Pre-connection screen. Requests the BLE runtime permissions (and asks to turn
 * Bluetooth on), then scans for the BulbBee peripheral. On connect, MainActivity
 * switches to the Light tab.
 */
public class ScanFragment extends Fragment {

    private LightViewModel vm;
    private TextView scanStatus;

    private final ActivityResultLauncher<String[]> permLauncher =
            registerForActivityResult(new ActivityResultContracts.RequestMultiplePermissions(), granted -> {
                for (Boolean g : granted.values()) {
                    if (!Boolean.TRUE.equals(g)) {
                        scanStatus.setText(R.string.perm_denied);
                        return;
                    }
                }
                startScan();
            });

    private final ActivityResultLauncher<Intent> enableBtLauncher =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), r -> onPairClicked());

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_scan, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        vm = new ViewModelProvider(requireActivity()).get(LightViewModel.class);
        scanStatus = view.findViewById(R.id.scanStatus);
        ((MaterialButton) view.findViewById(R.id.pairButton)).setOnClickListener(v -> onPairClicked());
        vm.status().observe(getViewLifecycleOwner(), s -> scanStatus.setText(s));
    }

    private void onPairClicked() {
        BluetoothManager bm = (BluetoothManager) requireContext().getSystemService(Context.BLUETOOTH_SERVICE);
        BluetoothAdapter adapter = bm != null ? bm.getAdapter() : null;
        if (adapter == null) {
            scanStatus.setText(R.string.no_bluetooth);
            return;
        }
        if (!adapter.isEnabled()) {
            enableBtLauncher.launch(new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE));
            return;
        }
        String[] needed = requiredPermissions();
        if (allGranted(needed)) startScan();
        else permLauncher.launch(needed);
    }

    private void startScan() {
        scanStatus.setText(R.string.scan_scanning);
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
}
