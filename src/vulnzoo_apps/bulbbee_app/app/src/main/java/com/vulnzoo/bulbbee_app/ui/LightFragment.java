package com.vulnzoo.bulbbee_app.ui;

import android.Manifest;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;
import androidx.navigation.Navigation;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.button.MaterialButtonToggleGroup;
import com.vulnzoo.bulbbee_app.R;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.function.IntConsumer;

/**
 * The daily control surface. The orb, the wheel, the brightness bar and the
 * temperature ramp drive Control (0xFF31) through the shared {@link LightViewModel};
 * the State characteristic (0xFF32) drives them back. Wheel / bar / ramp writes
 * are throttled to ~20 Hz so a drag does not flood the bulb (BULB-07 is a
 * scene-payload DoS finding — do not feed it a stream of Control writes).
 */
public class LightFragment extends Fragment {

    private LightViewModel vm;

    private TextView linkLine, brightnessRaw;
    private View stateOverlay;
    private TextView stateMessage, stateSub;
    private MaterialButton linkButton, retryButton;
    private BulbOrbView orb;
    private BrightnessBarView brightnessBar;
    private ColorWheelView colorWheel;
    private TempRampView tempRamp;
    private RecyclerView presetGrid;

    private Throttle colorThrottle, brightnessThrottle;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_light, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View v, @Nullable Bundle savedInstanceState) {
        vm = new ViewModelProvider(requireActivity()).get(LightViewModel.class);

        linkLine = v.findViewById(R.id.linkLine);
        brightnessRaw = v.findViewById(R.id.brightnessRaw);
        orb = v.findViewById(R.id.orb);
        brightnessBar = v.findViewById(R.id.brightnessBar);
        colorWheel = v.findViewById(R.id.colorWheel);
        tempRamp = v.findViewById(R.id.tempRamp);
        presetGrid = v.findViewById(R.id.presetGrid);

        colorThrottle = new Throttle(vm::writeColor);
        brightnessThrottle = new Throttle(vm::writeBrightness);

        orb.setOnPowerToggleListener(vm::writePower);
        brightnessBar.setOnBrightnessChangeListener(value -> {
            brightnessRaw.setText(getString(R.string.brightness_raw, value));
            brightnessThrottle.submit(value);
        });
        colorWheel.setOnColorPickedListener((color, hue, sat) -> colorThrottle.submit(color));
        tempRamp.setOnKelvinChangeListener((kelvin, color) -> colorThrottle.submit(color));

        presetGrid.setAdapter(new PresetAdapter(color -> {
            colorWheel.setHueSat(hueOf(color), satOf(color));
            vm.writeColor(color);
        }));

        ((MaterialButton) v.findViewById(R.id.forgetButton)).setOnClickListener(x -> vm.forgetDevice());
        ((MaterialButton) v.findViewById(R.id.signOutButton)).setOnClickListener(x -> vm.signOut());

        MaterialButtonToggleGroup pickMode = v.findViewById(R.id.pickMode);
        pickMode.addOnButtonCheckedListener((group, checkedId, isChecked) -> {
            if (!isChecked) return;
            colorWheel.setVisibility(checkedId == R.id.modeWheel ? View.VISIBLE : View.GONE);
            tempRamp.setVisibility(checkedId == R.id.modeWhite ? View.VISIBLE : View.GONE);
            presetGrid.setVisibility(checkedId == R.id.modePresets ? View.VISIBLE : View.GONE);
        });
        pickMode.check(R.id.modeWheel);

        stateOverlay = v.findViewById(R.id.stateOverlay);
        stateMessage = v.findViewById(R.id.stateMessage);
        stateSub = v.findViewById(R.id.stateSub);
        linkButton = v.findViewById(R.id.linkButton);
        retryButton = v.findViewById(R.id.retryButton);
        // BULB-U4: link a device (Setup is the link panel).
        linkButton.setOnClickListener(x -> Navigation.findNavController(x).navigate(R.id.setupFragment));
        // BULB-U3: retry the probe, the device may have come back.
        retryButton.setOnClickListener(x -> vm.enterControl(bleReady()));

        vm.stateJson().observe(getViewLifecycleOwner(), this::applyState);
        vm.controlState().observe(getViewLifecycleOwner(), this::applyControlState);

        // BULB-U2: pick the channel automatically on FIRST entry (BLE proximity ->
        // Cloud). Skip it when already connected, so switching tabs and returning to
        // Light does not re-probe and flash "Connecting". The connection lives in the
        // activity-scoped repositories, so it survives tab switches, only Forget
        // device / Sign out (or a real drop) change it. Retry re-probes explicitly.
        if (vm.controlState().getValue() != LightViewModel.ControlState.CONNECTED) {
            vm.enterControl(bleReady());
        }
    }

    /** BULB-U2/U3/U4: show the controls only when CONNECTED, the overlay otherwise. */
    private void applyControlState(LightViewModel.ControlState st) {
        boolean connected = st == LightViewModel.ControlState.CONNECTED;
        stateOverlay.setVisibility(connected ? View.GONE : View.VISIBLE);
        linkButton.setVisibility(st == LightViewModel.ControlState.UNLINKED ? View.VISIBLE : View.GONE);
        retryButton.setVisibility(st == LightViewModel.ControlState.OFFLINE ? View.VISIBLE : View.GONE);
        switch (st) {
            case OFFLINE:
                stateMessage.setText(R.string.offline_device);
                stateSub.setText(R.string.offline_sub);
                break;
            case UNLINKED:
                stateMessage.setText(R.string.no_bulb_title);
                stateSub.setText(R.string.no_bulb_sub);
                break;
            default:   // CONNECTING
                stateMessage.setText(R.string.state_connecting);
                stateSub.setText("");
        }
    }

    /** BLE is usable for the proximity probe only when the adapter is on and the
     *  runtime permissions are already granted (they are requested in the link
     *  panel, BULB-U4, not on every login). */
    private boolean bleReady() {
        if (!vm.isBluetoothReady()) return false;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return granted(Manifest.permission.BLUETOOTH_SCAN)
                    && granted(Manifest.permission.BLUETOOTH_CONNECT);
        }
        return granted(Manifest.permission.ACCESS_FINE_LOCATION);
    }

    private boolean granted(String perm) {
        return ContextCompat.checkSelfPermission(requireContext(), perm)
                == PackageManager.PERMISSION_GRANTED;
    }

    /** Reflect the 0xFF32 snapshot into the controls. These setters do not fire
     *  the views' listeners, so a notification never echoes back as a write. */
    private void applyState(String json) {
        try {
            JSONObject o = new JSONObject(json);
            boolean power = o.optBoolean("power", true);
            int brightness = o.optInt("brightness", 178);
            String scene = o.optString("scene", "solid");
            JSONArray c = o.optJSONArray("color");
            int color = c != null
                    ? Color.rgb(c.optInt(0), c.optInt(1), c.optInt(2))
                    : 0xFFFBB03F;

            orb.setBulbState(power, brightness, color, scene);
            brightnessBar.setValue(brightness);
            brightnessRaw.setText(getString(R.string.brightness_raw, brightness));
            linkLine.setText(transportLabel() + " · " + Math.round(brightness / 255f * 100) + "% · " + scene
                    + (o.optBoolean("simulated") ? " · sim" : ""));
        } catch (Exception e) {
            linkLine.setText(json);
        }
    }

    /** The active transport, for the state line (BLE / Cloud / LAN). */
    private String transportLabel() {
        switch (vm.transport()) {
            case CLOUD: return "Cloud";
            case LOCAL: return "LAN";
            default: return "BLE";
        }
    }

    private static float hueOf(int color) {
        float[] hsv = new float[3];
        Color.colorToHSV(color, hsv);
        return hsv[0];
    }

    private static float satOf(int color) {
        float[] hsv = new float[3];
        Color.colorToHSV(color, hsv);
        return hsv[1];
    }

    /** Leading + trailing throttle at ~20 Hz, so a fast drag sends a bounded
     *  stream of Control writes and always delivers the final value. */
    private static final class Throttle {
        private static final long INTERVAL_MS = 50;
        private final Handler h = new Handler(Looper.getMainLooper());
        private final IntConsumer sink;
        private long last = 0;
        private Runnable pending;

        Throttle(IntConsumer sink) { this.sink = sink; }

        void submit(int value) {
            long now = SystemClock.uptimeMillis();
            if (pending != null) { h.removeCallbacks(pending); pending = null; }
            if (now - last >= INTERVAL_MS) {
                last = now;
                sink.accept(value);
            } else {
                pending = () -> { last = SystemClock.uptimeMillis(); sink.accept(value); };
                h.postDelayed(pending, INTERVAL_MS);
            }
        }
    }
}
