package com.vulnzoo.bulbbee_app;

import android.os.Bundle;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.ViewModelProvider;
import androidx.navigation.NavController;
import androidx.navigation.NavDestination;
import androidx.navigation.fragment.NavHostFragment;
import androidx.navigation.ui.NavigationUI;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.vulnzoo.bulbbee_app.ui.LightViewModel;

/**
 * BulbBee Android controller (BULB-APP), navigation host.
 *
 * The screen is a bottom-nav shell (Light / Scenes / Routines / Setup) over a
 * NavHostFragment, with a Scan destination shown until a bulb is connected. The
 * BLE plumbing moved to {@code ble.BleRepository} and the per-screen logic to the
 * fragments, so this Activity only wires navigation. The intentional
 * vulnerabilities (hardcoded PIN M1, plaintext credential store M9) live in
 * {@code ui.SetupFragment}.
 */
public class MainActivity extends AppCompatActivity {

    private NavController navController;
    private BottomNavigationView bottomNav;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        bottomNav = findViewById(R.id.bottomNav);
        NavHostFragment host = (NavHostFragment) getSupportFragmentManager()
                .findFragmentById(R.id.navHost);
        navController = host.getNavController();
        NavigationUI.setupWithNavController(bottomNav, navController);

        // The Scan destination is the pre-connection screen, not a tab: hide the
        // bottom nav there so it does not offer tabs for a bulb that is not paired.
        navController.addOnDestinationChangedListener((c, dest, args) ->
                bottomNav.setVisibility(
                        dest.getId() == R.id.scanFragment ? View.GONE : View.VISIBLE));

        LightViewModel vm = new ViewModelProvider(this).get(LightViewModel.class);
        vm.connected().observe(this, this::onConnectionChanged);
    }

    private void onConnectionChanged(@NonNull Boolean isConnected) {
        NavDestination dest = navController.getCurrentDestination();
        int id = dest != null ? dest.getId() : 0;
        if (isConnected && id == R.id.scanFragment) {
            bottomNav.setSelectedItemId(R.id.lightFragment);   // enter the app on connect
        } else if (!isConnected && id != R.id.scanFragment) {
            navController.navigate(R.id.scanFragment);          // fall back to scan on drop
        }
    }
}
