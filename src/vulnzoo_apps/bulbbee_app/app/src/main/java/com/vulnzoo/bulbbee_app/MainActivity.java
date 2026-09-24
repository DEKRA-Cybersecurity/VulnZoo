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
 * NavHostFragment, with Login as the mandatory pre-app barrier (BULB-U1). The
 * BLE plumbing moved to {@code ble.BleRepository} and the per-screen logic to the
 * fragments, so this Activity only wires navigation and the session gate. The
 * intentional vulnerabilities (hardcoded PIN M1, plaintext credential store M9)
 * live in {@code ui.SetupFragment}.
 */
public class MainActivity extends AppCompatActivity {

    private NavController navController;
    private BottomNavigationView bottomNav;
    private LightViewModel vm;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        bottomNav = findViewById(R.id.bottomNav);
        NavHostFragment host = (NavHostFragment) getSupportFragmentManager()
                .findFragmentById(R.id.navHost);
        navController = host.getNavController();
        NavigationUI.setupWithNavController(bottomNav, navController);

        // Login is the pre-app barrier (BULB-U1/U5): hide the bottom nav there.
        navController.addOnDestinationChangedListener((c, dest, args) ->
                bottomNav.setVisibility(
                        dest.getId() == R.id.loginFragment ? View.GONE : View.VISIBLE));

        vm = new ViewModelProvider(this).get(LightViewModel.class);
        // Gate on the cloud session (BULB-U1): logged in -> the app, else -> login.
        vm.cloudConnected().observe(this, c -> onSessionChanged());
        // BULB-U1: auto-resume a stored session so login is skipped when possible.
        vm.resumeSession();
    }

    private void onSessionChanged() {
        boolean loggedIn = Boolean.TRUE.equals(vm.cloudConnected().getValue());
        NavDestination dest = navController.getCurrentDestination();
        int id = dest != null ? dest.getId() : 0;
        boolean onLogin = (id == R.id.loginFragment);
        if (loggedIn && onLogin) {
            bottomNav.setSelectedItemId(R.id.lightFragment);   // enter the app on sign-in / resume
        } else if (!loggedIn && !onLogin) {
            navController.navigate(R.id.loginFragment);          // sign out -> login
        }
    }
}
