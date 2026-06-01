package com.example.owlcamapp.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.ViewModelProvider
import android.app.Application
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController

@Composable
fun VulnZooApp() {
    val navController = rememberNavController()
    val context = LocalContext.current.applicationContext as Application
    val sessionViewModel: SessionViewModel = viewModel(
        factory = object : ViewModelProvider.Factory {
            override fun <T : androidx.lifecycle.ViewModel> create(modelClass: Class<T>): T {
                @Suppress("UNCHECKED_CAST")
                return SessionViewModel(context) as T
            }
        }
    )
    val token by sessionViewModel.token.collectAsState()
    
    MaterialTheme {
        Surface {
            NavHost(navController = navController, startDestination = "login") {
                composable("login") { LoginScreen(navController, sessionViewModel) }
                composable("cameras") { CameraListScreen(navController, sessionViewModel) }
                composable("camera/{id}") { backStackEntry ->
                    CameraDetailScreen(
                        navController,
                        backStackEntry.arguments?.getString("id") ?: "",
                        token
                    )
                }
                composable("messages") { MessageListScreen(navController, sessionViewModel) }
                composable("send_message") { SendMessageScreen(navController, sessionViewModel) }
                composable("support") { SupportScreen(navController, sessionViewModel) }
                composable("profile") { ProfileScreen(navController, sessionViewModel) }
                composable("change_password") { ChangePasswordScreen(navController, sessionViewModel) }
                composable("register") { RegisterScreen(navController) }
                composable("logout") { LogoutScreen(navController, sessionViewModel) }
                composable("firmware") { FirmwareScreen(navController, sessionViewModel) }
            }
        }
    }
}
