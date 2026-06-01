package com.example.owlcamapp.ui

import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalContext
import androidx.navigation.NavController
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.net.HttpURLConnection
import java.net.URL
import com.example.owlcamapp.util.ApiConfig

@Composable
fun LogoutScreen(navController: NavController, sessionViewModel: SessionViewModel) {
    val token by sessionViewModel.token.collectAsState()
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(token) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val url = URL("${ApiConfig.BASE_URL}/api/v2/logout")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "DELETE"
                conn.setRequestProperty("X-Auth-Token", token)
                val responseCode = conn.responseCode
                if (responseCode == 200) {
                    sessionViewModel.clearToken()
                    CoroutineScope(Dispatchers.Main).launch {
                        navController.navigate("login") {
                            popUpTo(0)
                        }
                    }
                } else {
                    error = "Error al cerrar sesión"
                }
            } catch (e: Exception) {
                error = "Error de red o servidor"
            } finally {
                loading = false
            }
        }
    }

    if (loading) {
        CircularProgressIndicator()
    } else if (error != null) {
        Text(error!!, color = MaterialTheme.colorScheme.error)
    }
}
