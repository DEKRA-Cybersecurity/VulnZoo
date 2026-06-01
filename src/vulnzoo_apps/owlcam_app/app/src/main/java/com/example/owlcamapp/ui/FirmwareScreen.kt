package com.example.owlcamapp.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import com.example.owlcamapp.util.ApiConfig
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.automirrored.filled.ExitToApp
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.List

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FirmwareScreen(navController: NavController, sessionViewModel: SessionViewModel) {
    var version by remember { mutableStateOf("") }
    var filename by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(true) }
    val token by sessionViewModel.token.collectAsState()

    LaunchedEffect(token) {
        loading = true
        error = null
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val url = URL("${ApiConfig.BASE_URL}/firmware/latest-version")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "GET"
                val responseCode = conn.responseCode
                val response = conn.inputStream.bufferedReader().readText()
                if (responseCode == 200) {
                    val json = JSONObject(response)
                    version = json.optString("version", "")
                    filename = json.optString("filename", "")
                    loading = false
                } else {
                    error = "Could not get firmware version"
                    loading = false
                }
            } catch (e: Exception) {
                error = "Network or server error"
                loading = false
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Cameras") },
                actions = {
                    IconButton(onClick = { navController.navigate("profile") }) {
                        Icon(Icons.Default.Person, contentDescription = "Profile")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    titleContentColor = MaterialTheme.colorScheme.onPrimary
                )
            )
        },
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    icon = { Icon(Icons.Default.Email, contentDescription = "Messages") },
                    label = { Text("Messages") },
                    selected = false,
                    onClick = { navController.navigate("messages") }
                )
                NavigationBarItem(
                    icon = { Icon(Icons.Default.Info, contentDescription = "Support") },
                    label = { Text("Support") },
                    selected = false,
                    onClick = { navController.navigate("support") }
                )
                NavigationBarItem(
                    icon = { Icon(Icons.Default.List, contentDescription = "Cameras") },
                    label = { Text("Cameras") },
                    selected = false,
                    onClick = { navController.navigate("cameras") }
                )
                NavigationBarItem(
                    icon = { Icon(Icons.Default.Build, contentDescription = "Firmware") },
                    label = { Text("Firmware") },
                    selected = false,
                    onClick = { navController.navigate("firmware") }
                )
                NavigationBarItem(
                    icon = { Icon(Icons.AutoMirrored.Filled.ExitToApp, contentDescription = "Logout") },
                    label = { Text("Logout") },
                    selected = false,
                    onClick = { navController.navigate("logout") }
                )
            }
        }
    ) { innerPadding ->
        Box(modifier = Modifier
            .fillMaxSize()
            .padding(innerPadding), contentAlignment = Alignment.Center) {
            when {
                loading -> CircularProgressIndicator()
                error != null -> Text(error!!, color = MaterialTheme.colorScheme.error)
                else -> Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text("Available Firmware", style = MaterialTheme.typography.headlineMedium)
                    Spacer(modifier = Modifier.height(16.dp))
                    Text("Version: $version", style = MaterialTheme.typography.bodyLarge)
                    Text("File: $filename", style = MaterialTheme.typography.bodyLarge)
                }
            }
        }
    }
}
