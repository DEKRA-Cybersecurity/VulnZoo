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
fun ProfileScreen(navController: NavController, sessionViewModel: SessionViewModel) {
    var username by remember { mutableStateOf("") }
    var role by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(true) }
    val token by sessionViewModel.token.collectAsState()

    LaunchedEffect(token) {
        loading = true
        error = null
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val url = URL("${ApiConfig.BASE_URL}/api/profile")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "GET"
                conn.setRequestProperty("X-Auth-Token", token)
                val responseCode = conn.responseCode
                val response = conn.inputStream.bufferedReader().readText()
                if (responseCode == 200) {
                    val json = JSONObject(response)
                    username = json.optString("username", "")
                    role = json.optString("role", "")
                    loading = false
                } else {
                    val json = JSONObject(response)
                    val msg = json.optString("error", "Unknown error")
                    CoroutineScope(Dispatchers.Main).launch {
                        error = msg
                        loading = false
                    }
                }
            } catch (e: Exception) {
                CoroutineScope(Dispatchers.Main).launch {
                    error = "Network or server error"
                    loading = false
                }
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
                    Text("User Profile", style = MaterialTheme.typography.headlineMedium)
                    Spacer(modifier = Modifier.height(16.dp))
                    Text("Username: $username", style = MaterialTheme.typography.bodyLarge)
                    Text("Role: $role", style = MaterialTheme.typography.bodyLarge)
                }
            }
        }
    }
}
