package com.example.owlcamapp.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.automirrored.filled.ExitToApp
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.List
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CameraListScreen(navController: NavController, sessionViewModel: SessionViewModel) {
    var cameras by remember { mutableStateOf(listOf<Camera>()) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    val token by sessionViewModel.token.collectAsState()

    LaunchedEffect(token) {
        loading = true
        error = null
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val url = URL("${ApiConfig.BASE_URL}/api/cameras")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "GET"
                conn.setRequestProperty("X-Auth-Token", token)
                val responseCode = conn.responseCode
                val response = conn.inputStream.bufferedReader().readText()
                if (responseCode == 200) {
                    val json = JSONObject(response)
                    val camList = json.getJSONArray("cameras")
                    val parsed = mutableListOf<Camera>()
                    for (i in 0 until camList.length()) {
                        val cam = camList.getJSONObject(i)
                        parsed.add(Camera(
                            id = cam.getString("id"),
                            name = cam.optString("name", "No name"),
                            active = cam.optBoolean("active", false),
                            rtspUrl = cam.optString("rtsp_url", ""),
                            firmwareVersion = cam.optString("firmware-version", "unknown")
                        ))
                    }
                    CoroutineScope(Dispatchers.Main).launch {
                        cameras = parsed
                        loading = false
                    }
                } else {
                    CoroutineScope(Dispatchers.Main).launch {
                        error = "Failed to load cameras"
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
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
            contentAlignment = Alignment.Center
        ) {
            when {
                loading -> CircularProgressIndicator()
                error != null -> Text(error!!, color = MaterialTheme.colorScheme.error)
                else -> LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(cameras) { camera ->
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(8.dp),
                            elevation = CardDefaults.cardElevation(4.dp)
                        ) {
                            Column(
                                modifier = Modifier.padding(16.dp)
                            ) {
                                Text(camera.name, style = MaterialTheme.typography.titleMedium)
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    "Installed firmware: ${camera.firmwareVersion}",
                                    style = MaterialTheme.typography.bodySmall
                                )
                                Spacer(modifier = Modifier.height(8.dp))
                                if (camera.active) {
                                    Button(
                                        onClick = { navController.navigate("camera/${camera.id}") },
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Text("View Snapshot")
                                    }
                                } else {
                                    Button(
                                        onClick = { },
                                        enabled = false,
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Text("Camera is inactive")
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

data class Camera(
    val id: String,
    val name: String,
    val active: Boolean,
    val rtspUrl: String,
    val firmwareVersion: String = "unknown"
)
