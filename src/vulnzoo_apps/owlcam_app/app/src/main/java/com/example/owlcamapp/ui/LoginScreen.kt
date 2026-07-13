package com.example.owlcamapp.ui

import android.content.Context
import android.net.wifi.WifiManager
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import com.example.owlcamapp.util.ApiConfig

@Composable
fun LoginScreen(navController: NavController, sessionViewModel: SessionViewModel) {
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }

    // Configurable API server, prefilled from the last saved value.
    var serverIp by remember { mutableStateOf(sessionViewModel.serverIp.value) }
    var serverPort by remember { mutableStateOf(sessionViewModel.serverPort.value) }
    var testStatus by remember { mutableStateOf<String?>(null) }
    val context = LocalContext.current

    // Detect the phone's WiFi /24 prefix so the user can reach the lab server on
    // the same network (the only path in this lab). The host is conventionally .2.
    @Suppress("DEPRECATION")
    fun detectWifiPrefix(): String {
        return try {
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
                ?: return "192.168.2."
            val ipInt = wm.connectionInfo.ipAddress
            if (ipInt == 0) return "192.168.2."
            val a = ipInt and 0xFF
            val b = (ipInt shr 8) and 0xFF
            val c = (ipInt shr 16) and 0xFF
            "$a.$b.$c."
        } catch (e: Exception) {
            "192.168.2."
        }
    }

    fun applyServer() {
        sessionViewModel.setServer(serverIp.trim(), serverPort.trim())
    }

    fun testConnection() {
        testStatus = "Testing..."
        applyServer()
        CoroutineScope(Dispatchers.IO).launch {
            val msg = try {
                val conn = URL("${ApiConfig.BASE_URL}/").openConnection() as HttpURLConnection
                conn.connectTimeout = 4000
                conn.readTimeout = 4000
                val code = conn.responseCode
                conn.disconnect()
                "Reachable at ${ApiConfig.BASE_URL} (HTTP $code)"
            } catch (e: Exception) {
                "Unreachable: ${e.message}"
            }
            CoroutineScope(Dispatchers.Main).launch { testStatus = msg }
        }
    }

    fun login(username: String, password: String) {
        loading = true
        error = null
        applyServer()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val url = URL("${ApiConfig.BASE_URL}/api/v2/login")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/json")
                conn.doOutput = true
                val body = JSONObject(mapOf("username" to username, "password" to password)).toString()
                conn.outputStream.write(body.toByteArray())
                val responseCode = conn.responseCode
                val response = conn.inputStream.bufferedReader().readText()
                if (responseCode == 200) {
                    val json = JSONObject(response)
                    val token = json.optString("auth")
                    // Guardar token en ViewModel global y persistente
                    sessionViewModel.setToken(token)
                    CoroutineScope(Dispatchers.Main).launch {
                        navController.navigate("cameras") {
                            popUpTo("login") { inclusive = true }
                        }
                    }
                } else {
                    val json = JSONObject(response)
                    val msg = json.optString("error", "Unknown error")
                    CoroutineScope(Dispatchers.Main).launch {
                        error = msg
                    }
                }
            } catch (e: Exception) {
                CoroutineScope(Dispatchers.Main).launch {
                    error = "Network or server error"
                }
            } finally {
                loading = false
            }
        }
    }

    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier
                .verticalScroll(rememberScrollState())
                .padding(24.dp)
        ) {
            Text("Login", style = MaterialTheme.typography.headlineMedium)
            Spacer(modifier = Modifier.height(16.dp))

            // ── API Server ──────────────────────────────────────────────────
            Text("API Server", style = MaterialTheme.typography.titleSmall)
            Spacer(modifier = Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = serverIp,
                    onValueChange = { serverIp = it },
                    label = { Text("Server IP") },
                    placeholder = { Text("192.168.2.2") },
                    singleLine = true,
                    modifier = Modifier.weight(1f)
                )
                Spacer(modifier = Modifier.width(8.dp))
                OutlinedTextField(
                    value = serverPort,
                    onValueChange = { serverPort = it },
                    label = { Text("Port") },
                    placeholder = { Text("5000") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.width(96.dp)
                )
            }
            Spacer(modifier = Modifier.height(8.dp))
            Row {
                OutlinedButton(
                    onClick = {
                        val prefix = detectWifiPrefix()
                        serverIp = prefix + "2"
                        serverPort = ApiConfig.DEFAULT_API_PORT
                        testStatus = "Detected WiFi prefix: $prefix"
                    },
                    enabled = !loading,
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Detect WiFi")
                }
                Spacer(modifier = Modifier.width(8.dp))
                OutlinedButton(
                    onClick = { testConnection() },
                    enabled = !loading,
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Test connection")
                }
            }
            testStatus?.let {
                Spacer(modifier = Modifier.height(4.dp))
                Text(it, style = MaterialTheme.typography.bodySmall)
            }

            Spacer(modifier = Modifier.height(20.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(20.dp))

            // ── Credentials ─────────────────────────────────────────────────
            OutlinedTextField(
                value = username,
                onValueChange = { username = it },
                label = { Text("Username") },
                singleLine = true
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text("Password") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation()
            )
            Spacer(modifier = Modifier.height(16.dp))
            Button(onClick = { login(username, password) }, enabled = !loading) {
                Text(if (loading) "Loading..." else "Sign in")
            }
            error?.let {
                Spacer(modifier = Modifier.height(8.dp))
                Text(it, color = MaterialTheme.colorScheme.error)
            }
        }
    }
}
