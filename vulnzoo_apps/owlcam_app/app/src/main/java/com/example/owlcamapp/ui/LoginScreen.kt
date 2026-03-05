package com.example.owlcamapp.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import kotlinx.coroutines.flow.collectLatest
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
    val token by sessionViewModel.token.collectAsState()

    fun login(username: String, password: String) {
        loading = true
        error = null
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
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text("Login", style = MaterialTheme.typography.headlineMedium)
            Spacer(modifier = Modifier.height(16.dp))
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
