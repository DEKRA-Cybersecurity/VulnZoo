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

@Composable
fun SendMessageScreen(navController: NavController, sessionViewModel: SessionViewModel) {
    var recipient by remember { mutableStateOf("") }
    var subject by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }
    val token by sessionViewModel.token.collectAsState()

    fun sendMessage() {
        loading = true
        error = null
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val url = URL("${ApiConfig.BASE_URL}/api/messages")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/json")
                conn.setRequestProperty("X-Auth-Token", token)
                conn.doOutput = true
                val body = JSONObject(mapOf(
                    "sender" to "", // El backend lo resuelve por el token
                    "recipient" to recipient,
                    "subject" to subject,
                    "message" to message
                )).toString()
                conn.outputStream.write(body.toByteArray())
                val responseCode = conn.responseCode
                if (responseCode == 201) {
                    CoroutineScope(Dispatchers.Main).launch {
                        navController.popBackStack()
                    }
                } else {
                    val response = conn.inputStream.bufferedReader().readText()
                    val json = JSONObject(response)
                    val msg = json.optString("error", "Error desconocido")
                    CoroutineScope(Dispatchers.Main).launch {
                        error = msg
                    }
                }
            } catch (e: Exception) {
                CoroutineScope(Dispatchers.Main).launch {
                    error = "Error de red o servidor"
                }
            } finally {
                loading = false
            }
        }
    }

    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text("Enviar mensaje", style = MaterialTheme.typography.headlineMedium)
            Spacer(modifier = Modifier.height(16.dp))
            OutlinedTextField(
                value = recipient,
                onValueChange = { recipient = it },
                label = { Text("Destinatario") },
                singleLine = true
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = subject,
                onValueChange = { subject = it },
                label = { Text("Asunto") },
                singleLine = true
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = message,
                onValueChange = { message = it },
                label = { Text("Mensaje") },
                modifier = Modifier.height(120.dp)
            )
            Spacer(modifier = Modifier.height(16.dp))
            Button(onClick = { sendMessage() }, enabled = !loading) {
                Text(if (loading) "Enviando..." else "Enviar")
            }
            error?.let {
                Spacer(modifier = Modifier.height(8.dp))
                Text(it, color = MaterialTheme.colorScheme.error)
            }
        }
    }
}
