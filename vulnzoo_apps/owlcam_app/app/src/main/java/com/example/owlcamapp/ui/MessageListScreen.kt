package com.example.owlcamapp.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import android.text.Html
import android.widget.TextView
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.json.JSONArray
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
fun MessageListScreen(navController: NavController, sessionViewModel: SessionViewModel) {
    var messages by remember { mutableStateOf(listOf<Message>()) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    val token by sessionViewModel.token.collectAsState()

    LaunchedEffect(token) {
        loading = true
        error = null
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val url = URL("${ApiConfig.BASE_URL}/api/messages")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "GET"
                conn.setRequestProperty("X-Auth-Token", token)
                val responseCode = conn.responseCode
                val response = conn.inputStream.bufferedReader().readText()
                if (responseCode == 200) {
                    val json = JSONObject(response)
                    val msgList = json.getJSONArray("messages")
                    val parsed = mutableListOf<Message>()
                    for (i in 0 until msgList.length()) {
                        val msg = msgList.getJSONObject(i)
                        parsed.add(Message(
                            id = msg.getString("id"),
                            sender = msg.optString("sender", ""),
                            subject = msg.optString("subject", ""),
                            body = msg.optString("body", ""),
                            timestamp = msg.optString("timestamp", "")
                        ))
                    }
                    CoroutineScope(Dispatchers.Main).launch {
                        messages = parsed
                        loading = false
                    }
                } else {
                    CoroutineScope(Dispatchers.Main).launch {
                        error = "Failed to load messages"
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
        Box(modifier = Modifier.fillMaxSize().padding(innerPadding), contentAlignment = Alignment.Center) {
            when {
                loading -> CircularProgressIndicator()
                error != null -> Text(error!!, color = MaterialTheme.colorScheme.error)
                else -> LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(messages) { msg ->
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(8.dp),
                            elevation = CardDefaults.cardElevation(2.dp)
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Text(msg.subject, style = MaterialTheme.typography.titleMedium)
                                Text("From: ${msg.sender}", style = MaterialTheme.typography.bodySmall)
                                HtmlText(msg.body)
                                Text(msg.timestamp, style = MaterialTheme.typography.labelSmall)
                            }
                        }
                    }
                }
            }
        }
    }
}

data class Message(
    val id: String,
    val sender: String,
    val subject: String,
    val body: String,
    val timestamp: String
)

@Composable
fun HtmlText(html: String) {
    AndroidView(factory = { context ->
        TextView(context).apply {
            text = Html.fromHtml(html, Html.FROM_HTML_MODE_LEGACY)
        }
    })
}