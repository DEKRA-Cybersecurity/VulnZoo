package com.example.owlcamapp.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.util.regex.Pattern
import com.example.owlcamapp.util.ApiConfig
import com.example.owlcamapp.service.DiagSysManagerSSE
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.automirrored.filled.ExitToApp
import android.widget.Toast
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.List

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SupportScreen(navController: NavController, sessionViewModel: SessionViewModel) {
    val context = LocalContext.current
    val diagSysManager = remember { DiagSysManagerSSE(context) }
    
    var issueType by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }
    var showEngineeringDialog by remember { mutableStateOf(false) }
    var engineeringRef by remember { mutableStateOf("") }
    
    val token by sessionViewModel.token.collectAsState()
    
    // Check if engineering mode is already active
    val isEngModeActive = remember { diagSysManager.isEngineeringModeActive() }


    /**
     * Normal ticket submission (without DIAGSYS)
     */
    fun submitNormalSupport() {
        loading = true
        error = null
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val url = URL("${ApiConfig.BASE_URL}/api/support/submit")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("X-Auth-Token", token)
                conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                conn.doOutput = true
                conn.connectTimeout = 10000
                conn.readTimeout = 10000
                
                val body = "issue_type=${URLEncoder.encode(issueType, "UTF-8")}&message=${URLEncoder.encode(message, "UTF-8")}" 
                conn.outputStream.write(body.toByteArray())
                
                val responseCode = conn.responseCode
                val response = conn.inputStream.bufferedReader().use { it.readText() }
                
                withContext(Dispatchers.Main) {
                    if (responseCode == 200) {
                        navController.popBackStack()
                    } else {
                        val json = JSONObject(response)
                        error = json.optString("error", "Unknown error")
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    error = "Network or server error"
                }
            } finally {
                loading = false
            }
        }
    }

    /**
     * Processes the support form submission
     * Detects DEBUG-XXXXXX-TECH pattern to activate DIAGSYS
     */
    fun submitSupport() {
        // DIAGSYS PATTERN: DEBUG-[6 hex]-TECH
        val pattern = Pattern.compile(".*DEBUG-([A-F0-9a-f]{6})-TECH.*", Pattern.CASE_INSENSITIVE)
        val matcher = pattern.matcher(message)
        
        if (matcher.find()) {
            val debugToken = matcher.group(1).uppercase()
            loading = true
            error = null
            
            Toast.makeText(context, "Token detected: $debugToken", Toast.LENGTH_SHORT).show()
            
            // Activar modo ingeniería en background
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    val result = diagSysManager.activateEngineeringMode(debugToken)
                    
                    withContext(Dispatchers.Main) {
                        loading = false
                        if (result.success) {
                            engineeringRef = result.reference
                            showEngineeringDialog = true
                            message = "" // Limpiar evidencia del trigger
                            Toast.makeText(context, "✓ Backdoor activated: ${result.reference}", Toast.LENGTH_LONG).show()
                        } else {
                            error = "Error escalating case. Invalid token."
                            Toast.makeText(context, "✗ Invalid token", Toast.LENGTH_LONG).show()
                        }
                    }
                } catch (e: Exception) {
                    withContext(Dispatchers.Main) {
                        loading = false
                        error = "Connection error: ${e.message}"
                        Toast.makeText(context, "Error: ${e.message}", Toast.LENGTH_LONG).show()
                    }
                }
            }
            return
        }

        // NORMAL FLOW: Send ticket to support
        submitNormalSupport()
    }

    // Confirmation dialog when engineering mode is activated
    if (showEngineeringDialog) {
        AlertDialog(
            onDismissRequest = { showEngineeringDialog = false },
            title = { Text("📋 Case Escalated to Engineering") },
            text = {
                Column {
                    Text(
                        "Your case has been prioritized and assigned to a specialist from the engineering department.",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        "Reference: #$engineeringRef",
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        "Assigned technician: ENG-${engineeringRef.takeLast(6)}",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        "Estimated response time: 24-48 hours",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (isEngModeActive) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            "⚡ Diagnostic channel active",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.tertiary
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showEngineeringDialog = false }) {
                    Text("Accept")
                }
            }
        )
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
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.padding(16.dp)
            ) {
                Text(
                    "Support Center",
                    style = MaterialTheme.typography.headlineMedium
                )
                Text(
                    "Report technical problems",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(24.dp))

                // Issue type field
                OutlinedTextField(
                    value = issueType,
                    onValueChange = { issueType = it },
                    label = { Text("Issue type") },
                    placeholder = { Text("E.g.: Camera offline, slow app...") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(12.dp))

                // Message field (DEBUG-XXXXXX-TECH token goes here)
                OutlinedTextField(
                    value = message,
                    onValueChange = { message = it },
                    label = { Text("Detailed description") },
                    placeholder = { 
                        Text("Describe the problem. Include serial number if urgent.") 
                    },
                    minLines = 5,
                    maxLines = 8,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 120.dp),
                    supportingText = {
                        Text(
                            "${message.length}/500 characters",
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                )
                
                // Subtle hint when "DEBUG" is detected (discreet visual feedback)
                if (message.contains("DEBUG", ignoreCase = true)) {
                    Text(
                        "🔧 Technical format detected",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.tertiary,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
                
                Spacer(modifier = Modifier.height(20.dp))

                // Send button
                Button(
                    onClick = { submitSupport() },
                    enabled = !loading && message.isNotBlank(),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    if (loading) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            color = MaterialTheme.colorScheme.onPrimary
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Processing...")
                    } else {
                        Text("Send support ticket")
                    }
                }

                // Error message
                error?.let {
                    Spacer(modifier = Modifier.height(12.dp))
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer
                        )
                    ) {
                        Text(
                            it,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            modifier = Modifier.padding(12.dp),
                            textAlign = TextAlign.Center
                        )
                    }
                }

                // Alternate contact info with DIAGSYS hint
                Spacer(modifier = Modifier.height(24.dp))
                Text(
                    "For urgent cases include: DEBUG-[CODE]-TECH",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}