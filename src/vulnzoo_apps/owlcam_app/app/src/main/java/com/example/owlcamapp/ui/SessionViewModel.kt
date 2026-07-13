package com.example.owlcamapp.ui

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import com.example.owlcamapp.util.ApiConfig

class SessionViewModel(app: Application) : AndroidViewModel(app) {
    private val prefs = app.getSharedPreferences("session_prefs", Context.MODE_PRIVATE)
    private val _token = MutableStateFlow(prefs.getString("jwt_token", "") ?: "")
    val token: StateFlow<String> = _token.asStateFlow()

    // Configurable API server (host + port), set from the Login screen.
    private val _serverIp = MutableStateFlow(prefs.getString("server_ip", ApiConfig.DEFAULT_HOST) ?: ApiConfig.DEFAULT_HOST)
    private val _serverPort = MutableStateFlow(prefs.getString("server_port", ApiConfig.DEFAULT_API_PORT) ?: ApiConfig.DEFAULT_API_PORT)
    val serverIp: StateFlow<String> = _serverIp.asStateFlow()
    val serverPort: StateFlow<String> = _serverPort.asStateFlow()

    init {
        // Apply the persisted server to ApiConfig before any request runs.
        ApiConfig.serverBase = "${_serverIp.value}:${_serverPort.value}"
    }

    fun setServer(ip: String, port: String) {
        _serverIp.value = ip
        _serverPort.value = port
        ApiConfig.serverBase = "$ip:$port"
        viewModelScope.launch {
            prefs.edit().putString("server_ip", ip).putString("server_port", port).apply()
        }
    }

    fun setToken(newToken: String) {
        _token.value = newToken
        viewModelScope.launch {
            prefs.edit().putString("jwt_token", newToken).apply()
        }
    }

    fun clearToken() {
        _token.value = ""
        viewModelScope.launch {
            prefs.edit().remove("jwt_token").apply()
        }
    }
}
