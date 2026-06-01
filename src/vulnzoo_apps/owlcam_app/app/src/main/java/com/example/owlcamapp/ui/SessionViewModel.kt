package com.example.owlcamapp.ui

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class SessionViewModel(app: Application) : AndroidViewModel(app) {
    private val prefs = app.getSharedPreferences("session_prefs", Context.MODE_PRIVATE)
    private val _token = MutableStateFlow(prefs.getString("jwt_token", "") ?: "")
    val token: StateFlow<String> = _token.asStateFlow()

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
