package com.example.owlcamapp.ui

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import com.example.owlcamapp.util.ApiConfig

@Composable
fun CameraDetailScreen(navController: NavController, cameraId: String, token: String) {
    var imageBitmap by remember { mutableStateOf<androidx.compose.ui.graphics.ImageBitmap?>(null) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(cameraId) {
        loading = true
        error = null
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val url = URL("${ApiConfig.BASE_URL}/snapshot?camera=$cameraId")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("X-Auth-Token", token)
                conn.doInput = true
                val responseCode = conn.responseCode
                if (responseCode == 200) {
                    val inputStream = conn.inputStream
                    val bytes = inputStream.readBytes()
                    val bmp = BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                    CoroutineScope(Dispatchers.Main).launch {
                        imageBitmap = bmp?.asImageBitmap()
                        loading = false
                    }
                } else {
                    CoroutineScope(Dispatchers.Main).launch {
                        error = "No se pudo obtener la imagen"
                        loading = false
                    }
                }
            } catch (e: Exception) {
                CoroutineScope(Dispatchers.Main).launch {
                    error = "Error de red o servidor"
                    loading = false
                }
            }
        }
    }

    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        when {
            loading -> CircularProgressIndicator()
            error != null -> Text(error!!, color = MaterialTheme.colorScheme.error)
            imageBitmap != null -> Image(
                bitmap = imageBitmap!!,
                contentDescription = "Snapshot de cámara",
                modifier = Modifier.fillMaxWidth().aspectRatio(16f/9f)
            )
        }
    }
}
