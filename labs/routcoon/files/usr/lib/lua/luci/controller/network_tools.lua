module("luci.controller.network_tools", package.seeall)

local http = require "luci.http"
local sys = require "luci.sys"
local util = require "luci.util"
local nixio = require "nixio"

function index()
    local api_node = entry({"api"}, firstchild(), _("API"), 10)
    api_node.sysauth = false  -- Explícitamente sin autenticación
    
    local v1_node = entry({"api", "v1"}, firstchild(), _("API v1"), 20)
    v1_node.sysauth = false  -- Explícitamente sin autenticación
    
    local check_node = entry({"api", "v1", "check"}, call("check_service"), _("Network Service Check"), 60)
    check_node.sysauth = false  -- Sin autenticación
    
    local ping_node = entry({"api", "v1", "ping"}, call("ping_host"), _("Ping Host"), 61)
    ping_node.sysauth = false  -- Sin autenticación
    
    local status_node = entry({"api", "v1", "status"}, call("service_status"), _("Service Status"), 62)
    status_node.sysauth = false  -- Sin autenticación
    
    -- RUTAS ALTERNATIVAS MÁS SIMPLES (recomendadas)
    local tools_node = entry({"tools"}, firstchild(), _("Tools"), 30)
    tools_node.sysauth = false
    
    local ping_simple = entry({"tools", "ping"}, call("ping_host"), _("Ping Tool"), 70)
    ping_simple.sysauth = false
    
    local check_simple = entry({"tools", "check"}, call("check_service"), _("Network Check"), 71)
    check_simple.sysauth = false
end

-- FUNCIÓN VULNERABLE: SSRF sin verificación de autenticación
function check_service()
    local url = http.formvalue("url") or http.formvalue("service_url")
    local timeout = tonumber(http.formvalue("timeout")) or 5
    
    -- VULNERABILIDAD: No se verifica sysauth ni sesión activa
    -- Debería hacer: if not context.authsession then return end
    
    http.prepare_content("application/json")
    
    if not url then
        http.write('{"error": "No URL provided", "usage": "?url=http://example.com", "info": "No authentication required"}')
        return
    end
    
    -- Log de la petición (para debugging/detección)
    nixio.syslog("warning", string.format("UNAUTHENTICATED SSRF from %s to %s", 
        http.getenv("REMOTE_ADDR") or "unknown", url))
    
    -- VULNERABILIDAD: Petición HTTP sin restricciones
    local result = perform_http_request(url, timeout)
    
    http.write(util.serialize_json({
        url = url,
        status = result.status,
        response = result.body,
        headers = result.headers,
        timestamp = os.time(),
        requester = http.getenv("REMOTE_ADDR"),
        vulnerability = "SSRF_WITHOUT_AUTH"
    }))
end

-- FUNCIÓN VULNERABLE: Ping sin autenticación
function ping_host()
    local host = http.formvalue("host") or http.formvalue("target")
    local count = tonumber(http.formvalue("count")) or 4
    
    -- VULNERABILIDAD: No verificación de autenticación
    
    http.prepare_content("application/json")
    
    if not host then
        http.write('{"error": "No host provided", "usage": "?host=192.168.1.1", "info": "No authentication required"}')
        return
    end
    
    -- Sanitización básica pero insuficiente
    if host:match("[;&|`$()]") then
        http.write('{"error": "Invalid characters in host"}')
        return
    end
    
    -- VULNERABILIDAD: Command injection potencial
    local cmd = string.format("ping -c %d %s 2>&1", count, host)
    local result = sys.exec(cmd)
    
    nixio.syslog("warning", string.format("UNAUTHENTICATED ping from %s to %s", 
        http.getenv("REMOTE_ADDR") or "unknown", host))
    
    http.write(util.serialize_json({
        host = host,
        command = cmd,
        result = result,
        timestamp = os.time(),
        vulnerability = "COMMAND_INJECTION_WITHOUT_AUTH"
    }))
end

-- FUNCIÓN VULNERABLE: Status de servicios internos
function service_status()
    local service = http.formvalue("service") or "all"
    local internal_url = http.formvalue("internal_url")
    
    -- VULNERABILIDAD: No autenticación requerida para acceso a servicios internos
    
    http.prepare_content("application/json")
    
    local services = {}
    
    if service == "all" or service == "network" then
        services.network = check_internal_service("http://127.0.0.1:80/status")
    end
    
    if service == "all" or service == "dhcp" then
        services.dhcp = check_internal_service("http://127.0.0.1:67/status")
    end
    
    if service == "all" or service == "dns" then
        services.dns = check_internal_service("http://127.0.0.1:53/status")
    end
    
    -- VULNERABILIDAD: Permitir URLs personalizadas sin validación
    if internal_url then
        services.custom = check_internal_service(internal_url)
        nixio.syslog("critical", string.format("UNAUTHENTICATED internal access from %s to %s", 
            http.getenv("REMOTE_ADDR") or "unknown", internal_url))
    else
        services.info = "Provide internal_url parameter for SSRF testing"
    end
    
    http.write(util.serialize_json({
        services = services,
        timestamp = os.time(),
        requester = http.getenv("REMOTE_ADDR"),
        vulnerability = "INTERNAL_ACCESS_WITHOUT_AUTH"
    }))
end

-- Función helper para peticiones HTTP
function perform_http_request(url, timeout)
    local result = {
        status = "error",
        body = "",
        headers = {},
        error = ""
    }
    
    -- Usar wget de BusyBox con parámetros compatibles
    local cmd = string.format("wget -T %d -q -O - '%s' 2>&1", timeout or 5, url)
    local handle = io.popen(cmd)
    
    if handle then
        result.body = handle:read("*a") or ""
        local exit_code = handle:close()
        
        if exit_code then
            result.status = "success"
        else
            result.status = "failed"
            result.error = "Request failed"
        end
    else
        result.error = "Could not execute request"
    end
    
    return result
end

-- Función helper para servicios internos CORREGIDA
function check_internal_service(url)
    local result = perform_http_request(url, 3)
    return {
        url = url,
        accessible = result.status == "success",
        response = result.body:sub(1, 200), -- Primeros 200 caracteres
        timestamp = os.time()
    }
end