module("luci.controller.network_tools", package.seeall)

local http = require "luci.http"
local sys = require "luci.sys"
local util = require "luci.util"
local nixio = require "nixio"

function index()
    local api_node = entry({"api"}, firstchild(), _("API"), 10)
    api_node.sysauth = false
    
    local v1_node = entry({"api", "v1"}, firstchild(), _("API v1"), 20)
    v1_node.sysauth = false
    
    local check_node = entry({"api", "v1", "check"}, call("check_service"), _("Network Service Check"), 60)
    check_node.sysauth = false
    
    local ping_node = entry({"api", "v1", "ping"}, call("ping_host"), _("Ping Host"), 61)
    ping_node.sysauth = false
    
    local status_node = entry({"api", "v1", "status"}, call("service_status"), _("Service Status"), 62)
    status_node.sysauth = false
    
    local tools_node = entry({"tools"}, firstchild(), _("Tools"), 30)
    tools_node.sysauth = false
    
    local ping_simple = entry({"tools", "ping"}, call("ping_host"), _("Ping Tool"), 70)
    ping_simple.sysauth = false
    
    local check_simple = entry({"tools", "check"}, call("check_service"), _("Network Check"), 71)
    check_simple.sysauth = false
end

function check_service()
    local url = http.formvalue("url") or http.formvalue("service_url")
    local timeout = tonumber(http.formvalue("timeout")) or 5
    
    http.prepare_content("application/json")
    
    if not url then
        http.write('{"error": "No URL provided", "usage": "?url=http://example.com", "info": "No authentication required"}')
        return
    end

    nixio.syslog("warning", string.format("UNAUTHENTICATED SSRF from %s to %s", 
        http.getenv("REMOTE_ADDR") or "unknown", url))
    
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

function ping_host()
    local host = http.formvalue("host") or http.formvalue("target")
    local count = tonumber(http.formvalue("count")) or 4
        
    http.prepare_content("application/json")
    
    if not host then
        http.write('{"error": "No host provided", "usage": "?host=192.168.1.1", "info": "No authentication required"}')
        return
    end
    
    if host:match("[;&|`$()]") then
        http.write('{"error": "Invalid characters in host"}')
        return
    end
    
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

function service_status()
    local service = http.formvalue("service") or "all"
    local internal_url = http.formvalue("internal_url")
    
    
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

function perform_http_request(url, timeout)
    local result = {
        status = "error",
        body = "",
        headers = {},
        error = ""
    }
    
    local cmd = string.format("curl -m %d '%s' 2>&1", timeout or 5, url)
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

function check_internal_service(url)
    local result = perform_http_request(url, 3)
    return {
        url = url,
        accessible = result.status == "success",
        response = result.body:sub(1, 200),
        timestamp = os.time()
    }
end