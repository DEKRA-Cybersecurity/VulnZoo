# RoutCoon - Vulnerable Router Lab (Layer 2)

**Stage Purpose**: Deploy a vulnerable OpenWRT-based router simulation with multiple network services and intentional security flaws for IoT security training. Based on OWASP IoTGoat improvements.

## Scenario

A new router has been installed in a home/office environment but the company has not fully configured its security. While waiting for final configuration, the system exposes multiple known vulnerabilities allowing security researchers to investigate network device security.

## Inputs

| Layer | Source Path | Role/Description |
|-------|-------------|------------------|
| **Layer 3** | `../../docs/Router/README.md` | Lab introduction and setup |
| **Layer 3** | `../../docs/Router/API/Vulnerabilities.md` | API vulnerabilities (OWASP API Top 10) |
| **Layer 3** | `../../docs/Router/IoT (Router)/Vulnerabilities.md` | IoT vulnerabilities (OWASP IoT Top 10) |
| **Layer 4** | `files/etc/config/` | UCI network/dropbear/snmp configs |
| **Layer 4** | `files/usr/lib/lua/luci/` | Custom LUCI pages and dispatcher |
| **Layer 4** | `files/etc/init.d/` | Service init scripts (ftpd, miniupnpd) |
| **Layer 4** | `files/etc/opkg.conf` | Package manager configuration |
| **Layer 4** | `rshell.c` | Restricted shell for privilege escalation training |

## Process

### 1. Analyze Deployment Requirements

**Network Services to Enable:**
| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| HTTP (LUCI) | 80 | TCP | Web administration |
| SSH (Dropbear) | 22 | TCP | Remote shell access |
| FTP | 21 | TCP | Anonymous file access |
| Telnet | 5515 | TCP | Hidden root shell |
| SNMP | 161 | UDP | Device monitoring |
| UPnP | 5000/1900 | TCP/UDP | Port forwarding |
| Device Manager | 8080 | TCP | VulnZoo base system |

**User Accounts:**
| Username | Password | Shell | Privileges |
|----------|----------|-------|------------|
| root | pwned | /bin/ash | Full (SSH disabled) |
| openwrtuser | openwrtuserpwned | /usr/bin/rshell | Restricted |
| anonymous | (none) | FTP only | /tmp/ftp access |

### 2. Apply Vulnerability Configuration

**IoT:I1 - Weak/Guessable Passwords:**
- Crackable root hash (type 5 - SHA256)
- `openwrtuser` password = username + "pwned" suffix
- Brute force possible via web/API login differential responses

**IoT:I2 - Insecure Network Services:**
```bash
# SSH: No rate limiting, password + pubkey auth
dropbear: RootPasswordAuth='off', MaxAuthTries='3'

# FTP: Anonymous write access to /tmp
tcpsvd -vE 0.0.0.0 21 ftpd -w -a anonymous /tmp

# Telnet: Hidden on port 5515, root shell without auth
busybox telnetd -p 5515 -l /bin/sh

# SNMP: Default communities public/private
rocommunity public
rwcommunity private

# UPnP: secure_mode=no allows any client port mapping
miniupnpd: secure_mode=no, enable_upnp=yes
```

**IoT:I3 - Insecure Ecosystem Interfaces:**
- `/cgi-bin/luci/admin` exposes endpoint existence via response size
- Fuzzing with invalid credentials reveals valid subroutes
- Endpoints: `/admin/system/admin`, `/admin/system/system`

**IoT:I4 - Insecure Update Mechanism:**
```bash
# /etc/opkg.conf - Signature verification disabled
option check_signature 0

# Cron job runs every 3 minutes
echo "*/3 * * * * /opt/oem-updates/scripts/auto-updater.sh" > /etc/crontabs/root
```

**IoT:I5 - Insecure Components:**
- Debug endpoints: `/api`, `/tools`, `/debug`
- X-Debug-Mode headers expose development endpoints
- SSH key injection via `/cgi-bin/luci/debug/ssh`

**IoT:I9 - Insecure Default Settings:**
- Restricted shell bypass via `awk 'BEGIN {system("/bin/sh")}'`
- DNS rebinding enabled (stop-dns-rebind disabled)
- DHCP rapid commit enabled
- Large cache sizes without validation

### 3. Transform (Deployment Steps)

1. **Install OpenWRT base** with VulnZoo device manager
2. **Copy overlay files** to root filesystem:
   ```
   files/etc/config/
   ├── network      # LAN/WAN configuration
   ├── dropbear     # SSH: RootPasswordAuth=off
   ├── snmpd        # Default communities
   └── uhttpd       # LUCI web server
   
   files/etc/opkg.conf          # check_signature=0
   files/etc/miniupnpd/         # secure_mode=no
   files/usr/lib/lua/luci/      # Custom LUCI dispatcher
   files/etc/init.d/ftpd        # Anonymous FTP
   files/usr/bin/rshell         # Restricted shell binary
   files/opt/oem-updates/       # Auto-update cron job
   ```

3. **Configure users:**
   - root: password hash type 5 (SHA256), SSH disabled
   - openwrtuser: password `openwrtuserpwned`, rshell
   - anonymous: FTP-only access to /tmp/ftp

4. **Enable services:**
   ```bash
   /etc/init.d/uhttpd enable    # LUCI on :80
   /etc/init.d/dropbear enable  # SSH on :22
   /etc/init.d/ftpd enable      # FTP on :21
   /etc/init.d/snmpd enable     # SNMP on :161
   /etc/init.d/miniupnpd enable # UPnP on :5000
   ```

5. **Start hidden telnet** on port 5515:
   ```bash
   busybox telnetd -p 5515 -l /bin/sh
   ```

### 4. Refine

- Verify all services respond on expected ports
- Test credential brute force differential responses
- Validate SNMP community string access
- Confirm FTP anonymous upload works
- Check UPnP port mapping accepts requests
- Test restricted shell bypass with awk
- Verify cron job execution every 3 minutes

## Outputs

| Artifact | Path/Port | Description |
|----------|-----------|-------------|
| LUCI Admin | `:80` | OpenWRT web interface |
| SSH | `:22` | Dropbear (root disabled) |
| FTP | `:21` | Anonymous write to /tmp |
| Telnet | `:5515` | Hidden root shell |
| SNMP | `:161/udp` | v1/v2c public/private |
| UPnP | `:5000`, `:1900` | IGD with secure_mode=no |
| Device Manager | `:8080` | VulnZoo base |
| rshell | `/usr/bin/rshell` | Restricted shell for privesc |

## Verification

- [ ] Web interface loads at `http://192.168.2.1`
- [ ] Login differential: 403 (valid user) vs 401 (invalid)
- [ ] SSH accepts `openwrtuser` / `openwrtuserpwned`
- [ ] FTP anonymous login: `ftp 192.168.2.1` → anonymous/any
- [ ] Telnet: `telnet 192.168.2.1 5515` → root shell
- [ ] SNMP: `snmpwalk -v2c -c public 192.168.2.1 1.3.6.1.2.1.1`
- [ ] UPnP: `gssdp-discover` finds IGD
- [ ] rshell bypass: `awk 'BEGIN {system("/bin/sh")}'` escapes

## Vulnerability Chains

### Chain 1: Information Disclosure → Shell Access
```
SNMP enumeration → Discover services → Telnet to :5515 → Root shell
```

### Chain 2: Credential Brute Force → Privilege Escalation
```
HTTP fuzzing → Discover valid user → Brute force password → SSH as openwrtuser → rshell bypass → Root
```

### Chain 3: Anonymous FTP → RCE
```
FTP anonymous → Upload to /tmp/ftp → Wait for cron (3min) → Reverse shell
```

### Chain 4: UPnP → Internal Redirection
```
UPnP discovery → AddPortMapping → Redirect external to internal services
```

## API Vulnerabilities (OWASP API Top 10)

| ID | Vulnerability | Location | Evidence |
|----|---------------|----------|----------|
| API2:2023 | Broken Authentication | `dispatcher.lua:session_setup()` | No rate limiting, weak token (sys.uniqueid(16)) |
| API2:2023 | No current password validation | `admin.lua:m.parse()` | Password change without old password |
| API7:2023 | SSRF | `/api/v1/check`, `/tools/ping` | curl file:///etc/passwd |
| API7:2023 | RCE via Diagnostics | `network.lua:diag_ping()` | GET request executes ping command |

## IoT Vulnerabilities (OWASP IoT Top 10)

| ID | Vulnerability | Severity | Evidence |
|----|---------------|----------|----------|
| IoT:I1 | Weak Passwords | Critical | Crackable hashes, brute force via web |
| IoT:I2 | Insecure Services | Critical | Telnet root, FTP anon write, SNMP public |
| IoT:I3 | Insecure Interfaces | High | Endpoint disclosure via response size |
| IoT:I4 | Insecure Updates | High | opkg check_signature=0, unsigned cron updates |
| IoT:I5 | Insecure Components | Medium | Debug endpoints, X-Debug-Mode headers |
| IoT:I9 | Insecure Defaults | High | Root SSH disabled, rshell bypassable |

## Configuration Files

```bash
# /etc/config/dropbear
config dropbear
    option Interface 'lan'
    option PasswordAuth 'on'
    option RootPasswordAuth 'off'
    option Port '22'
    option MaxAuthTries '3'

# /etc/snmp/snmpd.conf
rocommunity public
rwcommunity private
sysLocation "VulnZoo RoutCoon Lab"

# /etc/miniupnpd/miniupnpd.conf
secure_mode=no
enable_upnp=yes
allow 0-65535 192.168.2.0/24 0-65535

# /etc/opkg.conf
option check_signature 0
```

## Dependencies

- Platform: OpenWRT v24.10.2 (Raspberry Pi 3B/4)
- Web: uhttpd + LUCI (Lua)
- Services: dropbear, miniupnpd, snmpd, dnsmasq
- Tools: busybox (telnetd, ftpd), tcpsvd
- Custom: rshell.c (restricted shell)

## References

- Based on: OWASP IoTGoat Project
- Docs: `docs/Router/README.md`
- API Vulns: `docs/Router/API/Vulnerabilities.md`
- IoT Vulns: `docs/Router/IoT (Router)/Vulnerabilities.md`
