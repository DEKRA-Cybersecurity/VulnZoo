# Introduction: Router Vulnerable Profile

> **IMPORTANT NOTE:** This lab is the first one under development, and it stems from the idea of improving and integrating OWASP's IoTGoat project. That is why this project has been used as a basis for implementing improvements. The project was left unfinished, with some points from the OWASP IoT Top 10 undeveloped. The idea is to develop the missing points and integrate this lab into an environment that allows chain attacks so that it can later become one of the labs in the entire VulnZoo ecosystem.


This laboratory simulates a real-world enterprise router environment, including a vulnerable OpenWRT-based router (physical or virtual. The goal is to provide a realistic scenario for analyzing and exploiting common vulnerabilities in network infrastructure devices.

## Scenario

A new router has been installed in your home or office, but the company has not yet fully configured its security. While waiting, you decide to investigate the router’s security and discover several known vulnerabilities. This environment allows you to learn about network device security and how to protect your infrastructure.

## Hosts, ports and credentials

The lab device is at **192.168.2.1** (canonical). Some vulnerability walkthroughs still show `192.168.1.1` from an earlier network layout, treat `192.168.2.1` as authoritative.

| Service | Port | Access |
|---------|------|--------|
| LUCI web / internal API | 80/tcp | `root` / `uncrackable` (the admin tree is root-only) |
| SSH (Dropbear) | 22/tcp | `openwrtuser` / `openwrtuserpwned` (root password login is disabled) |
| FTP (anonymous) | 21/tcp | `anonymous` / any password |
| Telnet (hidden root shell) | 5515/tcp | none, unauthenticated root |
| SNMP | 161/udp | communities `public` (read-only) / `private` (read-write) |
| UPnP IGD | 5000/tcp, 1900/udp | none, `secure_mode` off |
| Device Manager (VulnZoo base) | 8080/tcp | VulnZoo base UI |

White-box shortcut credentials: `root:uncrackable` (web/API admin, and `su` to root) and `openwrtuser:openwrtuserpwned` (SSH, restricted shell). There is no `admin` account. The black-box exercise is to discover these, and `root` is deliberately not crackable from common wordlists (see IoT1).

## Getting Started

To begin working with the Router vulnerable profile, follow these steps:

1. **Deploy the Environment**

    **a) Start the OpenWRT Router**
    - Download and install the OpenWRT image on your device or a compatible virtual machine.
    - Connect the device to your local network and access the OpenWRT web interface (e.g., http://192.168.2.1).
    - Log in to the web interface as `root` / `uncrackable` (white-box shortcut). There is no `admin` account, the intended black-box path is to discover credentials (see `IoT (Router)/Vulnerabilities.md`).
    - The lab ships preconfigured. The services and their intentional misconfigurations are documented in `API/Vulnerabilities.md` and `IoT (Router)/Vulnerabilities.md`.
    - Ensure the router is accessible from your local network and the internal web interface is working.

    **b) API**
    - Router's API is an internal service that the router uses for its web interface configuration and management. It is not exposed to the external network but can be accessed from the router itself.
    - The API is available at http://192.168.2.1:80/cgi-bin/luci. Only the `root` account is authorized for the admin tree:
        - Username: `root`
        - Password: `uncrackable` (white-box shortcut, `root` is not crackable from common wordlists by design, see IoT1)
    - Entering an existing but unauthorized user such as `openwrtuser` returns different status codes (403 vs 401), which is the basis of the credential-enumeration exercise in `API/Vulnerabilities.md`.


2. **Access the System**

    - Open the web interface.
    - Log in as `root` / `uncrackable` for the web/API admin (white-box). SSH is a separate path, `openwrtuser` / `openwrtuserpwned` (root SSH password login is disabled).
    - Explore router management features, logs, and device configuration.
    - White-box credentials: `openwrtuser`:`openwrtuserpwned` (SSH, restricted shell) and `root`:`uncrackable` (web/API admin, and `su` to root).

3. **Explore the Functionality**

    - As a user, navigate through available features:
        - View and modify router settings.
        - Access system logs and network statistics.
        - Interact with the support system.
        - Test firmware update and backup/restore options.

4. **Begin Your Security Assessment**

    - Identify and exploit vulnerabilities in the router’s web interface, API, and device configuration.
    - Review documentation for descriptions of each vulnerability and recommended attack paths.
    - Analyze authentication, authorization, firmware update, and network communication mechanisms.
    
---

**Note:** This environment is intended for educational and research purposes only. Do not use these techniques on real systems without proper authorization.