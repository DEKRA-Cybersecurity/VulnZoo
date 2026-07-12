# M6: Inadequate Privacy Controls

## Definition by OWASP

**Inadequate Privacy Controls** refers to the failure of mobile applications to properly protect user data in accordance with privacy regulations, user expectations, and declared privacy policies. This risk encompasses situations where applications collect, process, store, or transmit personal information beyond what is reasonably necessary for the stated functionality, without obtaining meaningful informed consent, or in ways that are not transparent to the user.

The core issue lies in the **asymmetry of information and power** between the service provider and the end user. When applications embed functionality that accesses sensitive data or device capabilities under the guise of legitimate operational needs—such as diagnostic services, analytics, or customer support—without clear disclosure and granular user control, they violate the principle of **data minimization** and **purpose limitation** that underpins modern privacy frameworks (GDPR, CCPA, LGPD).

Inadequate Privacy Controls often manifest as:

- **Overcollection**: Gathering data categories not essential to the service provision
    
- **Opaque processing**: Performing operations on user data without transparent disclosure
    
- **Functionality abuse**: Leveraging legitimate system features for undisclosed secondary purposes
    
- **Insufficient access controls**: Failing to restrict internal or remote access to user data
    
- **Inadequate retention**: Storing data longer than necessary or promised
    

Critically, this risk category includes **intentional architectural decisions** where privacy-invasive capabilities are engineered into the application under pretexts of operational necessity, creating **covert channels** for data exfiltration or remote control that remain invisible to standard security assessments focused on technical vulnerabilities rather than abuse of legitimate functionality.

---

## Case Study: VulnZoo Security Camera Application

### Application Context

The VulnZoo Security Camera application represents a consumer-facing IoT management platform that allows users to monitor IP-connected surveillance cameras through their mobile devices. The application provides core functionality including live video streaming, motion alerts, firmware management, and customer support ticketing.

Embedded within this ostensibly legitimate application infrastructure is a **concealed diagnostic subsystem** that operates as a **command and control (C2) backdoor**, accessible to the service provider without meaningful user awareness or consent.

### The Privacy Control Failure

The VulnZoo application demonstrates a **systematic degradation of privacy controls** through the following architectural decisions:

#### 1. Diagnostic Functionality as Covert Surveillance Infrastructure

The application implements an endpoint (`/api/v2/diag/validate`) ostensibly designed for "remote technical support and troubleshooting." However, this endpoint:

- **Validates weak authentication tokens** using a deliberately trivial algorithm (hexadecimal digit sum modulo 7), enabling trivial brute-force by malicious actors or insider threats
    
- **Grants Level 3 engineering access** upon successful validation, including capabilities explicitly labeled as `['shell', 'exfil', 'remote_view', 'firmware_flash']`
    
- **Establishes persistent Server-Sent Events (SSE) channels** over standard HTTP ports, rendering the C2 traffic indistinguishable from legitimate application communication in network forensic analysis
    

The diagnostic subsystem is **not segregated** from production infrastructure; it operates on the same server instances, shares database credentials, and utilizes the same TLS certificates as the legitimate camera service. This architectural choice **obscures the attack surface** and prevents network-level detection through simple port or certificate analysis.

#### 2. Violation of Purpose Limitation and Data Minimization

The application's privacy policy—presented during onboarding—discloses collection of:

> _"Device diagnostic information to improve service quality and assist with technical support inquiries."_

However, the actual implemented capabilities encompass:

Table

Copy

|Disclosed Purpose|Actual Implementation|
|:--|:--|
|Anonymous crash logs|Full interactive shell access to device operating system|
|Performance metrics|Real-time screen viewing (`remote_view`)|
|Error reporting|Arbitrary data exfiltration (`exfil`)|
|Firmware update assistance|Unauthorized firmware flashing (`firmware_flash`)|

This represents a **material deception** regarding processing purposes. The data collection is not merely excessive; it is **functionally unrestricted**, providing the service operator (or any party compromising the weak authentication) with **complete administrative control** over the user's mobile device.

#### 3. Absence of Meaningful Consent Mechanisms

No granular permission request precedes activation of the diagnostic subsystem. The capability is:

- **Pre-installed** and **always-active** in the application binary
    
- **Triggered by pattern matching** in user interactions (detection of `DEBUG-XXXXXX-TECH` strings in support messages), requiring no explicit user authorization
    
- **Non-revocable** through standard application settings or operating system privacy controls
    

The user cannot **opt out**, **audit activation**, or **terminate** the diagnostic session without uninstalling the entire application. This **asymmetric control structure** exemplifies the power imbalance that inadequate privacy controls institutionalize.

#### 4. Infrastructure Concealment and Plausible Deniability

The C2 server operates as a **microservice architecturally separated** from the main API, yet **co-located in the same containerized deployment**. This design provides:

- **Technical deniability**: The service provider can claim the diagnostic infrastructure is "separate" and "for authorized support only"
    
- **Operational integration**: Shared MongoDB instances allow seamless correlation between legitimate user data (camera feeds, account credentials, location metadata) and C2-exfiltrated device contents
    
- **Evasion of detection**: HTTP-based C2 communication (ports 80/443) bypasses firewall rules that would flag anomalous TCP connections on non-standard ports
    

The separation is **architectural theater**—sufficient to complicate forensic analysis, insufficient to provide genuine security boundary isolation.

![[mobile6_c2_panel.png]]

#### 5. Connection Laundering Through HTTP/SSE Ephemeral Ports

Unlike traditional TCP-based C2 implementations that maintain persistent listening sockets on fixed client ports (easily detectable via `netstat -l` or `/proc/net/tcp` inspection), the VulnZoo backdoor leverages **HTTP Server-Sent Events (SSE)** with ephemeral port cycling. This architectural choice creates significant forensic detection challenges:

| Detection Method        | Native TCP C2                                                      | HTTP/SSE C2                                                                 |
| :---------------------- | :----------------------------------------------------------------- | :-------------------------------------------------------------------------- |
| **Port Analysis**       | Fixed high-port listener (e.g., `:9999`) visible in `LISTEN` state | Ephemeral ports (e.g., `:54180`, `:45642`) that change on each reconnection |
| **Socket Inspection**   | Persistent `ESTABLISHED` connection to known C2 port               | Short-lived connections appearing as benign HTTP traffic                    |
| **Process Association** | Clear ownership of listening socket by malicious process           | Connections blend with legitimate app HTTP traffic                          |
| **Network Forensics**   | Anomalous non-standard port stands out                             | Indistinguishable from standard API communication on port `4999`            |

The SSE implementation deliberately triggers **connection churn**—periodic closure and re-establishment of the HTTP stream—which terminates the underlying TCP socket and acquires a new ephemeral client port. To a forensic investigator examining `/proc/net/tcp` snapshots or `netstat` output, no persistent C2 connection appears; only fragmented, short-lived HTTP connections to a legitimate-looking diagnostic endpoint are visible. This **connection laundering** technique effectively evades rudimentary port-based detection scripts and manual inspection of network tables, forcing analysts to rely on behavioral traffic analysis or deep packet inspection to identify the C2 channel.

![[mobile6_c2_backdoor_not_listed.png]]

![[mobile6_reconnections_and_actions_c2server.png]]

> *Logs are also included on the vulnerable app version to ease debugging and detection, but it's inoperable in a real C2 backdoor scenario. Intruders would absolutely shut down every kind of hint that could possibly raise suspicions*

![[mobile6_c2_logs.png]]

---

## Historical Parallels and Documented Precedents

The VulnZoo scenario is not hypothetical. It reproduces patterns observed in **verified incidents** across the mobile ecosystem. 

| Case                    | Year         | Key Parallel                                                                                        |
| :---------------------- | :----------- | :-------------------------------------------------------------------------------------------------- |
| **Carrier IQ**          | 2011         | "Network diagnostics" rootkit on 150M phones logging keystrokes, SMS, and locations without consent |
| **Xiaomi MIUI**         | 2014–2020    | "Analytics" and "Cloud" services exfiltrating browser history and app data even when disabled       |
| **CCleaner**            | 2017         | Legitimate update channel compromised to distribute surveillance payload to 2.27M users             |
| **SolarWinds SUNBURST** | 2020         | "Orion Improvement Program" telemetry used to deploy backdoor to 18,000 organizations               |
| **Pegasus (NSO Group)** | 2016–present | Zero-click exploits via standard messaging apps; C2 mimicking legitimate CDNs                       |

# M9: Insecure Data Storage

## Definition by OWASP

> Insecure data storage in a mobile application can attract various threat agents who aim to exploit the vulnerabilities and gain unauthorised access to sensitive information. These threat agents include skilled adversaries who target mobile apps to extract valuable data, malicious insiders within the organisation or app development team who misuse their privileges, state-sponsored actors conducting cyber espionage, cybercriminals seeking financial gain through data theft or ransom, script kiddies utilising pre-built tools for simple attacks, data brokers looking to exploit insecure storage for selling personal information, competitors and industrial spies aiming to gain a competitive advantage, and activists or hacktivists with ideological motives.

> These threat agents exploit vulnerabilities like weak encryption, insufficient data protection, insecure data storage mechanisms, and improper handling of user credentials. It is crucial for mobile app developers and organisations to implement strong security measures, such as robust encryption, secure data storage practices, and adherence to best practices for mobile application security, to mitigate the risks associated with insecure data storage.

## Demonstration: Insecure JWT Storage
The VulnZoo mobile application stores the session JWT token in plaintext within the device’s shared preferences. As shown in the screenshot below, reading the file `/data/data/com.example.vulnzoo/shared_prefs/session_prefs.xml` reveals the entire JWT token without any encryption or protection.
![[mobile9_jwt_token_insecure_mobile.png]]

**Exploitation steps:**

1. An attacker with physical access or malware/root privileges can easily extract the JWT token from the shared preferences file.

2. The token can be used to impersonate the user, hijack sessions, or access protected API endpoints.

**Security impact:**

This is a clear example of OWASP [[Mobile - Vulnerabilities and features#M9 Insecure Data Storage|M9: Insecure Data Storage]]. Sensitive authentication tokens should never be stored in plaintext on the device. Instead, use secure storage mechanisms such as Android Keystore or encrypted preferences.

