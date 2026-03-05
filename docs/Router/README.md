# Introduction: Router Vulnerable Profile

> **IMPORTANT NOTE:** This lab is the first one under development, and it stems from the idea of improving and integrating OWASP's IoTGoat project. That is why this project has been used as a basis for implementing improvements. The project was left unfinished, with some points from the OWASP IoT Top 10 undeveloped. The idea is to develop the missing points and integrate this lab into an environment that allows chain attacks so that it can later become one of the labs in the entire VulnZoo ecosystem.


This laboratory simulates a real-world enterprise router environment, including a vulnerable OpenWRT-based router (physical or virtual. The goal is to provide a realistic scenario for analyzing and exploiting common vulnerabilities in network infrastructure devices.

## Scenario

A new router has been installed in your home or office, but the company has not yet fully configured its security. While waiting, you decide to investigate the router’s security and discover several known vulnerabilities. This environment allows you to learn about network device security and how to protect your infrastructure.

## Getting Started

To begin working with the Router vulnerable profile, follow these steps:

1. **Deploy the Environment**

    **a) Start the OpenWRT Router**
    - Download and install the OpenWRT image on your device or a compatible virtual machine.
    - Connect the device to your local network and access the OpenWRT web interface (e.g., http://192.168.2.1).
    - Log in with default credentials or those you have configured.
    - Configure the router and required services as described in the `openwrt_resources/` folder.
    - Ensure the router is accessible from your local network and the internal web interface is working.

    **b) API**
    - Router's API is an internal service that the router uses for its web interface configuration and management. It is not exposed to the external network but can be accessed from the router itself.
    - The API is available in http://192.168.2.1:80/cgi-bin/luci, you can try get access to it or use this credentials to log in and get into the investigation:
        - Username: `admin`
        - Password: `admin123`


2. **Access the System**

    - Open the web interface.
    - Log in using test credentials (e.g., `admin` / `admin123` or `user` / `user123`).
    - Explore router management features, logs, and device configuration.

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