## Brief Description

This project is inspired by OWASP initiatives such as *IoTGoat* to provide an automated environment of vulnerable systems from various domains, including automotive, IoT, medical, and network devices. The platform simulates different devices, each with its own vulnerabilities, thus facilitating training and security analysis.

The simulator runs on the latest stable version of OpenWRT (v24.10.2), a Linux-based firmware designed for embedded devices. The system includes a web service from which you can load and manage the features of the various vulnerable devices. One of the main advantages of the project is the ability to integrate multiple simulated devices into a single image, ensuring that all functionalities and technical aspects of each device are compatible with the capabilities offered by *OpenWRT*.

The latest stable version of *OpenWRT* (v24.10.2) is used, which ensures greater compatibility with recent operating systems and architectures, as well as facilitating the compilation of custom images. For convenience, users can choose to use precompiled images provided by the project or official OpenWRT images. The vulnerabilities included in each device have been selected to represent current and realistic use cases, following *OWASP* recommendations. Information is also provided on managing security updates in the images, allowing the environment to remain secure and up to date.

> **Warning:** This environment is for educational and research purposes only. Do not use these techniques on real systems without authorization.

## Main Objective

The goal is to offer comprehensive training oriented towards product certification. Each simulation incorporates typical vulnerabilities identified by *OWASP* for each type of device, allowing each lab to have both specific peculiarities and common similarities.

To achieve a more realistic environment, some simulations include multiple components, forming complex and complete systems. For example, a lab may consist of the vulnerable device itself, a cloud API that interacts with it, and an associated mobile service.

The project’s source code is available so that users can compile their own custom image, allowing deployment on multiple devices and architectures. This not only facilitates portability and use, but also helps to understand advanced theoretical concepts and learn how to configure more secure environments.

Each lab offers the option to apply secure configurations, allowing users to compare the vulnerable environment with a protected one and learn best practices to mitigate the present vulnerabilities.

In VulnZoo you can find:

- **Vulnerable Home Router:**  
	- Based on *IoTGoat*, this environment simulates a home router with insecure configurations and common vulnerabilities such as default credentials, exposed services without encryption, and lack of validation in remote configuration. It allows users to explore attacks such as unauthorized access, configuration manipulation, and exploitation of vulnerable web services.

- **Secure Cameras System:**  
	- Simulates an IP camera system with typical IoT device vulnerabilities, such as weak credentials, exposure of unencrypted streams, and failures in authentication and authorization. It allows analysis of unauthorized access attacks, firmware manipulation, and exploitation of insecure APIs.

- **IoT Medical Device:**  
	- Emulates a connected medical device, with vulnerabilities such as insecure data storage, lack of encryption in communications, and exposure of sensitive information. The lab allows exploration of privacy risks, data manipulation, and attacks on device integrity.

---

## Device Manager Installation and Deployment

### Prerequisites:
- Required hardware (Raspberry Pi, SD card, Internet connection, etc.)
- Required software (OpenWRT, flashing tools)

### Method 1: Custom OpenWRT Image Compilation

1. Clone the official OpenWRT repository and checkout version v24.10.3:
```bash
git clone https://github.com/openwrt/openwrt.git
cd openwrt
git checkout v24.10.3
```

2. Run the `setup.sh` script from the `labs/vulnzoo` directory, passing the path to the clean OpenWRT repository. The script handles feeds, file copying, build configuration, and all patches required for Bluetooth support on Raspberry Pi 3B+:
```bash
cd /path/to/VulnZoo/labs/vulnzoo
./setup.sh /path/to/openwrt
```

   The script applies the following automatically:
   - Copies `files/` (BT firmware, init scripts, web app) into the OpenWRT tree
   - Copies `.config` with all required packages enabled
   - Patches `package/kernel/linux/modules/other.mk` to enable `CONFIG_BT_HCIUART_BCM=y` and include `btbcm.ko`
   - Patches `target/linux/bcm27xx/image/distroconfig.txt` to remove `dtoverlay=disable-bt` for Pi 3, freeing the PL011 UART for the onboard BCM4345C0 Bluetooth chip
   - Patches `target/linux/bcm27xx/image/cmdline.txt` to remove the serial console from `ttyAMA0` (which is now used by Bluetooth)
   - Runs `make defconfig` to resolve configuration dependencies

3. Compile the image:
```bash
cd /path/to/openwrt
make -j$(nproc) V=s 2>&1 | tee build.log
```

4. Flash the squashfs image to the SD card.

### Method 2: Using a Precompiled Image

Write the already generated image found in the repository to your Raspberry Pi’s SD card.

```bash
cd VulnZoo
sudo dd if=openwrt-squashfs-factory.img of=/dev/sdX bs=4M status=progress conv=fsync
sudo eject /dev/sdX
```

Insert the SD card into the Raspberry Pi and boot.

Once the device is running, you can access the web interface at `http://192.168.2.1:8080` to manage the vulnerable devices.

---

## Lab Architecture and Simulation of External Services

To provide a more realistic and flexible training experience, **VulnZoo** integrates the simulation of external services, such as cloud APIs, using Docker containers. The presence of these services is essential to replicate real scenarios of interaction between vulnerable devices and external servers, as occurs in production environments.

The API server runs in an independent container on the trainee’s PC, which provides several key advantages:

- **Compatibility:** Docker allows easy deployment of the environment on different operating systems and architectures, without the need for complex configurations.
- **Simplicity and lightness:** Using containers reduces resource overhead and facilitates the management and updating of simulated services.
- **Isolation:** Running the API server in a separate container more realistically simulates the presence of an external server on the network, clearly differentiating it from the attacker’s machine or the vulnerable device.

Before starting the lab, make sure if the vulnerable environment that is running needs the API server. If so, you can start the API server with the following command:

```bash
cd cloud_api
docker-compose up -d --build
```

#### Network Configuration

To connect the PC used for testing and the Raspberry Pi emulating a vulnerable device, simply connect both devices with an Ethernet cable and configure the local PC with an IP address in the 192.168.2.0/24 range.

> **The vulnerable device has the address 192.168.2.1**