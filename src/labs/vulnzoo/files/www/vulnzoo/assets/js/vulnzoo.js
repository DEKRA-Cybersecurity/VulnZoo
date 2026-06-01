// VulnZoo Device Simulator JavaScript Functions
let currentDevice = null;

async function loadDevice(deviceType) {
    if (currentDevice) {
        if (!confirm('Reset current device and load ' + deviceType + '?')) {
            return;
        }
    }

    updateStatus('Loading ' + deviceType + '...');
    
    // Use XMLHttpRequest for better compatibility
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/cgi-bin/device-manager.sh', true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            if (xhr.status === 200) {
                try {
                    var data = JSON.parse(xhr.responseText);
                    if (data.success) {
                        currentDevice = deviceType;
                        document.getElementById('active-device').textContent = getDeviceName(deviceType);
                        if (currentDevice === "loading_" + deviceType) {
                            document.getElementById('device-status').textContent = 'Running';
                            document.getElementById('device-status').className = 'status running';
                        }

                        // Highlight active device
                        document.querySelectorAll('.device-card').forEach(function(card) {
                            card.classList.remove('active');
                        });
                        var deviceCard = document.querySelector('[data-device="' + deviceType + '"]');
                        if (deviceCard) {
                            deviceCard.classList.add('active');
                        }
                        
                        updateStatus('Device ' + deviceType + ' loaded successfully');
                        
                        // Enable device-specific interface button
                        enableDeviceInterface(deviceType);
                        
                        // Show updated device interface info
                        setTimeout(function() {
                            updateStatus(getDeviceName(deviceType) + ' interface available at: http://192.168.2.1/');
                        }, 1500);
                    } else {
                        updateStatus('Error: ' + data.message);
                    }
                } catch (e) {
                    updateStatus('JSON parsing error: ' + e.message);
                    console.error('Response was:', xhr.responseText);
                }
            } else {
                updateStatus('HTTP Error: ' + xhr.status);
            }
        }
    };
    
    xhr.send('action=load&device=' + deviceType);


    setTimeout(function() {
        checkCurrentDeviceStatus();
    }, 20000);
}

function resetCurrentDevice() {
    if (!currentDevice) {
        alert('No device is currently running');
        return;
    }

    console.log('Resetting device:', currentDevice);
    updateStatus('Resetting device ' + currentDevice + '...');

    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/cgi-bin/device-manager.sh', true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            console.log('Reset response status:', xhr.status);
            console.log('Reset response text:', xhr.responseText);
            
            if (xhr.status === 200) {
                try {
                    var data = JSON.parse(xhr.responseText);
                    if (data.success) {
                        document.getElementById('active-device').textContent = 'None';
                        document.getElementById('device-status').textContent = 'Reset';
                        document.getElementById('device-status').className = 'status reset';
                        document.querySelectorAll('.device-card').forEach(function(card) {
                            card.classList.remove('active');
                        });
                        currentDevice = null;
                        updateStatus('Device reset successfully');
                        
                        // Disable device interface buttons
                        disableAllDeviceInterfaces();
                    } else {
                        updateStatus('Error resetting device: ' + (data.message || 'Unknown error'));
                    }
                } catch (e) {
                    updateStatus('JSON parsing error: ' + e.message);
                    console.error('Parse error, response was:', xhr.responseText);
                }
            } else {
                updateStatus('HTTP Error: ' + xhr.status);
            }
        }
    };
    
    var postData = 'action=reset&device=' + encodeURIComponent(currentDevice);
    console.log('Sending POST data:', postData);
    xhr.send(postData);
}

function getDeviceName(type) {
    const names = {
        'routcoon': 'RoutCoon',
        'owlcam': 'OwlCam',
        'careotter': 'CareOtter',
        'industrial': 'Industrial Controller',
        'automotive': 'Automotive System', 
        'medical': 'Medical Device',
        'iot': 'IoT Device'
    };
    return names[type] || type;
}

function updateStatus(message) {
    console.log('Status:', message);
    
    var statusDiv = document.getElementById('status-message');
    if (!statusDiv) {
        statusDiv = document.createElement('div');
        statusDiv.id = 'status-message';
        statusDiv.style.cssText = 'background: linear-gradient(145deg, #4caf50, #388e3c); border:1px solid #2e7d32; color:#ffffff; padding:12px; margin:15px 0; border-radius:4px; display:none; font-family: "JetBrains Mono", monospace; font-size: 0.85em; box-shadow: 0 2px 8px rgba(76, 175, 80, 0.3);';
        var targetElement = document.getElementById('current-device') || document.body;
        targetElement.appendChild(statusDiv);
    }
    
    statusDiv.textContent = message;
    statusDiv.style.display = 'block';
    
    // Hide after 5 seconds
    setTimeout(function() {
        statusDiv.style.display = 'none';
    }, 5000);
}

function restartServices() {
    updateStatus('Restarting services...');
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/cgi-bin/device-manager.sh', true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            if (xhr.status === 200) {
                updateStatus('Services restarted successfully');
            } else {
                updateStatus('Error restarting services');
            }
        }
    };
    xhr.send('action=restart');
}

function scrollToDevice(deviceType) {
    const element = document.querySelector('[data-device="' + deviceType + '"]');
    if (element) {
        element.scrollIntoView({ behavior: 'smooth', block: 'center' });
        // Optional: highlight the target card briefly
        element.style.transform = 'scale(1.05)';
        setTimeout(() => {
            element.style.transform = '';
        }, 500);
    }
}

function checkCurrentDeviceStatus() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/cgi-bin/device-manager.sh?action=status', true);
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4 && xhr.status === 200) {
            try {
                var data = JSON.parse(xhr.responseText);
                if (data.current_device && data.current_device !== 'none') {
                    currentDevice = data.current_device;
                    var activeDeviceElement = document.getElementById('active-device');
                    var deviceStatusElement = document.getElementById('device-status');
                    
                    if (activeDeviceElement) {
                        activeDeviceElement.textContent = getDeviceName(data.current_device);
                    }
                    if (currentDevice) {
                        document.getElementById('device-status').textContent = 'Running';
                        document.getElementById('device-status').className = 'status running';
                    }
                    var deviceCard = document.querySelector('[data-device="' + data.current_device + '"]');
                    if (deviceCard) {
                        deviceCard.classList.add('active');
                    }
                    
                    // Enable interface buttons for current device
                    enableDeviceInterface(data.current_device);
                } else {
                    // No device running, disable all interface buttons
                    disableAllDeviceInterfaces();
                }
            } catch (e) {
                console.error('Error parsing status:', e);
                // On error, disable all interface buttons
                disableAllDeviceInterfaces();
            }
        } else if (xhr.readyState === 4) {
            // On HTTP error, disable all interface buttons
            disableAllDeviceInterfaces();
        }
    };
    xhr.send();
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    checkCurrentDeviceStatus();
});

// Legacy support for window.onload
window.onload = function() {
    checkCurrentDeviceStatus();
};

// Device-specific interface management
function openDeviceInterface(deviceType) {
    // All devices use the same IP and port since only one can be active at a time
    // The device interface is available at port 80 when a device is loaded
    const deviceIP = '192.168.2.1';  // OpenWrt device IP
    const devicePort = '80';         // Main device interface port
    
    if (!currentDevice) {
        updateStatus('No device is currently running. Please load a device first.');
        return;
    }
    
    if (currentDevice !== deviceType) {
        updateStatus('Device ' + deviceType + ' is not currently running. Current device: ' + currentDevice);
        return;
    }
    
    // Construct the device interface URL
    const deviceURL = 'http://' + deviceIP + ':' + devicePort + '/';
    
    updateStatus('Opening ' + getDeviceName(deviceType) + ' interface...');
    
    // Open device interface in new tab
    const newWindow = window.open(deviceURL, '_blank');
    
    if (!newWindow) {
        // Popup blocked - provide manual link
        updateStatus('Popup blocked. Please visit: ' + deviceURL);
    } else {
        updateStatus('Device interface opened. URL: ' + deviceURL);
    }
}

function enableDeviceInterface(deviceType) {
    // Enable interface button for current device
    const interfaceButtons = {
        'routcoon': 'routcoon-interface-btn',
        'owlcam': 'owlcam-interface-btn',
        'careotter': 'careotter-interface-btn',
        'industrial': 'industrial-interface-btn',
        'automotive': 'automotive-interface-btn',
        'medical': 'medical-interface-btn',
        'iot': 'iot-interface-btn'
    };
    
    // Disable all first
    disableAllDeviceInterfaces();
    
    // Enable current device interface
    const buttonId = interfaceButtons[deviceType];
    const button = document.getElementById(buttonId);
    if (button) {
        button.disabled = false;
        button.style.opacity = '1';
        button.style.cursor = 'pointer';
        button.title = 'Open ' + getDeviceName(deviceType) + ' interface';
    }
    
    // Also enable any generic "Access Device Interface" buttons
    const genericButtons = document.querySelectorAll('.device-interface-btn, .access-interface-btn');
    genericButtons.forEach(function(btn) {
        btn.disabled = false;
        btn.style.opacity = '1';
        btn.style.cursor = 'pointer';
        btn.textContent = 'Access ' + getDeviceName(deviceType) + ' Interface';
    });
}

function disableAllDeviceInterfaces() {
    const allButtons = [
        'routcoon-interface-btn',
        'owlcam-interface-btn',
        'careotter-interface-btn',
        'industrial-interface-btn', 
        'automotive-interface-btn',
        'medical-interface-btn',
        'iot-interface-btn'
    ];
    
    allButtons.forEach(function(buttonId) {
        const button = document.getElementById(buttonId);
        if (button) {
            button.disabled = true;
            button.style.opacity = '0.5';
            button.style.cursor = 'not-allowed';
            button.title = 'Load a device first';
        }
    });
    
    // Also disable any generic "Access Device Interface" buttons
    const genericButtons = document.querySelectorAll('.device-interface-btn, .access-interface-btn');
    genericButtons.forEach(function(btn) {
        btn.disabled = true;
        btn.style.opacity = '0.5';
        btn.style.cursor = 'not-allowed';
        btn.textContent = 'Access Device Interface (No device loaded)';
        btn.title = 'Load a device first';
    });
}