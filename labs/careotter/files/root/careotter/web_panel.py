#!/usr/bin/env python3
"""
CareOtter Web Panel - OpenWRT Status Dashboard
Lightweight Flask micro-app for device status via web
"""
from flask import Flask, jsonify, render_template_string
from datetime import datetime
import logging
import json
from pathlib import Path

logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Global state (would normally come from data_store)
CURRENT_READING = None
PENDING_ALERTS = []
DEVICE_STATUS = {
    'status': 'running',
    'uptime_seconds': 0,
    'ble_connected': False,
    'cloud_synced': False,
    'battery_percent': 100
}


@app.route('/status', methods=['GET'])
def get_status():
    """Get current device status as JSON"""
    return jsonify({
        'device': {
            'id': 'careotter-001',
            'name': 'CareOtter HR Monitor',
            'status': DEVICE_STATUS['status'],
            'uptime_seconds': DEVICE_STATUS['uptime_seconds']
        },
        'cardiac': {
            'heart_rate': CURRENT_READING['heart_rate'] if CURRENT_READING else 0,
            'spo2': CURRENT_READING['spo2'] if CURRENT_READING else 0,
            'perfusion_index': CURRENT_READING['perfusion_index'] if CURRENT_READING else 0,
            'timestamp': CURRENT_READING['timestamp'] if CURRENT_READING else None
        },
        'connectivity': {
            'ble_connected': DEVICE_STATUS['ble_connected'],
            'cloud_synced': DEVICE_STATUS['cloud_synced'],
            'last_sync': None
        },
        'alerts': {
            'pending': len(PENDING_ALERTS),
            'critical': sum(1 for a in PENDING_ALERTS if a.get('severity') == 'critical'),
            'warning': sum(1 for a in PENDING_ALERTS if a.get('severity') == 'warning')
        },
        'hardware': {
            'battery_percent': DEVICE_STATUS['battery_percent'],
            'temperature_celsius': 45.2
        }
    })


@app.route('/alerts', methods=['GET'])
def get_alerts():
    """Get pending alerts"""
    return jsonify({
        'alerts': PENDING_ALERTS,
        'total': len(PENDING_ALERTS)
    })


@app.route('/readings', methods=['GET'])
def get_readings():
    """Get last N readings"""
    limit = 100  # Would be configurable
    return jsonify({
        'readings': [CURRENT_READING] if CURRENT_READING else [],
        'count': 1 if CURRENT_READING else 0
    })


@app.route('/dashboard', methods=['GET'])
def dashboard():
    """HTML dashboard"""
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>CareOtter Dashboard</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 20px;
                background-color: #f5f5f5;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            h1 {
                color: #333;
                border-bottom: 2px solid #007bff;
                padding-bottom: 10px;
            }
            .card {
                display: inline-block;
                width: calc(25% - 10px);
                margin: 5px;
                padding: 15px;
                background: #f9f9f9;
                border: 1px solid #ddd;
                border-radius: 5px;
                text-align: center;
            }
            .card h3 {
                margin: 0 0 10px 0;
                color: #666;
                font-size: 12px;
                text-transform: uppercase;
            }
            .card .value {
                font-size: 32px;
                font-weight: bold;
                color: #007bff;
            }
            .card .unit {
                font-size: 14px;
                color: #999;
            }
            .status-critical { color: #dc3545; }
            .status-warning { color: #ffc107; }
            .status-normal { color: #28a745; }
            .alert-box {
                background: #fff3cd;
                border-left: 4px solid #ffc107;
                padding: 10px;
                margin: 10px 0;
                border-radius: 3px;
            }
            .alert-box.critical {
                background: #f8d7da;
                border-left-color: #dc3545;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }
            th, td {
                padding: 10px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }
            th {
                background-color: #f9f9f9;
                font-weight: bold;
            }
            .endpoint {
                background: #f0f0f0;
                padding: 10px;
                margin: 10px 0;
                font-family: monospace;
                border-radius: 3px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🏥 CareOtter Cardiac Monitor Dashboard</h1>
            
            <h2>Current Status</h2>
            <div id="status"></div>
            
            <h2>Cardiac Readings</h2>
            <div class="card">
                <h3>Heart Rate</h3>
                <div class="value status-normal">-- BPM</div>
                <div class="unit">beats per minute</div>
            </div>
            <div class="card">
                <h3>Oxygen Saturation</h3>
                <div class="value status-normal">-- %</div>
                <div class="unit">SpO₂</div>
            </div>
            <div class="card">
                <h3>Perfusion Index</h3>
                <div class="value status-normal">--</div>
                <div class="unit">arbitrary units</div>
            </div>
            <div class="card">
                <h3>Battery Level</h3>
                <div class="value status-warning">-- %</div>
                <div class="unit">remaining</div>
            </div>
            
            <h2>Active Alerts</h2>
            <div id="alerts">
                <p style="color: #999;">No active alerts</p>
            </div>
            
            <h2>API Endpoints</h2>
            <p>Access device data via REST API:</p>
            <div class="endpoint">GET /api/status</div>
            <div class="endpoint">GET /api/alerts</div>
            <div class="endpoint">GET /api/readings</div>
            
            <h2>System Information</h2>
            <table>
                <tr>
                    <th>Parameter</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Device ID</td>
                    <td>careotter-001</td>
                </tr>
                <tr>
                    <td>Version</td>
                    <td>1.0.0-baseline</td>
                </tr>
                <tr>
                    <td>Status</td>
                    <td><span class="status-normal">Running</span></td>
                </tr>
                <tr>
                    <td>BLE</td>
                    <td>Advertising as "CareOtter_HR_001"</td>
                </tr>
            </table>
        </div>
        
        <script>
            // Auto-refresh status
            async function updateStatus() {
                try {
                    const response = await fetch('/api/status');
                    const data = await response.json();
                    document.getElementById('status').innerHTML = 
                        '<p>System Status: <strong>' + data.device.status + '</strong></p>';
                } catch (e) {
                    console.error('Failed to fetch status:', e);
                }
            }
            
            // Update alerts
            async function updateAlerts() {
                try {
                    const response = await fetch('/api/alerts');
                    const data = await response.json();
                    
                    if (data.alerts.length > 0) {
                        let html = '';
                        for (let alert of data.alerts) {
                            const cls = alert.severity === 'critical' ? 'critical' : '';
                            html += '<div class="alert-box ' + cls + '">' +
                                    '<strong>' + alert.type + '</strong> (' + alert.severity + ')' +
                                    '</div>';
                        }
                        document.getElementById('alerts').innerHTML = html;
                    }
                } catch (e) {
                    console.error('Failed to fetch alerts:', e);
                }
            }
            
            // Initial load
            updateStatus();
            updateAlerts();
            
            // Refresh every 5 seconds
            setInterval(updateStatus, 5000);
            setInterval(updateAlerts, 5000);
        </script>
    </body>
    </html>
    '''
    return render_template_string(html)


# API routes (prefixed for clarity)
@app.route('/api/status', methods=['GET'])
def api_status():
    return get_status()

@app.route('/api/alerts', methods=['GET'])
def api_alerts():
    return get_alerts()

@app.route('/api/readings', methods=['GET'])
def api_readings():
    return get_readings()


def update_status(reading, alerts, device_status):
    """Update dashboard state (called from main.py)"""
    global CURRENT_READING, PENDING_ALERTS, DEVICE_STATUS
    CURRENT_READING = reading
    PENDING_ALERTS = alerts
    DEVICE_STATUS = device_status


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    
    # Demo data
    CURRENT_READING = {
        'timestamp': datetime.now().isoformat(),
        'heart_rate': 72,
        'spo2': 98,
        'perfusion_index': 2.5,
        'status': 'normal'
    }
    
    DEVICE_STATUS = {
        'status': 'running',
        'uptime_seconds': 3600,
        'ble_connected': True,
        'cloud_synced': True,
        'battery_percent': 85
    }
    
    logger.info("[*] Starting CareOtter Web Panel on http://0.0.0.0:8080")
    app.run(host='0.0.0.0', port=8080, debug=False)
