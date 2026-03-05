#!/usr/bin/env python3
import asyncio
import json
from datetime import datetime

class CardiacAlertEngine:
    """Cardiac event detection engine"""
    
    ALERTS = {
        'BRADYCARDIA': {'hr_max': 50, 'severity': 'warning'},
        'TACHYCARDIA': {'hr_min': 120, 'severity': 'warning'},
        'SEVERE_TACHYCARDIA': {'hr_min': 150, 'severity': 'critical'},
        'HYPOXIA': {'spo2_max': 90, 'severity': 'critical'},
        'ASYSTOLE': {'hr_max': 0, 'severity': 'critical'},
        'IRREGULAR_RHYTHM': {'hr_variability': 30, 'severity': 'warning'}
    }
    
    def __init__(self, store):
        self.store = store
        self.history = []  # Last 10 readings to detect irregularities
        
    def process_reading(self, reading):
        """Analyzes reading and generates alerts"""
        self.history.append(reading)
        if len(self.history) > 10:
            self.history.pop(0)
            
        alerts = []
        hr = reading['heart_rate']
        spo2 = reading['spo2']
        
        # Event detection
        if hr == 0:
            alerts.append(self._create_alert('ASYSTOLE', reading))
        elif hr < 50:
            alerts.append(self._create_alert('BRADYCARDIA', reading))
        elif hr > 150:
            alerts.append(self._create_alert('SEVERE_TACHYCARDIA', reading))
        elif hr > 120:
            alerts.append(self._create_alert('TACHYCARDIA', reading))
            
        if spo2 < 90:
            alerts.append(self._create_alert('HYPOXIA', reading))
            
        # Fibrillation detection (extreme variability)
        if len(self.history) >= 5:
            hr_values = [r['heart_rate'] for r in self.history[-5:]]
            variability = max(hr_values) - min(hr_values)
            if variability > 30:
                alerts.append(self._create_alert('IRREGULAR_RHYTHM', reading))
                
        # Save to database
        self.store.save_reading(reading, alerts)
        
        return alerts
    
    def _create_alert(self, alert_type, reading):
        return {
            'type': alert_type,
            'timestamp': reading['timestamp'],
            'severity': self.ALERTS[alert_type]['severity'],
            'value': f"HR:{reading['heart_rate']} SpO2:{reading['spo2']}",
            'acknowledged': False
        }