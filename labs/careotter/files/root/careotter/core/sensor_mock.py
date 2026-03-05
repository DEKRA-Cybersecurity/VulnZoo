#!/usr/bin/env python3
import random
import math
from datetime import datetime

class MockMAX30102:
    """Simulates real pulse oximeter with cardiac scenarios"""
    
    def __init__(self, scenario='normal_sinus'):
        self.scenario = scenario
        self.base_hr = 72
        self.last_hr = 72
        self.time_counter = 0
        
    def set_scenario(self, scenario):
        """Changes the medical scenario for testing"""
        self.scenario = scenario
        scenarios = {
            'normal_sinus': 72,
            'bradycardia': 45,
            'tachycardia': 145,
            'afib': 90,  # Atrial fibrillation (irregular)
            'hypoxia': 85
        }
        self.base_hr = scenarios.get(scenario, 72)
        
    def get_reading(self):
        """Returns realistic BPM and SpO2 readings"""
        self.time_counter += 1
        
        # Simulation of heart rate variability (realistic HRV)
        if self.scenario == 'afib':
            # Completely irregular
            hr = self.base_hr + random.randint(-30, 30)
        else:
            # Smooth variation (respiratory waves)
            variation = math.sin(self.time_counter * 0.1) * 5
            noise = random.randint(-2, 2)
            hr = self.base_hr + variation + noise
            
        hr = max(0, min(220, int(hr)))  # Physiological limits
        
        # SpO2 inversely correlated with extreme HR
        if self.scenario == 'hypoxia':
            spo2 = random.randint(82, 88)
        elif hr > 150:
            spo2 = random.randint(90, 95)
        else:
            spo2 = random.randint(96, 99)
            
        # Perfusion index (signal quality)
        perfusion = random.uniform(2.0, 8.0) if hr > 0 else 0.0
        
        return {
            'timestamp': datetime.now().isoformat(),
            'heart_rate': int(hr),
            'spo2': int(spo2),
            'perfusion_index': round(perfusion, 2),
            'status': self._classify_status(hr, spo2)
        }
    
    def _classify_status(self, hr, spo2):
        """Basic medical classification"""
        if hr == 0:
            return 'asystole'
        elif hr < 50 or hr > 150 or spo2 < 90:
            return 'critical'
        elif hr < 60 or hr > 120 or spo2 < 95:
            return 'warning'
        return 'normal'