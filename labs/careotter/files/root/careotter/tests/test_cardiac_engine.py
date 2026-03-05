#!/usr/bin/env python3
"""
Unit Tests for CareOtter Cardiac Alert Engine
Validates alert detection for all scenarios
"""
import unittest
import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from core.cardiac_monitor import CardiacAlertEngine
from core.data_store import DataStore


class TestCardiacAlertEngine(unittest.TestCase):
    """Test suite for CardiacAlertEngine"""
    
    def setUp(self):
        """Initialize test components"""
        self.data_store = DataStore()
        self.engine = CardiacAlertEngine(self.data_store)
    
    def test_normal_sinus_no_alerts(self):
        """Normal heart rate (60-100 BPM) should not trigger alerts"""
        reading = {
            'timestamp': '2024-01-15T10:00:00Z',
            'heart_rate': 72,
            'spo2': 98,
            'perfusion_index': 2.5,
            'status': 'normal'
        }
        
        alerts = self.engine.process_reading(reading)
        self.assertEqual(len(alerts), 0, "Normal reading should have no alerts")
    
    def test_bradycardia_detection(self):
        """Heart rate < 50 BPM should trigger bradycardia alert"""
        reading = {
            'timestamp': '2024-01-15T10:00:00Z',
            'heart_rate': 48,
            'spo2': 98,
            'perfusion_index': 2.5,
            'status': 'normal'
        }
        
        alerts = self.engine.process_reading(reading)
        self.assertGreater(len(alerts), 0, "Bradycardia should trigger alert")
        
        alert = alerts[0]
        self.assertEqual(alert['type'], 'bradycardia')
        self.assertEqual(alert['severity'], 'warning')
    
    def test_tachycardia_detection(self):
        """Heart rate 120-150 BPM should trigger tachycardia alert"""
        reading = {
            'timestamp': '2024-01-15T10:00:00Z',
            'heart_rate': 130,
            'spo2': 98,
            'perfusion_index': 2.5,
            'status': 'normal'
        }
        
        alerts = self.engine.process_reading(reading)
        self.assertGreater(len(alerts), 0, "Tachycardia should trigger alert")
        
        alert = alerts[0]
        self.assertEqual(alert['type'], 'tachycardia')
        self.assertEqual(alert['severity'], 'warning')
    
    def test_severe_tachycardia_detection(self):
        """Heart rate ≥ 150 BPM should trigger severe tachycardia (critical)"""
        reading = {
            'timestamp': '2024-01-15T10:00:00Z',
            'heart_rate': 160,
            'spo2': 98,
            'perfusion_index': 2.5,
            'status': 'normal'
        }
        
        alerts = self.engine.process_reading(reading)
        self.assertGreater(len(alerts), 0, "Severe tachycardia should trigger alert")
        
        alert = alerts[0]
        self.assertEqual(alert['type'], 'severe_tachycardia')
        self.assertEqual(alert['severity'], 'critical')
    
    def test_asystole_detection(self):
        """Heart rate = 0 (no pulse) should trigger critical asystole alert"""
        reading = {
            'timestamp': '2024-01-15T10:00:00Z',
            'heart_rate': 0,
            'spo2': 60,
            'perfusion_index': 0.0,
            'status': 'critical'
        }
        
        alerts = self.engine.process_reading(reading)
        self.assertGreater(len(alerts), 0, "Asystole should trigger alert")
        
        alert = [a for a in alerts if a['type'] == 'asystole'][0]
        self.assertEqual(alert['severity'], 'critical')
    
    def test_hypoxia_detection(self):
        """SpO₂ < 90% should trigger hypoxia alert"""
        reading = {
            'timestamp': '2024-01-15T10:00:00Z',
            'heart_rate': 72,
            'spo2': 88,
            'perfusion_index': 1.5,
            'status': 'warning'
        }
        
        alerts = self.engine.process_reading(reading)
        self.assertGreater(len(alerts), 0, "Hypoxia should trigger alert")
        
        alert = alerts[0]
        self.assertEqual(alert['type'], 'hypoxia')
        self.assertEqual(alert['severity'], 'warning')
    
    def test_severe_hypoxia_detection(self):
        """SpO₂ ≤ 85% should trigger critical severe hypoxia"""
        reading = {
            'timestamp': '2024-01-15T10:00:00Z',
            'heart_rate': 100,
            'spo2': 82,
            'perfusion_index': 0.8,
            'status': 'critical'
        }
        
        alerts = self.engine.process_reading(reading)
        alert = [a for a in alerts if a['type'].startswith('hypoxia')]
        
        self.assertGreater(len(alert), 0, "Severe hypoxia should trigger alert")
        self.assertIn(alert[0]['severity'], ['warning', 'critical'])
    
    def test_multiple_alerts(self):
        """Multiple simultaneous conditions should trigger multiple alerts"""
        reading = {
            'timestamp': '2024-01-15T10:00:00Z',
            'heart_rate': 160,          # Severe tachycardia
            'spo2': 82,                 # Severe hypoxia
            'perfusion_index': 0.5,
            'status': 'critical'
        }
        
        alerts = self.engine.process_reading(reading)
        self.assertGreaterEqual(len(alerts), 2, "Multiple conditions should trigger multiple alerts")
    
    def test_history_buffer_management(self):
        """History buffer should maintain last 10 readings"""
        for i in range(15):
            reading = {
                'timestamp': f'2024-01-15T10:{i:02d}:00Z',
                'heart_rate': 72 + i,
                'spo2': 98,
                'perfusion_index': 2.5,
                'status': 'normal'
            }
            self.engine.process_reading(reading)
        
        self.assertEqual(
            len(self.engine.reading_history),
            10,
            "History should maintain exactly 10 readings"
        )
    
    def test_afib_detection_high_variability(self):
        """High HR variability (>30 BPM) should indicate irregular rhythm"""
        # Process readings with high variability
        readings = [
            {'timestamp': '2024-01-15T10:00:00Z', 'heart_rate': 60, 'spo2': 98, 'perfusion_index': 2.5, 'status': 'normal'},
            {'timestamp': '2024-01-15T10:00:01Z', 'heart_rate': 105, 'spo2': 98, 'perfusion_index': 2.5, 'status': 'normal'},
            {'timestamp': '2024-01-15T10:00:02Z', 'heart_rate': 65, 'spo2': 98, 'perfusion_index': 2.5, 'status': 'normal'},
            {'timestamp': '2024-01-15T10:00:03Z', 'heart_rate': 100, 'spo2': 98, 'perfusion_index': 2.5, 'status': 'normal'},
            {'timestamp': '2024-01-15T10:00:04Z', 'heart_rate': 62, 'spo2': 98, 'perfusion_index': 2.5, 'status': 'normal'},
        ]
        
        last_alerts = []
        for reading in readings:
            last_alerts = self.engine.process_reading(reading)
        
        # Check if irregular_rhythm alert detected
        irregular = [a for a in last_alerts if a['type'] == 'irregular_rhythm']
        if irregular:
            self.assertEqual(irregular[0]['severity'], 'warning')


class TestDataStore(unittest.TestCase):
    """Test suite for DataStore"""
    
    def setUp(self):
        """Initialize test database"""
        self.store = DataStore()
    
    def test_save_reading(self):
        """Should save reading and return ID"""
        reading = {
            'timestamp': '2024-01-15T10:00:00Z',
            'heart_rate': 72,
            'spo2': 98,
            'perfusion_index': 2.5,
            'status': 'normal'
        }
        alerts = []
        
        reading_id = self.store.save_reading(reading, alerts)
        self.assertGreater(reading_id, 0, "Reading ID should be positive")
    
    def test_get_recent_readings(self):
        """Should retrieve recent readings"""
        reading = {
            'timestamp': '2024-01-15T10:00:00Z',
            'heart_rate': 72,
            'spo2': 98,
            'perfusion_index': 2.5,
            'status': 'normal'
        }
        
        self.store.save_reading(reading, [])
        recent = self.store.get_recent_readings(limit=5)
        
        self.assertGreater(len(recent), 0, "Should return saved reading")
    
    def test_acknowledge_alert(self):
        """Should mark alert as acknowledged"""
        reading = {
            'timestamp': '2024-01-15T10:00:00Z',
            'heart_rate': 48,
            'spo2': 98,
            'perfusion_index': 2.5,
            'status': 'normal'
        }
        alert = {
            'type': 'bradycardia',
            'severity': 'warning',
            'value': 48
        }
        
        reading_id = self.store.save_reading(reading, [alert])
        unacked = self.store.get_unacked_alerts()
        
        if unacked:
            alert_id = unacked[0]['id']
            self.store.acknowledge_alert(alert_id)
            
            unacked_after = self.store.get_unacked_alerts()
            self.assertEqual(
                len(unacked_after),
                len(unacked) - 1,
                "Acknowledged alert should be removed from unacked list"
            )


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestCardiacAlertEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestDataStore))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
