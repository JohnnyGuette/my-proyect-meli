import unittest
from unittest.mock import patch, MagicMock
import json
from datetime import datetime, timedelta
from main import logAnalysisFunction  # Asegúrate de importar tu función correctamente

class TestLogAnalysisFunction(unittest.TestCase):
    @patch('main.cloud_logging.Client')
    @patch('main.datetime')
    def test_log_analysis_function(self, mock_datetime, mock_client):
        mock_now = datetime(2023, 6, 20, 12, 0, 0)
        mock_past = mock_now - timedelta(hours=8)
        mock_datetime.utcnow.return_value = mock_now
        
        mock_client_instance = mock_client.return_value
        
        sql_injection_entry = MagicMock()
        sql_injection_entry.payload = {'mock_key': 'mock_value'}
        sql_injection_entry.http_request = {
            'requestUrl': "http://example.com/?id=1%27+OR+%271%27%3D%271",
            'requestMethod': 'GET',
            'remoteIp': '192.168.1.1'
        }
        sql_injection_entry.timestamp = mock_now

        ddos_entry = MagicMock()
        ddos_entry.payload = {'mock_key': 'mock_value'}
        ddos_entry.http_request = {
            'requestUrl': "http://example.com/?other_param=123",
            'requestMethod': 'GET',
            'remoteIp': '192.168.1.2'
        }
        ddos_entry.timestamp = mock_now

        entries = [sql_injection_entry] * 5  
        entries.extend([ddos_entry] * 25)    

        mock_client_instance.list_entries.return_value = entries

        mock_request = MagicMock()

        response_body, status_code, headers = logAnalysisFunction(mock_request)
       
        response_data = json.loads(response_body)
        
        self.assertEqual(status_code, 200)

        self.assertIn('vulnerabilities_mitigation', response_data)
        self.assertGreater(len(response_data['vulnerabilities_mitigation']), 0)

        sql_injection_detected = any(
            'Posible inyección SQL' in mitigation['vulnerabilities'] 
            for mitigation in response_data['vulnerabilities_mitigation']
        )
        self.assertTrue(sql_injection_detected)

        ddos_detected = any(
            'Posible ataque DDOS' in mitigation['vulnerabilities'] 
            for mitigation in response_data['vulnerabilities_mitigation']
        )
        self.assertTrue(ddos_detected)

if __name__ == '__main__':
    unittest.main()
