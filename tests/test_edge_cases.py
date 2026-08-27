import unittest
from app import analyze

class TestAuthEdgeCases(unittest.TestCase):
    def test_ignores_invalid_ip_tokens(self):
        result = analyze({'log':'Failed password for root from 999.999.999.999 port 22'})
        self.assertEqual(result['failed_authentication_events'], 1)
        self.assertEqual(result['top_source_ips'], [])
        self.assertEqual(result['invalid_ip_tokens_ignored'], 1)

if __name__ == '__main__': unittest.main()
