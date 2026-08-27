import unittest
from app import analyze

class TestAuthLog(unittest.TestCase):
    def test_counts_failed_ip(self):
        result = analyze({'log':'Failed password for invalid user root from 203.0.113.10 port 22'})
        self.assertEqual(result['failed_authentication_events'], 1)
        self.assertEqual(result['top_source_ips'][0][0], '203.0.113.10')

if __name__ == '__main__': unittest.main()
