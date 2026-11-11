import base64
import json
import unittest
from private_leaks import scan_canaries


class PrivateLeakTests(unittest.TestCase):
    def test_encoded_split_partial_and_raw_leaks(self):
        token = '0123456789abcdef'*4
        for raw in [token, base64.b64encode(token.encode()), token.encode().hex(), '\n'.join(token[i:i+8] for i in range(0,64,8)), token[16:32]]:
            with self.subTest(raw_type=type(raw)):
                result = scan_canaries(raw, [token], surface='hidden-log')
                self.assertTrue(result['leakDetected'])
                self.assertNotIn(token, json.dumps(result))

    def test_safe_evidence_and_unknown_surface(self):
        self.assertFalse(scan_canaries('no capability here', ['a'*64], surface='context')['leakDetected'])
        with self.assertRaises(ValueError): scan_canaries('secret', ['a'*64], surface='arbitrary-secret-path')


if __name__ == '__main__': unittest.main()
