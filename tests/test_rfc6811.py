import unittest
from src.core.rpki_validator import RPKIValidator, RFC6811State
from src.core.bogon_filter import BogonFilter

class TestRFC6811Validation(unittest.TestCase):
    def setUp(self):
        self.sample_roas = [
            {"prefix": "1.1.1.0/24", "max_length": 24, "asn": 13335, "tai": "APNIC"},
            {"prefix": "8.8.8.0/24", "max_length": 24, "asn": 15169, "tai": "ARIN"},
            # Supernet ROA with max-length 20
            {"prefix": "93.184.216.0/20", "max_length": 20, "asn": 15133, "tai": "RIPE NCC"},
            # Multi-homed prefix authorized for two ASNs
            {"prefix": "198.51.200.0/22", "max_length": 24, "asn": 64496, "tai": "TEST"},
            {"prefix": "198.51.200.0/22", "max_length": 24, "asn": 20000, "tai": "TEST"}
        ]
        self.validator = RPKIValidator(self.sample_roas)

    def test_valid_exact_match(self):
        res = self.validator.validate("1.1.1.0/24", 13335)
        self.assertEqual(res.state, RFC6811State.VALID)
        self.assertEqual(res.rfc_state, "VALID")

    def test_not_found_unknown_prefix(self):
        res = self.validator.validate("203.0.113.0/24", 13335)
        self.assertEqual(res.state, RFC6811State.NOT_FOUND)
        self.assertEqual(res.rfc_state, "NOT_FOUND")

    def test_invalid_origin_asn(self):
        # 1.1.1.0/24 is authorized for AS13335, but announced by AS99999
        res = self.validator.validate("1.1.1.0/24", 99999)
        self.assertEqual(res.state, RFC6811State.INVALID_ASN)
        self.assertEqual(res.rfc_state, "INVALID")
        self.assertIn(13335, res.expected_asns)

    def test_invalid_length_subprefix_hijack(self):
        # 93.184.216.0/20 has max_length 20. Announcing a /24 subprefix with correct ASN should fail max_length check!
        res = self.validator.validate("93.184.216.0/24", 15133)
        self.assertEqual(res.state, RFC6811State.INVALID_LENGTH)
        self.assertEqual(res.rfc_state, "INVALID")

    def test_multihomed_prefix_valid(self):
        # Should be valid for either authorized ASN
        res1 = self.validator.validate("198.51.200.0/24", 64496)
        self.assertEqual(res1.state, RFC6811State.VALID)
        res2 = self.validator.validate("198.51.200.0/24", 20000)
        self.assertEqual(res2.state, RFC6811State.VALID)

    def test_bogon_filters(self):
        # Check private ASN
        is_bogon, label = BogonFilter.is_bogon_asn(64512)
        self.assertTrue(is_bogon)
        self.assertIn("Private", label)

        # Check public ASN
        is_bogon, label = BogonFilter.is_bogon_asn(13335)
        self.assertFalse(is_bogon)

        # Check RFC 1918 bogon prefix
        is_bogon, label = BogonFilter.is_bogon_prefix("10.0.1.0/24")
        self.assertTrue(is_bogon)

        # Check public prefix
        is_bogon, label = BogonFilter.is_bogon_prefix("1.1.1.0/24")
        self.assertFalse(is_bogon)

if __name__ == "__main__":
    unittest.main()
