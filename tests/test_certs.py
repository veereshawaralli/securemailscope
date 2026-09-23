"""Unit tests for X.509 certificate analysis: weakness detection on synthetic
certificates (expired, self-signed, sub-2048-bit RSA) and chain completeness.
Skipped when the optional ``cryptography`` dependency is unavailable.
"""
from __future__ import annotations

import unittest

from securemailscope.certs.analyze import _HAVE_CRYPTO, analyze_cert, analyze_chain
from securemailscope.samples import tlsgen as T


@unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed")
class TestCertAnalysis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_key = T.gen_key("rsa4096")
        cls.ca = T.make_cert("Example Root CA", cls.ca_key, "Example Root CA",
                             cls.ca_key, days_from=-800, days_to=3000, ca=True)
        leaf_key = T.gen_key("rsa2048")
        cls.good = T.make_cert("mail.example.com", leaf_key, "Example Root CA",
                               cls.ca_key, days_from=-30, days_to=365,
                               sans=["mail.example.com"])
        wk = T.gen_key("rsa1024")
        cls.weak = T.make_cert("mail.legacy.example", wk, "mail.legacy.example",
                               wk, days_from=-800, days_to=-10)
        # an impostor "Example Root CA": same names as the real root but a
        # different key, so it cannot have signed the genuine leaf
        imp_key = T.gen_key("rsa2048")
        cls.imposter = T.make_cert("Example Root CA", imp_key, "Example Root CA",
                                   imp_key, days_from=-800, days_to=3000, ca=True)

    def test_good_leaf_has_no_weaknesses(self):
        info = analyze_cert(self.good)
        self.assertTrue(info.parsed)
        self.assertEqual(info.public_key_algo, "RSA")
        self.assertGreaterEqual(info.key_bits, 2048)
        self.assertFalse(info.is_expired)
        self.assertFalse(info.self_signed)
        self.assertEqual(info.weaknesses, [])
        self.assertIn("mail.example.com", info.san)

    def test_weak_leaf_flags_expiry_key_and_self_signed(self):
        info = analyze_cert(self.weak)
        self.assertTrue(info.is_expired)
        self.assertTrue(info.self_signed)
        self.assertLess(info.key_bits, 2048)
        for tag in ("CERT_EXPIRED", "WEAK_RSA_KEY", "SELF_SIGNED"):
            self.assertIn(tag, info.weaknesses)

    def test_complete_chain(self):
        ch = analyze_chain([self.good, self.ca])
        self.assertEqual(ch.count, 2)
        self.assertTrue(ch.chain_complete)
        self.assertFalse(ch.self_signed_leaf)
        self.assertNotIn("CHAIN_INCOMPLETE", ch.leaf.weaknesses)

    def test_chain_signatures_verify_cryptographically(self):
        ch = analyze_chain([self.good, self.ca])
        self.assertIs(ch.signatures_valid, True)
        self.assertTrue(ch.self_signed_root)
        self.assertNotIn("CHAIN_SIGNATURE_INVALID", ch.leaf.weaknesses)
        # a private (self-managed) root that verifies internally
        self.assertIn(ch.trust_status, ("private-ca", "trusted"))

    def test_broken_chain_signature_is_detected(self):
        ch = analyze_chain([self.good, self.imposter])
        self.assertIs(ch.signatures_valid, False)
        self.assertIn("CHAIN_SIGNATURE_INVALID", ch.leaf.weaknesses)
        self.assertEqual(ch.trust_status, "broken")
        self.assertFalse(ch.validated)

    def test_lone_leaf_is_incomplete_chain(self):
        ch = analyze_chain([self.good])
        self.assertFalse(ch.chain_complete)
        self.assertIn("CHAIN_INCOMPLETE", ch.leaf.weaknesses)

    def test_empty_chain(self):
        ch = analyze_chain([])
        self.assertEqual(ch.count, 0)
        self.assertIsNone(ch.leaf)


if __name__ == "__main__":            # pragma: no cover
    unittest.main()
