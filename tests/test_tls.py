"""Unit tests for the TLS layer: cipher-suite registry semantics, version
constants and handshake message parsing (round-tripped through the synthetic
handshake encoders in ``samples.tlsgen``).
"""
from __future__ import annotations

import unittest

from securemailscope.samples import tlsgen as T
from securemailscope.tls import cipher_suites as cs
from securemailscope.tls import constants as C
from securemailscope.tls import handshake as hs
from securemailscope.tls.records import iter_handshakes, iter_records


class TestCipherSuites(unittest.TestCase):
    def test_strong_aead_pfs_suite(self):
        s = cs.lookup(0xC02F)                 # ECDHE-RSA-AES128-GCM-SHA256
        self.assertEqual(s.grade, "strong")
        self.assertTrue(s.aead)
        self.assertTrue(s.pfs)
        self.assertEqual(s.issues, ())

    def test_rc4_is_flagged(self):
        self.assertIn("RC4", cs.lookup(0xC011).issues)

    def test_static_rsa_cbc_weaknesses(self):
        s = cs.lookup(0x002F)                 # RSA-AES128-CBC-SHA
        self.assertFalse(s.pfs)
        for tag in ("NO_PFS", "CBC", "SHA1_MAC"):
            self.assertIn(tag, s.issues)

    def test_unknown_suite_is_tagged(self):
        s = cs.lookup(0xABCD)
        self.assertEqual(s.grade, "unknown")
        self.assertIn("UNKNOWN_SUITE", s.issues)


class TestVersionConstants(unittest.TestCase):
    def test_version_names(self):
        self.assertEqual(C.version_name(C.TLS_1_2), "TLS 1.2")
        self.assertEqual(C.version_name(C.TLS_1_3), "TLS 1.3")

    def test_deprecation_flags(self):
        self.assertTrue(C.is_deprecated_version(C.TLS_1_0))
        self.assertTrue(C.is_deprecated_version(C.SSL_3_0))
        self.assertFalse(C.is_deprecated_version(C.TLS_1_2))
        self.assertFalse(C.is_deprecated_version(C.TLS_1_3))


class TestHandshakeParsing(unittest.TestCase):
    def _first(self, blob, msg_type):
        for m in iter_handshakes(iter_records(blob)):
            if m.msg_type == msg_type:
                return m
        self.fail(f"handshake message {msg_type} not found")

    def test_client_hello_roundtrip(self):
        blob = T.client_hello(0x0303, [0xC02F, 0x009C],
                              sni="mail.example.com", groups=[0x0017, 0x001d])
        ch = hs.parse_client_hello(self._first(blob, C.HS_CLIENT_HELLO).body)
        self.assertEqual(ch["sni"], "mail.example.com")
        self.assertIn(0xC02F, ch["cipher_suites"])
        self.assertIn(0x0017, ch["groups"])

    def test_server_hello_tls12(self):
        m = self._first(T.server_hello(0x0303, 0xC030), C.HS_SERVER_HELLO)
        sh = hs.parse_server_hello(m.body)
        self.assertEqual(sh["negotiated_version"], C.TLS_1_2)
        self.assertEqual(sh["cipher_suite"], 0xC030)

    def test_server_hello_tls13_via_supported_versions(self):
        blob = T.server_hello(0x0303, 0x1301, supported_version=0x0304)
        sh = hs.parse_server_hello(self._first(blob, C.HS_SERVER_HELLO).body)
        self.assertEqual(sh["negotiated_version"], C.TLS_1_3)

    def test_certificate_extraction_roundtrips_der(self):
        key = T.gen_key("rsa2048")
        der = T.make_cert("x.example", key, "x.example", key)
        m = self._first(T.certificate([der]), C.HS_CERTIFICATE)
        certs = hs.parse_certificate(m.body, tls13=False)
        self.assertEqual(len(certs), 1)
        self.assertEqual(certs[0], der)


if __name__ == "__main__":            # pragma: no cover
    unittest.main()
