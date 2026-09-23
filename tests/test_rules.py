"""Unit tests for the deterministic rules engine, posture scoring and the
recommendation aggregator: synthetic session summaries in, graded findings,
scores and de-duplicated remediations out.
"""
from __future__ import annotations

import unittest

from securemailscope.analysis import posture, recommendations, rules
from securemailscope.analysis.models import Finding, Severity


def _summary(**over):
    base = dict(protocol="SMTP", server_port=587, tls_present=True,
                cleartext_auth=False, starttls_offered=True,
                negotiated_version_name="TLS 1.2", cipher_issues=[],
                cipher_suite_name="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    base.update(over)
    return base


class TestRules(unittest.TestCase):
    def _ids(self, summary, chain=None):
        return {f.id for f in rules.evaluate(summary, chain)}

    def test_clean_session_is_ok(self):
        self.assertIn("SMS-OK", self._ids(_summary()))

    def test_cleartext_auth_is_critical(self):
        f = [x for x in rules.evaluate(_summary(cleartext_auth=True))
             if x.id == "SMS-AUTH-CLEARTEXT"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, Severity.CRITICAL)

    def test_no_tls_port25_flags_absent_and_no_starttls(self):
        ids = self._ids(_summary(tls_present=False, starttls_offered=False,
                                 server_port=25, negotiated_version_name=""))
        self.assertIn("SMS-TLS-ABSENT", ids)
        self.assertIn("SMS-NO-STARTTLS", ids)

    def test_starttls_stripped(self):
        ids = self._ids(_summary(tls_present=False, starttls_offered=True,
                                 negotiated_version_name=""))
        self.assertIn("SMS-STARTTLS-STRIPPED", ids)

    def test_deprecated_tls_version(self):
        self.assertIn("SMS-TLS-DEPRECATED",
                      self._ids(_summary(negotiated_version_name="TLS 1.0")))

    def test_rc4_cipher_finding(self):
        self.assertIn("SMS-CIPHER-RC4",
                      self._ids(_summary(cipher_issues=["RC4"])))

    def test_expired_cert_from_chain(self):
        chain = {"count": 1, "leaf": {"subject": "CN=x",
                 "weaknesses": ["CERT_EXPIRED"], "not_after": "2020-01-01"}}
        self.assertIn("SMS-CERT_EXPIRED", self._ids(_summary(), chain))

    def test_tls13_certificate_encrypted_note(self):
        ids = self._ids(_summary(negotiated_version_name="TLS 1.3"),
                        {"count": 0})
        self.assertIn("SMS-CERT-ENCRYPTED", ids)


class TestPosture(unittest.TestCase):
    def _f(self, sev):
        return Finding("X", "t", sev, "c", "e", "r", [])

    def test_score_deducts_penalties(self):
        fs = [self._f(Severity.HIGH), self._f(Severity.MEDIUM)]  # 22 + 10
        self.assertEqual(posture.score_session(fs), 68)
        self.assertEqual(posture.grade(68), "D")

    def test_score_clamped_at_zero(self):
        self.assertEqual(posture.score_session([self._f(Severity.CRITICAL)] * 5), 0)

    def test_grade_boundaries(self):
        self.assertEqual(posture.grade(90), "A")
        self.assertEqual(posture.grade(89), "B")
        self.assertEqual(posture.grade(60), "D")
        self.assertEqual(posture.grade(59), "F")

    def test_risk_label_takes_worst(self):
        fs = [self._f(Severity.LOW), self._f(Severity.CRITICAL)]
        self.assertEqual(posture.risk_label(fs), "critical")

    def test_overall_weights_the_worst_link(self):
        score, grade = posture.overall([0, 100])   # round(0.6*0 + 0.4*50)
        self.assertEqual(score, 20)
        self.assertEqual(grade, "F")


class _Sess:
    def __init__(self, findings, stream):
        self.findings, self.stream = findings, stream


class TestRecommendations(unittest.TestCase):
    def test_dedup_priority_and_info_dropped(self):
        hi = Finding("A", "t", Severity.HIGH, "c", "e", "Fix TLS", [])
        hi2 = Finding("B", "t", Severity.HIGH, "c", "e", "Fix TLS", [])
        crit = Finding("C", "t", Severity.CRITICAL, "c", "e", "Fix auth", [])
        info = Finding("D", "t", Severity.INFO, "c", "e", "Nothing to do", [])
        recs = recommendations.collect(
            [_Sess([hi, info], "s1"), _Sess([hi2, crit], "s2")])
        self.assertEqual(recs[0]["recommendation"], "Fix auth")   # crit first
        tls = next(r for r in recs if r["recommendation"] == "Fix TLS")
        self.assertEqual(sorted(tls["finding_ids"]), ["A", "B"])
        self.assertEqual(tls["affected_streams"], ["s1", "s2"])
        self.assertNotIn("Nothing to do",
                         [r["recommendation"] for r in recs])


if __name__ == "__main__":            # pragma: no cover
    unittest.main()
