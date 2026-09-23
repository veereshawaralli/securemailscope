"""End-to-end regression: generate the synthetic corpus, run the full analysis
pipeline and assert the known posture scoreboard, then exercise the JSON / HTML
/ PDF report writers and the ML risk model on real analysis output.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from securemailscope.analysis.engine import full_dict
from securemailscope.ml.model import load_default
from securemailscope.report import html_report, json_report

from tests import _corpus as corpus


class TestScenarioScoreboard(unittest.TestCase):
    def test_each_scenario_matches_expected(self):
        for name, (grade, score, top, must) in corpus.EXPECTED.items():
            with self.subTest(scenario=name):
                s = corpus.single(name)
                ids = {f.id for f in s.findings}
                self.assertEqual(s.grade, grade)
                self.assertEqual(s.score, score)
                self.assertEqual(s.findings[0].id, top)
                self.assertTrue(must.issubset(ids), f"missing {must - ids}")

    def test_findings_sorted_most_severe_first(self):
        s = corpus.single("03_imap_legacy_tls10")
        levels = [int(f.severity) for f in s.findings]
        self.assertEqual(levels, sorted(levels, reverse=True))


class TestCombinedCapture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = corpus.analyze_named("all")

    def test_session_count(self):
        self.assertEqual(len(self.res.sessions), corpus.SESSION_COUNT)

    def test_overall_posture(self):
        self.assertEqual(self.res.overall_grade, corpus.OVERALL_GRADE)
        self.assertEqual(self.res.overall_score, corpus.OVERALL_SCORE)

    def test_full_dict_shape(self):
        d = full_dict(self.res)
        for key in ("source", "session_count", "overall_score", "overall_grade",
                    "severity_totals", "sessions", "recommendations"):
            self.assertIn(key, d)
        self.assertEqual(d["session_count"], corpus.SESSION_COUNT)
        for sess in d["sessions"]:
            for k in ("stream", "protocol", "server_port", "summary",
                      "findings", "features", "score", "grade",
                      "severity_counts"):
                self.assertIn(k, sess)

    def test_recommendations_prioritized_and_actionable(self):
        recs = full_dict(self.res)["recommendations"]
        self.assertTrue(recs)
        levels = [r["severity_level"] for r in recs]
        self.assertEqual(levels, sorted(levels, reverse=True))
        crit = [r for r in recs if r["severity_level"] == 4]
        self.assertTrue(any("SMS-AUTH-CLEARTEXT" in r["finding_ids"]
                            for r in crit))


class TestReports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = corpus.analyze_named("all")
        cls.tmp = tempfile.mkdtemp(prefix="sms-report-")

    def test_json_report_is_valid_and_roundtrips(self):
        d = json.loads(json_report.render(self.res))
        self.assertEqual(d["overall_grade"], corpus.OVERALL_GRADE)
        path = json_report.write(self.res, os.path.join(self.tmp, "r.json"))
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["session_count"],
                             corpus.SESSION_COUNT)

    def test_html_report_is_self_contained(self):
        html = html_report.render(self.res)
        self.assertTrue(html.lstrip().lower().startswith("<!doctype html"))
        self.assertIn("const DATA=", html)          # analysis data inlined
        for placeholder in ("__SMS_DATA__", "__CSS__", "__JS__"):
            self.assertNotIn(placeholder, html)     # all templating resolved

    def test_pdf_report_optional(self):
        try:
            from securemailscope.report import pdf_report
        except Exception as e:                      # reportlab absent
            self.skipTest(f"reportlab unavailable: {e}")
        path = os.path.join(self.tmp, "r.pdf")
        try:
            pdf_report.write(self.res, path)
        except RuntimeError as e:                   # reportlab absent at call
            self.skipTest(str(e))
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(5), b"%PDF-")


class TestMlModel(unittest.TestCase):
    def test_predict_shape_and_labels(self):
        ml = load_default()
        labels = {"minimal", "low", "medium", "high", "critical"}
        for s in corpus.analyze_named("all").sessions:
            pred = ml.predict(s.features)
            self.assertIn(pred["risk_label"], labels)
            self.assertGreaterEqual(pred["confidence"], 0.0)
            self.assertLessEqual(pred["confidence"], 1.0)
            self.assertIsInstance(pred["anomaly"], bool)

    def test_ml_annotations_attached_to_sessions(self):
        res = corpus.analyze_named("all", ml=load_default())
        for s in res.sessions:
            self.assertIn("ml_risk", s.summary)
            self.assertIn("ml_confidence", s.summary)


if __name__ == "__main__":            # pragma: no cover
    unittest.main()
