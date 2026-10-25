"""Offline tests for validation, scoring, coverage and reports (NFR-12).
Run from the project root:  python -m unittest discover -s tests -v"""
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulnscan import pipeline, reports  # noqa: E402
from vulnscan.config import load_config  # noqa: E402
from vulnscan.validation import clean_context, to_bool, validate_target  # noqa: E402

CTX = {"asset_name": "Web <b>srv</b>", "business_function": "HR", "criticality": "high",
       "internet_facing": True, "sensitive_data": False}


class ValidationTests(unittest.TestCase):
    def test_accepts_valid_targets(self):
        self.assertEqual(validate_target(" 192.168.56.101 "), "192.168.56.101")
        self.assertEqual(validate_target("10.0.0.0/28"), "10.0.0.0/28")
        self.assertEqual(validate_target("Host.Local"), "host.local")

    def test_rejects_injection_and_large_ranges(self):
        for bad in ["", "-oN out.txt", "1.2.3.4; rm -rf /", "a b", "10.0.0.0/16", "$(id)"]:
            with self.assertRaises(ValueError, msg=bad):
                validate_target(bad)

    def test_bool_normalisation(self):
        self.assertTrue(to_bool("on") and to_bool("True") and to_bool(True))
        self.assertFalse(to_bool("false") or to_bool(None) or to_bool(""))

    def test_clean_context_defaults(self):
        ctx = clean_context({"criticality": "extreme", "internet_facing": "yes"})
        self.assertEqual(ctx["criticality"], "medium")
        self.assertIs(ctx["internet_facing"], True)
        self.assertIs(ctx["sensitive_data"], False)


class ScoringTests(unittest.TestCase):
    def test_severity_bands_by_version(self):            # FR-07 / NFR-01
        self.assertEqual(pipeline.severity_from_cvss(9.8, "3.1"), "CRITICAL")
        self.assertEqual(pipeline.severity_from_cvss(9.8, "2.0"), "HIGH")
        self.assertEqual(pipeline.severity_from_cvss(0, "3.1"), "NONE")
        self.assertEqual(pipeline.severity_from_cvss(None, "3.0"), "NONE")
        self.assertEqual(pipeline.severity_from_cvss(3.9, "2.0"), "LOW")

    def test_detection_confidence(self):                  # FR-14 / FR-09
        self.assertEqual(pipeline.detection_confidence("OpenSSH", "7.4"), "High")
        self.assertEqual(pipeline.detection_confidence("OpenSSH", ""), "Medium")
        self.assertEqual(pipeline.detection_confidence("", ""), "Low")
        self.assertEqual(pipeline.lower_confidence("High"), "Medium")
        self.assertEqual(pipeline.lower_confidence("Low"), "Low")

    def test_context_raises_risk_and_caps(self):          # FR-15
        self.assertEqual(pipeline.contextual_risk(5.0, {"criticality": "medium"}), 5.0)
        self.assertGreater(pipeline.contextual_risk(5.0, CTX), 5.0)
        self.assertEqual(pipeline.contextual_risk(9.8, CTX), 10.0)

    def test_priority_bands(self):                        # FR-16
        self.assertEqual([pipeline.priority_from_risk(x) for x in (9.0, 7.0, 4.0, 3.9)],
                         ["P1", "P2", "P3", "P4"])


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cfg = load_config()
        cfg["backend"] = "demo"
        cls.events = []
        cls.result = pipeline.run(cfg, "192.168.56.101", "service", CTX,
                                  emit=lambda *e: cls.events.append(e))

    def test_progress_reaches_done(self):
        self.assertEqual(self.events[-1][0], "done")
        self.assertEqual(self.events[-1][1], 100)

    def test_coverage_reported(self):                     # FR-10 / FR-20 / NFR-06
        s = self.result["summary"]
        self.assertFalse(s["complete"])
        reasons = {c["port"]: c["reason"] for c in pipeline.coverage_rows(self.result)
                   if not c["assessed"]}
        self.assertIn(8080, reasons)
        self.assertIn("No version", reasons[8080])
        self.assertIn(443, reasons)                       # API failure != no findings (FR-11)

    def test_findings_in_priority_order(self):            # NFR-04
        keys = [pipeline._finding_key(f) for f in pipeline.flat_findings(self.result)]
        self.assertEqual(keys, sorted(keys))

    def test_keyword_match_lowers_confidence(self):
        mysql = [f for f in pipeline.flat_findings(self.result) if f["port"] == 3306][0]
        self.assertEqual(mysql["match_method"], "keyword")
        self.assertEqual(mysql["confidence"], "Medium")

    def test_missing_mitigation_gets_fallback(self):
        hosts = [{"ip": "10.0.0.5", "ports": [{"port": 22, "protocol": "tcp",
                  "service": "ssh", "product": "OpenSSH", "version": "7.4",
                  "cves": [{"id": "CVE-2000-0001", "cvss": 5.0}]}]}]
        r = pipeline.finalise("10.0.0.5", "service", hosts, CTX)
        m = pipeline.flat_findings(r)[0]["mitigation"]
        self.assertEqual(m["source"], "fallback")
        self.assertIn("nvd.nist.gov", m["references"][0])

    def test_cancel(self):
        cfg = load_config()
        cfg["backend"] = "demo"
        ev = threading.Event()
        ev.set()
        with self.assertRaises(pipeline.ScanCancelled):
            pipeline.run(cfg, "10.0.0.1", "quick", CTX, emit=lambda *e: None,
                         cancel_event=ev)


class ReportTests(unittest.TestCase):
    def setUp(self):
        cfg = load_config()
        cfg["backend"] = "demo"
        self.profile = cfg["profiles"]["service"]
        result = pipeline.run(cfg, "192.168.56.101", "service", CTX, emit=lambda *e: None)
        self.scan = {"id": "abc123", "target": "192.168.56.101", "profile": "service",
                     "context": CTX, "created_at": "2026-10-25T14:00:00",
                     "finished_at": "2026-10-25T14:01:00", "result": result}

    def test_html_escapes_and_states_sensitivity(self):  # NFR-10
        out = reports.build_html(self.scan, self.profile)
        self.assertNotIn("<b>srv</b>", out)
        self.assertIn("Web &lt;b&gt;srv&lt;/b&gt;", out)
        self.assertIn("CONFIDENTIAL", out)
        self.assertIn("Not assessed", out)

    def test_pdf_written(self):
        try:
            import reportlab  # noqa: F401
        except ImportError:
            self.skipTest("reportlab not installed")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.pdf")
            reports.write_pdf(self.scan, self.profile, path)
            with open(path, "rb") as fh:
                self.assertEqual(fh.read(4), b"%PDF")


if __name__ == "__main__":
    unittest.main()
