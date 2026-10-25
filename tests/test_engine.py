"""Offline tests for the live engine: Nmap parsing and process handling, NVD
correlation, and Gemini validation (NFR-12: no network access needed).
Run from the project root:  python -m unittest discover -s tests -v"""
import os
import stat
import sys
import threading
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures"))

import fakes  # noqa: E402
from vulnscan import pipeline  # noqa: E402
from vulnscan.config import load_config  # noqa: E402
from vulnscan.engine import mitigation as mit  # noqa: E402
from vulnscan.engine import nmap_scanner, nvd_client  # noqa: E402

FIXTURES = os.path.join(ROOT, "tests", "fixtures")
FAKE_NMAP = os.path.join(FIXTURES, "fake_nmap.py")
CTX = {"asset_name": "Lab", "business_function": "Testing", "criticality": "high",
       "internet_facing": True, "sensitive_data": False}
POSIX = os.name == "posix"


def setUpModule():
    if POSIX:
        os.chmod(FAKE_NMAP, os.stat(FAKE_NMAP).st_mode | stat.S_IEXEC)


def no_wait(_seconds):
    return None


class NmapParsingTests(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(FIXTURES, "nmap_sample.xml"), encoding="utf-8") as fh:
            self.hosts = nmap_scanner.parse_xml(fh.read())

    def test_only_up_hosts_and_open_ports(self):
        self.assertEqual(len(self.hosts), 1)
        h = self.hosts[0]
        self.assertEqual((h["ip"], h["hostname"]), ("10.0.0.5", "lab.local"))
        self.assertEqual([p["port"] for p in h["ports"]], [21, 22, 80, 8080])
        self.assertIn("Linux", h["os"])

    def test_service_fields_and_cpe(self):
        ssh = self.hosts[0]["ports"][1]
        self.assertEqual((ssh["product"], ssh["version"]), ("OpenSSH", "7.4"))
        self.assertEqual(ssh["cpe"], ["cpe:/a:openbsd:openssh:7.4"])
        proxy = self.hosts[0]["ports"][3]
        self.assertEqual((proxy["version"], proxy["method"]), ("", "table"))
        self.assertEqual(self.hosts[0]["ports"][2]["scripts"]["http-title"], "Lab page")

    def test_bad_xml_raises_clear_error(self):
        with self.assertRaises(nmap_scanner.NmapError):
            nmap_scanner.parse_xml("<nmaprun><host>")

    def test_version_detection_flag(self):
        self.assertTrue(nmap_scanner.detects_versions("-sV -T4"))
        self.assertFalse(nmap_scanner.detects_versions("-T4 -F"))

    def test_command_has_no_shell_and_target_last(self):
        cmd = nmap_scanner.build_command("nmap", "-sV --script vuln", "10.0.0.5", "o.xml")
        self.assertEqual(cmd[0], "nmap")
        self.assertEqual(cmd[-1], "10.0.0.5")
        self.assertIn("--script", cmd)


@unittest.skipUnless(POSIX, "fake nmap script needs a POSIX shebang")
class NmapProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.chmod(FAKE_NMAP, os.stat(FAKE_NMAP).st_mode | stat.S_IEXEC)

    def test_streams_lines_and_parses(self):
        lines = []
        hosts = nmap_scanner.run_scan(FAKE_NMAP, "-sV", "10.0.0.5", lines.append)
        self.assertEqual(len(hosts[0]["ports"]), 4)
        self.assertTrue(any(nmap_scanner.PROGRESS_RE.match(l) for l in lines))
        self.assertTrue(any(nmap_scanner.DISCOVERED_RE.match(l) for l in lines))

    def test_cancel_terminates_nmap(self):
        class Stop(Exception):
            pass
        seen = []

        def on_line(line):
            seen.append(line)
            if len(seen) == 6:
                raise Stop()
        with mock.patch.dict(os.environ, {"FAKE_NMAP_MODE": "slow"}):
            with self.assertRaises(Stop):
                nmap_scanner.run_scan(FAKE_NMAP, "-sV", "10.0.0.5", on_line)

    def test_root_error_is_explained(self):
        with mock.patch.dict(os.environ, {"FAKE_NMAP_MODE": "root"}):
            with self.assertRaises(nmap_scanner.NmapError) as ctx:
                nmap_scanner.run_scan(FAKE_NMAP, "-O", "10.0.0.5", lambda l: None)
        self.assertIn("administrator", str(ctx.exception))


class CpeAndCvssTests(unittest.TestCase):
    def test_normalise_version(self):
        self.assertEqual(nvd_client.normalise_version("7.4p1 Debian 10"), ("7.4", "p1"))
        self.assertEqual(nvd_client.normalise_version("8.0.32-0ubuntu0.20.04.2"), ("8.0.32", ""))
        self.assertEqual(nvd_client.normalise_version("2.4.49"), ("2.4.49", ""))

    def test_cpe_conversion(self):
        self.assertEqual(nvd_client.cpe_for(["cpe:/a:apache:http_server:2.4.49"], "2.4.49"),
                         "cpe:2.3:a:apache:http_server:2.4.49")
        self.assertEqual(nvd_client.cpe_for(["cpe:/a:openbsd:openssh"], "7.4p1"),
                         "cpe:2.3:a:openbsd:openssh:7.4:p1")
        self.assertIsNone(nvd_client.cpe_for(["cpe:/o:linux:linux_kernel"], "4.15"))
        self.assertIsNone(nvd_client.cpe_for([], "1.0"))

    def test_cvss_extraction_all_versions(self):          # FR-06, NFR-01
        self.assertEqual(nvd_client.extract_cvss(fakes.v31(9.8))[:2], (9.8, "3.1"))
        self.assertEqual(nvd_client.extract_cvss(
            {"cvssMetricV30": [{"type": "Primary", "cvssData": {"baseScore": 7.5}}]})[:2],
            (7.5, "3.0"))
        self.assertEqual(nvd_client.extract_cvss(fakes.v2(5.0))[:2], (5.0, "2.0"))
        self.assertEqual(nvd_client.extract_cvss({}), (None, None, ""))
        both = {**fakes.v2(4.0), **fakes.v31(8.1)}
        self.assertEqual(nvd_client.extract_cvss(both)[1], "3.1")

    def test_primary_metric_preferred(self):
        recs = nvd_client.parse_vulnerabilities(fakes.VSFTPD, "cpe")
        self.assertEqual(recs[0]["cvss"], 9.8)

    def test_v2_bands_and_rejected_and_unscored(self):     # FR-07
        recs = nvd_client.parse_vulnerabilities(fakes.APACHE_KEYWORD, "keyword")
        ids = [r["id"] for r in recs]
        self.assertNotIn("CVE-2099-0002", ids)            # rejected records dropped
        unscored = [r for r in recs if r["id"] == "CVE-2099-0001"][0]
        self.assertFalse(unscored["scored"])
        self.assertEqual(pipeline.severity_from_cvss(9.5, "2.0"), "HIGH")


class NVDClientTests(unittest.TestCase):
    def make(self, **cfg):
        base = load_config()["nvd"]
        base.update(cfg)
        self.session = fakes.FakeNVDSession()
        self.waits = []
        return nvd_client.NVDClient(base, session=self.session, clock=lambda: 0.0)

    def test_cpe_match_first(self):                       # FR-08
        c = self.make()
        r = c.lookup("vsftpd", "2.3.4", ["cpe:/a:vsftpd:vsftpd:2.3.4"], self.waits.append)
        self.assertTrue(r.ok)
        self.assertEqual((r.method, r.cves[0]["id"]), ("cpe", "CVE-2011-2523"))
        self.assertIn("virtualMatchString", self.session.calls[0])

    def test_keyword_fallback_flagged(self):              # FR-08/09
        c = self.make()
        r = c.lookup("Apache httpd", "2.4.49", ["cpe:/a:apache:http_server:2.4.49"],
                     self.waits.append)
        self.assertEqual(r.method, "keyword")
        self.assertTrue(all(x["match_method"] == "keyword" for x in r.cves))

    def test_failure_is_not_empty_result(self):           # FR-11
        c = self.make(retries=2)
        r = c.lookup("OpenSSH", "7.4", ["cpe:/a:openbsd:openssh:7.4"], self.waits.append)
        self.assertFalse(r.ok)
        self.assertIn("503", r.error)
        self.assertEqual(len(self.session.calls), 3)      # 1 try + 2 retries
        self.assertTrue(self.waits)                       # backed off between retries

    def test_cache_prevents_duplicate_queries(self):      # NFR-07
        c = self.make()
        c.lookup("vsftpd", "2.3.4", ["cpe:/a:vsftpd:vsftpd:2.3.4"], no_wait)
        c.lookup("vsftpd", "2.3.4", ["cpe:/a:vsftpd:vsftpd:2.3.4"], no_wait)
        self.assertEqual(len(self.session.calls), 1)

    def test_pacing_and_api_key(self):                    # FR-12
        c = self.make(api_key="secret", delay_with_key=0.6)
        self.assertEqual(self.session.headers.get("apiKey"), "secret")
        c.lookup("vsftpd", "2.3.4", ["cpe:/a:vsftpd:vsftpd:2.3.4"], self.waits.append)
        c.lookup("Apache httpd", "2.4.49", ["cpe:/a:apache:http_server:2.4.49"],
                 self.waits.append)
        self.assertTrue(self.waits and all(abs(w - 0.6) < 1e-9 for w in self.waits))


class MitigationTests(unittest.TestCase):
    FINDING = {"id": "CVE-2011-2523", "cvss": 9.8, "cvss_version": "3.1",
               "description": "backdoor", "service": "ftp", "product": "vsftpd",
               "version": "2.3.4", "port": 21, "protocol": "tcp"}

    def test_validation(self):
        self.assertEqual(mit.validate('{"summary": "Do X", "steps": ["a", " ", "b"]}'),
                         {"summary": "Do X", "steps": ["a", "b"]})
        for bad in ["not json", "[]", '{"summary": "", "steps": ["a"]}',
                    '{"summary": "x", "steps": []}', '{"summary": "x"}', None]:
            self.assertIsNone(mit.validate(bad), bad)

    def gen(self, responses, key="k"):
        cfg = {**load_config()["gemini"], "api_key": key}
        self.session = fakes.FakeGeminiSession(responses)
        return mit.MitigationGenerator(cfg, session=self.session, clock=lambda: 0.0)

    def test_valid_response_used_and_prompt_is_structured(self):
        g = self.gen([fakes.FakeResponse(200, fakes.gemini_reply(
            {"summary": "Replace vsftpd.", "steps": ["Upgrade", "Block 6200"]}))])
        out = g.generate(self.FINDING, CTX, no_wait)
        self.assertEqual(out["steps"], ["Upgrade", "Block 6200"])
        body = self.session.bodies[0]
        self.assertEqual(body["generationConfig"]["responseMimeType"], "application/json")
        prompt = body["contents"][0]["parts"][0]["text"]
        self.assertIn("CVE-2011-2523", prompt)
        self.assertIn('"internet_facing": true', prompt)

    def test_invalid_or_failed_response_falls_back(self):
        g = self.gen([fakes.FakeResponse(200, fakes.gemini_reply("I think you should...")),
                      fakes.FakeResponse(422, text="oops")])
        self.assertIsNone(g.generate(self.FINDING, CTX, no_wait))
        self.assertEqual(g.last_error, "response failed validation")
        self.assertIsNone(g.generate(self.FINDING, CTX, no_wait))
        self.assertTrue(g.last_error.startswith("HTTP 422"))

    def test_busy_model_retried_then_next_model(self):          # HTTP 503 high demand
        busy = lambda: fakes.FakeResponse(503, {"error": {"message": "high demand"}})
        ok = fakes.FakeResponse(200, fakes.gemini_reply({"summary": "Fix.", "steps": ["Do it"]}))
        g = self.gen([busy(), busy(), busy(), ok])
        g.models = ["big", "lite"]
        waits = []
        out = g.generate(self.FINDING, CTX, waits.append)
        self.assertEqual(out["summary"], "Fix.")
        self.assertEqual(g.used_model, "lite")
        self.assertEqual([w for w in waits if w >= 8], [8.0, 20.0])   # backoff before retries

    def test_persistent_overload_stops_after_limit(self):
        g = self.gen([])                       # queue empty -> every call returns 500
        g.models = ["only"]
        g.backoff = []
        self.assertIsNone(g.generate(self.FINDING, CTX, no_wait))
        self.assertIn("Retry AI advice", g.last_error)
        self.assertFalse(g.stopped)
        self.assertIsNone(g.generate(self.FINDING, CTX, no_wait))
        self.assertTrue(g.stopped)             # second busy finding: stop for this scan
        calls = len(self.session.bodies)
        self.assertIsNone(g.generate(self.FINDING, CTX, no_wait))
        self.assertEqual(len(self.session.bodies), calls)

    def test_retired_model_falls_through_to_next(self):
        retired = fakes.FakeResponse(404, {"error": {"message":
                                     "This model models/gemini-2.5-flash is no longer available."}})
        ok = fakes.FakeResponse(200, fakes.gemini_reply({"summary": "Patch it.", "steps": ["Upgrade"]}))
        g = self.gen([retired, ok])
        g.models = ["gemini-2.5-flash", "gemini-3.8-flash"]
        self.assertEqual(g.generate(self.FINDING, CTX, no_wait)["summary"], "Patch it.")
        self.assertEqual(g.used_model, "gemini-3.8-flash")
        self.assertEqual(len(self.session.bodies), 2)

    def test_bad_key_stops_further_calls(self):
        bad = fakes.FakeResponse(400, {"error": {"message": "API key not valid."}})
        g = self.gen([bad])
        self.assertIsNone(g.generate(self.FINDING, CTX, no_wait))
        self.assertIn("API key not valid", g.last_error)
        self.assertIsNone(g.generate(self.FINDING, CTX, no_wait))
        self.assertEqual(len(self.session.bodies), 1)          # no second request

    def test_all_models_unavailable(self):
        gone = lambda: fakes.FakeResponse(404, {"error": {"message": "no longer available"}})
        g = self.gen([gone(), gone()])
        g.models = ["a", "b"]
        self.assertIsNone(g.generate(self.FINDING, CTX, no_wait))
        self.assertIn("no configured Gemini model", g.last_error)

    def test_disabled_without_key(self):
        g = self.gen([], key="")
        self.assertFalse(g.enabled)
        self.assertIsNone(g.generate(self.FINDING, CTX, no_wait))


@unittest.skipUnless(POSIX, "fake nmap script needs a POSIX shebang")
class EndToEndEngineTests(unittest.TestCase):
    """Full live pipeline with fake nmap, NVD and Gemini."""

    def run_engine(self, gemini_key="k", profile="service", responses=None):
        cfg = load_config()
        cfg["nmap"]["path"] = FAKE_NMAP
        cfg["gemini"]["api_key"] = gemini_key
        os.chmod(FAKE_NMAP, os.stat(FAKE_NMAP).st_mode | stat.S_IEXEC)
        if responses is None:
            responses = [
                fakes.FakeResponse(200, fakes.gemini_reply(
                    {"summary": "Replace the backdoored vsftpd.", "steps": ["Upgrade", "Block 6200"]})),
                fakes.FakeResponse(200, fakes.gemini_reply("not json")),
            ]
        session = fakes.RoutingSession(responses)
        events = []
        with mock.patch("requests.Session", return_value=session):
            result = pipeline.run(cfg, "10.0.0.5", profile, CTX,
                                  emit=lambda *e: events.append(e), backend="engine")
        return result, events, session

    def test_full_pipeline(self):
        result, events, session = self.run_engine()
        self.assertEqual(result["backend"], "engine")
        cov = {c["port"]: c for c in pipeline.coverage_rows(result)}
        self.assertTrue(cov[21]["assessed"])
        self.assertFalse(cov[22]["assessed"])                   # NVD 503 -> not assessed
        self.assertIn("NVD request failed", cov[22]["reason"])
        self.assertEqual(cov[8080]["reason"], "No version string detected")
        self.assertFalse(result["summary"]["complete"])          # NFR-06

        findings = pipeline.flat_findings(result)
        top = findings[0]
        self.assertEqual(top["id"], "CVE-2011-2523")
        self.assertEqual(top["mitigation"]["source"], "ai")
        self.assertIn("nvd.nist.gov", top["mitigation"]["references"][0])
        apache = [f for f in findings if f["port"] == 80]
        self.assertTrue(all(f["match_method"] == "keyword" for f in apache))
        self.assertTrue(all(f["confidence"] == "Medium" for f in apache))   # FR-09
        fallback = [f for f in findings if f["mitigation"]["source"] == "fallback"]
        self.assertTrue(fallback)
        self.assertTrue(all(f["mitigation"]["note"].startswith("AI unavailable") for f in fallback))
        self.assertEqual(top["mitigation"]["model"], "gemini-3.8-flash")
        self.assertEqual(events[-1][0], "done")
        self.assertTrue(all(isinstance(e[1], int) for e in events))

    def test_retry_mitigation_fills_in_missing_advice(self):
        from vulnscan.engine.runner import retry_mitigation, retry_targets
        result, _, _ = self.run_engine(responses=[])          # Gemini fails for all
        self.assertEqual(len(retry_targets(result)), 3)
        cfg = load_config()
        cfg["gemini"]["api_key"] = "k"
        good = lambda: fakes.FakeResponse(200, fakes.gemini_reply(
            {"summary": "Patch.", "steps": ["Upgrade"]}))
        session = fakes.RoutingSession([good(), good(), good()])
        with mock.patch("requests.Session", return_value=session):
            done = retry_mitigation(cfg, result, lambda *e: None, no_wait)
        self.assertEqual(done, 3)
        self.assertEqual(retry_targets(result), [])
        self.assertTrue(all(f["mitigation"]["source"] == "ai"
                            for f in pipeline.flat_findings(result)))

    def test_without_gemini_key_everything_falls_back(self):
        result, _, session = self.run_engine(gemini_key="", responses=[])
        findings = pipeline.flat_findings(result)
        self.assertTrue(findings)
        self.assertTrue(all(f["mitigation"]["source"] == "fallback" for f in findings))
        self.assertEqual(session.gemini.bodies, [])

    def test_quick_profile_reports_why_nothing_was_assessed(self):
        result, _, session = self.run_engine(profile="quick", responses=[])
        reasons = {c["reason"] for c in pipeline.coverage_rows(result)}
        self.assertEqual(len(reasons), 1)
        self.assertIn("does not detect versions", reasons.pop())
        self.assertEqual(session.calls, [])                       # no NVD traffic

    def test_cancel_stops_engine(self):
        cfg = load_config()
        cfg["nmap"]["path"] = FAKE_NMAP
        ev = threading.Event()
        calls = []

        def emit(*e):
            calls.append(e)
            if len(calls) == 3:
                ev.set()
        with mock.patch.dict(os.environ, {"FAKE_NMAP_MODE": "slow"}):
            with self.assertRaises(pipeline.ScanCancelled):
                pipeline.run(cfg, "10.0.0.5", "service", CTX, emit=emit,
                             cancel_event=ev, backend="engine")


if __name__ == "__main__":
    unittest.main()
