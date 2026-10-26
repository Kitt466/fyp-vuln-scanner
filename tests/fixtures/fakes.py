"""Fake HTTP sessions replaying recorded-style NVD and Gemini responses."""
import json


class FakeResponse:
    def __init__(self, status, payload=None, text=None):
        self.status_code = status
        self._payload = payload
        self.text = text if text is not None else json.dumps(payload or {})

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


def nvd_record(cve_id, metrics, desc="Test vulnerability description.", status="Analyzed"):
    return {"cve": {"id": cve_id, "vulnStatus": status, "published": "2021-10-05T09:15:07",
                    "descriptions": [{"lang": "es", "value": "es"}, {"lang": "en", "value": desc}],
                    "metrics": metrics,
                    "references": [{"url": f"https://example.org/{cve_id}"}]}}


def v31(score, kind="Primary"):
    return {"cvssMetricV31": [{"type": kind, "cvssData": {
        "version": "3.1", "baseScore": score, "baseSeverity": "CRITICAL",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}


def v2(score):
    return {"cvssMetricV2": [{"type": "Primary", "cvssData": {
        "version": "2.0", "baseScore": score, "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}}]}


def page(*records):
    return {"totalResults": len(records), "vulnerabilities": list(records)}


VSFTPD = page(nvd_record("CVE-2011-2523", {
    "cvssMetricV31": [
        {"type": "Secondary", "cvssData": {"baseScore": 7.0, "vectorString": "x"}},
        {"type": "Primary", "cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N"}},
    ]}, "vsftpd 2.3.4 backdoor."))
APACHE_KEYWORD = page(
    nvd_record("CVE-2021-41773", v2(5.0), "Apache 2.4.49 path traversal."),
    nvd_record("CVE-2099-0001", {}, "Awaiting analysis.", status="Awaiting Analysis"),
    nvd_record("CVE-2099-0002", v31(9.0), "Rejected entry.", status="Rejected"),
)


class FakeNVDSession:
    """Routes NVD queries by their parameters; records every request."""

    def __init__(self):
        self.headers = {}
        self.calls = []

    def get(self, url, params=None, timeout=None):
        assert timeout, "every NVD request must set a timeout (NFR-03)"
        self.calls.append(dict(params))
        cpe = params.get("virtualMatchString", "")
        kw = params.get("keywordSearch", "")
        if "vsftpd" in cpe:
            return FakeResponse(200, VSFTPD)
        if "openssh" in cpe:
            return FakeResponse(503, text="Service Unavailable")
        if "http_server" in cpe:
            return FakeResponse(200, page())
        if kw.startswith("Apache httpd"):
            return FakeResponse(200, APACHE_KEYWORD)
        return FakeResponse(200, page())


def gemini_reply(obj_or_text):
    text = obj_or_text if isinstance(obj_or_text, str) else json.dumps(obj_or_text)
    return {"candidates": [{"content": {"parts": [{"text": text}]}}]}


class FakeGeminiSession:
    """Returns queued responses in order; records request bodies."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.bodies = []
        self.headers = {}

    def post(self, url, json=None, timeout=None, headers=None):
        assert timeout and headers and headers.get("x-goog-api-key")
        self.bodies.append(json)
        return self.responses.pop(0) if self.responses else FakeResponse(500)


class RoutingSession(FakeNVDSession):
    """One session object serving both NVD (get) and Gemini (post)."""

    def __init__(self, gemini_responses):
        super().__init__()
        self.gemini = FakeGeminiSession(gemini_responses)

    def post(self, *a, **kw):
        return self.gemini.post(*a, **kw)
