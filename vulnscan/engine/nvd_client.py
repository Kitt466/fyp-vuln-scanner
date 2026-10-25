"""NVD CVE 2.0 API client (FR-05..FR-12, NFR-03, NFR-07).

- Structured CPE matching first (virtualMatchString), keyword search only as a
  fallback, and keyword results are flagged as lower confidence (FR-08/09).
- A failed or rejected request is reported as an error, never as "no CVEs" (FR-11).
- Requests are paced to the NVD rate limit, with an optional API key (FR-12).
- Every request has a timeout (NFR-03); repeated product/version pairs are
  answered from a per-scan cache (NFR-07).
"""
import re
import time

import requests

USER_AGENT = "VulnScan/0.3 (FYP vulnerability scanner)"
RETRY_STATUS = {403, 429, 500, 502, 503, 504}   # NVD answers 403 when rate limited


class NVDResult:
    def __init__(self, status, cves=None, method="", error="", total=0):
        self.status = status          # "ok" or "error"
        self.cves = cves or []
        self.method = method          # "cpe" or "keyword"
        self.error = error
        self.total = total            # matches reported by NVD
        self.found = len(self.cves)   # usable records before the per-service cap

    @property
    def ok(self):
        return self.status == "ok"


# --------------------------------------------------------------------------
# CPE helpers
# --------------------------------------------------------------------------
_VER_SUFFIX = re.compile(r"^(\d+(?:\.\d+)*)([a-z][a-z0-9]*)$", re.I)


def normalise_version(version: str):
    """'7.4p1 Debian 10' -> ('7.4', 'p1'); '8.0.32-0ubuntu0.20.04' -> ('8.0.32', '')."""
    token = (version or "").strip().split(" ")[0].split("-")[0].split("+")[0]
    m = _VER_SUFFIX.match(token)
    if m:
        return m.group(1), m.group(2).lower()
    return token, ""


def cpe_for(nmap_cpes, version):
    """Build a CPE 2.3 match string from Nmap's CPE (2.2 format) and the version."""
    for raw in nmap_cpes or []:
        if not raw.startswith("cpe:/a:"):
            continue
        parts = raw[len("cpe:/"):].split(":")
        if len(parts) < 3:
            continue
        vendor, product = parts[1].lower(), parts[2].lower()
        ver, update = normalise_version(parts[3] if len(parts) > 3 and parts[3] else version)
        if not ver:
            return None
        cpe = f"cpe:2.3:a:{vendor}:{product}:{ver}"
        return cpe + (f":{update}" if update else "")
    return None


# --------------------------------------------------------------------------
# Record parsing
# --------------------------------------------------------------------------
def extract_cvss(metrics):
    """FR-06: return (score, version, vector) preferring v3.1, then v3.0, then v2.
    Records not yet scored by NVD return (None, None, '')."""
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                         ("cvssMetricV2", "2.0")):
        entries = (metrics or {}).get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData") or {}
        if data.get("baseScore") is not None:
            return float(data["baseScore"]), version, data.get("vectorString", "")
    return None, None, ""


def parse_vulnerabilities(payload, method):
    cves = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve") or {}
        if not cve.get("id") or cve.get("vulnStatus") == "Rejected":
            continue
        score, version, vector = extract_cvss(cve.get("metrics"))
        desc = next((d.get("value", "") for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), "")
        refs = [r.get("url") for r in cve.get("references", []) if r.get("url")][:3]
        cves.append({
            "id": cve["id"],
            "cvss": score if score is not None else 0.0,
            "cvss_version": version or "n/a",
            "cvss_vector": vector,
            "scored": score is not None,
            "description": desc or "No description provided by NVD.",
            "published": (cve.get("published") or "")[:10],
            "match_method": method,
            "nvd_references": refs,
        })
    cves.sort(key=lambda c: c["cvss"], reverse=True)
    return cves


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------
class NVDClient:
    def __init__(self, cfg, session=None, clock=time.monotonic):
        self.base_url = cfg["base_url"]
        self.timeout = float(cfg.get("timeout_seconds", 15))
        self.api_key = cfg.get("api_key", "")
        self.delay = float(cfg.get("delay_with_key" if self.api_key else "delay_without_key", 6.0))
        self.per_page = int(cfg.get("results_per_page", 50))
        self.max_cves = int(cfg.get("max_cves_per_service", 20))
        self.retries = int(cfg.get("retries", 2))
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})
        self.clock = clock
        self._last_request = None
        self._cache = {}

    def lookup(self, product, version, nmap_cpes, wait) -> NVDResult:
        """Find CVEs for one detected service. `wait(seconds)` is a cancellable sleep."""
        key = ((product or "").lower(), (version or "").lower())
        if key in self._cache:                       # NFR-07
            return self._cache[key]

        cpe = cpe_for(nmap_cpes, version)
        result = None
        if cpe:
            result = self._query({"virtualMatchString": cpe}, "cpe", wait)
            if result.ok and not result.cves:
                result = None    # CPE name may differ from NVD's dictionary: try keyword
        if result is None:
            ver, update = normalise_version(version)
            keyword = f"{product} {ver}{update}".strip()
            result = self._query({"keywordSearch": keyword}, "keyword", wait)

        if result.ok:
            result.found = len(result.cves)           # usable records before the cap
            result.cves = result.cves[: self.max_cves]
        self._cache[key] = result
        return result

    def _pace(self, wait):
        if self._last_request is not None:
            remaining = self.delay - (self.clock() - self._last_request)
            if remaining > 0:
                wait(remaining)

    def _query(self, params, method, wait) -> NVDResult:
        params = {**params, "resultsPerPage": self.per_page}
        error = ""
        for attempt in range(self.retries + 1):
            self._pace(wait)
            self._last_request = self.clock()
            try:
                resp = self.session.get(self.base_url, params=params, timeout=self.timeout)
            except requests.Timeout:
                error = f"timed out after {self.timeout:.0f} s"
            except requests.RequestException as exc:
                error = f"connection error: {type(exc).__name__}"
            else:
                if resp.status_code == 200:
                    try:
                        payload = resp.json()
                    except ValueError:
                        return NVDResult("error", method=method, error="invalid JSON from NVD")
                    return NVDResult("ok", parse_vulnerabilities(payload, method), method,
                                     total=int(payload.get("totalResults", 0)))
                error = f"HTTP {resp.status_code}"
                if resp.status_code == 404 and method == "cpe":
                    # Malformed/unknown CPE: treat as "no structured match".
                    return NVDResult("ok", [], method)
                if resp.status_code not in RETRY_STATUS:
                    break
            if attempt < self.retries:
                wait(self.delay * (attempt + 2))     # back off before retrying
        return NVDResult("error", method=method, error=error)
