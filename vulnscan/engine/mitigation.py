"""AI mitigation recommendations with Gemini 2.5 Flash (FR-17, IR section 2.3.5).

Safeguards described in the IR:
- The model only receives a structured record (CVE id, CVSS, service/version,
  asset context) and is told to use nothing else.
- It must return JSON with a summary and remediation steps (response schema).
- Output that isn't valid JSON or lacks non-empty fields is discarded, and the
  static fallback (pointing to the NVD record) is used instead. API failures fall
  back the same way, so an outage never breaks the report.
- References are taken from the NVD record, never from the model.
"""
import json
import time

import requests

API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "summary": {"type": "STRING"},
        "steps": {"type": "ARRAY", "items": {"type": "STRING"}},
    },
    "required": ["summary", "steps"],
}

INSTRUCTIONS = """You are helping a non-expert secure their own system.
Write a remediation recommendation for ONE vulnerability finding.
Use ONLY the fields in the record below. Do not add facts about the CVE,
affected versions or fixes that the record does not support. If the record
does not say which version fixes the issue, tell the user to check the vendor
advisory linked from the NVD record instead of guessing a version number.
Take the asset context into account when ordering the steps (for example,
restricting exposure first for an internet-facing asset).
Return JSON: "summary" = one or two plain-English sentences on the risk and the
main action; "steps" = 2 to 5 short, concrete remediation steps."""

DISABLED_TEXT = ("AI recommendations are turned off because no GEMINI_API_KEY is set. "
                 "Review the linked NVD record for vendor guidance.")
LIMIT_TEXT = ("Not generated: the per-scan limit for AI recommendations was reached. "
              "Review the linked NVD record for vendor guidance.")


def build_record(finding, context) -> dict:
    return {
        "cve_id": finding["id"],
        "cvss_score": finding.get("cvss"),
        "cvss_version": finding.get("cvss_version"),
        "cvss_vector": finding.get("cvss_vector", ""),
        "description": finding.get("description", ""),
        "service": finding.get("service", ""),
        "product": finding.get("product", ""),
        "version": finding.get("version", ""),
        "port": f"{finding.get('port')}/{finding.get('protocol', 'tcp')}",
        "asset_context": {
            "asset_name": context.get("asset_name", ""),
            "business_function": context.get("business_function", ""),
            "criticality": context.get("criticality", "medium"),
            "internet_facing": bool(context.get("internet_facing")),
            "holds_sensitive_data": bool(context.get("sensitive_data")),
        },
    }


def validate(text):
    """Structural validation: valid JSON with a non-empty summary and steps."""
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    summary = data.get("summary")
    steps = data.get("steps")
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 800:
        return None
    if not isinstance(steps, list):
        return None
    steps = [s.strip() for s in steps if isinstance(s, str) and s.strip()]
    if not steps:
        return None
    return {"summary": summary.strip(), "steps": [s[:400] for s in steps[:6]]}


class MitigationGenerator:
    """Calls Gemini, trying each configured model in order. A model that the API
    reports as unavailable (HTTP 404) is skipped for the rest of the scan; errors
    that will affect every request (bad key, no access) stop further AI calls so
    the scan doesn't wait on requests that cannot succeed."""

    FATAL_STATUS = {400, 401, 403}
    TRANSIENT_STATUS = {429, 500, 502, 503, 504}
    BUSY_LIMIT = 2     # give up for this scan after N findings where every model was busy

    def __init__(self, cfg, session=None, clock=time.monotonic):
        self.api_key = cfg.get("api_key", "")
        models = cfg.get("models") or [cfg.get("model") or "gemini-3.8-flash"]
        self.models = [m for m in models if m]
        self.timeout = float(cfg.get("timeout_seconds", 30))
        self.delay = float(cfg.get("delay_seconds", 6.5))
        self.max_findings = int(cfg.get("max_findings", 15))
        self.session = session or requests.Session()
        self.clock = clock
        self._last = None
        self.last_error = ""
        self.stopped = ""          # set when no further AI calls should be made
        self.used_model = ""
        self.backoff = [float(x) for x in cfg.get("retry_backoff_seconds", [8, 20])]
        self._busy_streak = 0

    @property
    def enabled(self):
        return bool(self.api_key)

    @staticmethod
    def _api_message(resp):
        try:
            return str(resp.json()["error"]["message"])[:160]
        except (ValueError, KeyError, TypeError):
            return (getattr(resp, "text", "") or "")[:160]

    def _post(self, model, body, wait):
        if self._last is not None:
            remaining = self.delay - (self.clock() - self._last)
            if remaining > 0:
                wait(remaining)
        self._last = self.clock()
        return self.session.post(
            API_URL.format(model=model), json=body, timeout=self.timeout,
            headers={"x-goog-api-key": self.api_key, "Content-Type": "application/json"})

    def generate(self, finding, context, wait):
        """Return {'summary', 'steps'} or None (caller uses the static fallback)."""
        self.last_error = ""
        if not self.enabled:
            return None
        if self.stopped:
            self.last_error = self.stopped
            return None
        body = {
            "contents": [{"role": "user", "parts": [{"text": INSTRUCTIONS + "\n\nRecord:\n"
                          + json.dumps(build_record(finding, context), indent=2)}]}],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json",
                "responseSchema": RESPONSE_SCHEMA,
            },
        }
        busy_error = ""
        for model in list(self.models):
            resp, err = None, ""
            for attempt in range(len(self.backoff) + 1):
                try:
                    resp = self._post(model, body, wait)
                    err = ""
                except requests.RequestException as exc:
                    resp, err = None, f"request failed: {type(exc).__name__}"
                if resp is not None and resp.status_code not in self.TRANSIENT_STATUS:
                    break
                if attempt < len(self.backoff):
                    wait(self.backoff[attempt])        # temporary problem: back off, retry

            if resp is None or resp.status_code in self.TRANSIENT_STATUS:
                busy_error = err or f"HTTP {resp.status_code}: {self._api_message(resp)}"
                continue                               # overloaded: try the next model
            if resp.status_code == 404:
                # Model retired or not available to this key: drop it for this scan.
                self.last_error = f"model {model} unavailable ({self._api_message(resp)})"
                self.models.remove(model)
                continue
            if resp.status_code in self.FATAL_STATUS:
                self.stopped = f"HTTP {resp.status_code}: {self._api_message(resp)}"
                self.last_error = self.stopped
                return None
            if resp.status_code != 200:
                self.last_error = f"HTTP {resp.status_code}: {self._api_message(resp)}"
                return None

            self._busy_streak = 0
            try:
                payload = resp.json()
                parts = payload["candidates"][0]["content"]["parts"]
                text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
            except (ValueError, KeyError, IndexError, TypeError):
                reason = ""
                try:
                    reason = payload["candidates"][0].get("finishReason", "")
                except Exception:
                    pass
                self.last_error = "unexpected response format" + (f" ({reason})" if reason else "")
                return None
            self.used_model = model
            result = validate(text)
            if result is None:
                self.last_error = "response failed validation"
            return result

        if not self.models:
            self.stopped = ("no configured Gemini model is available to this API key"
                            + (f"; last error: {self.last_error}" if self.last_error else ""))
            self.last_error = self.stopped
            return None
        # Every model was busy or unreachable for this finding.
        self._busy_streak += 1
        self.last_error = f"Gemini busy ({busy_error}). Use Retry AI advice later"
        if self._busy_streak >= self.BUSY_LIMIT:
            self.stopped = self.last_error
        return None
