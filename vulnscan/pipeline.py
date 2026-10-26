"""Scan pipeline: runs a backend and normalises its output for the GUI and reports.

Normalised result shape (the GUI and reports depend only on this):

    {
      "target": "...", "profile": "service", "context": {...},
      "hosts": [{
        "ip": "...", "hostname": "...", "state": "up",
        "ports": [{
          "port": 22, "protocol": "tcp", "service": "ssh",
          "product": "OpenSSH", "version": "7.4",
          "assessed": True, "not_assessed_reason": "",
          "confidence": "High",                     # FR-14
          "cves": [{
            "id": "CVE-...", "cvss": 5.3, "cvss_version": "3.1",   # FR-06/07
            "severity": "MEDIUM", "description": "...",
            "match_method": "cpe" | "keyword",      # FR-08
            "confidence": "High",                   # FR-09: keyword lowers it
            "risk_score": 6.4, "priority": "P3",    # FR-15/16
            "mitigation": {"summary": "...", "steps": [...],
                           "references": [...], "source": "ai|demo|engine|fallback"}
          }]
        }]
      }],
      "summary": {...}
    }
"""
import copy
import ipaddress

from .validation import to_bool

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
PRIORITY_ORDER = ["P1", "P2", "P3", "P4"]
CONFIDENCE_ORDER = ["High", "Medium", "Low"]
_CRIT_MULT = {"low": 0.8, "medium": 1.0, "high": 1.2}

FALLBACK_MITIGATION = (
    "No validated recommendation is available for this finding. "
    "Review the linked NVD record for vendor guidance before acting."
)


class ScanCancelled(Exception):
    """Raised inside a backend when the user cancels the scan."""


# --------------------------------------------------------------------------
# Scoring helpers
# --------------------------------------------------------------------------
def severity_from_cvss(score, version="3.1") -> str:
    """FR-07: version-appropriate qualitative bands."""
    score = float(score or 0)
    if str(version).startswith("2"):
        # CVSS v2 has no Critical or None band.
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def detection_confidence(product: str, version: str) -> str:
    """FR-14: confidence from how complete the service identification was."""
    if product and version:
        return "High"
    if product:
        return "Medium"
    return "Low"


def lower_confidence(level: str) -> str:
    idx = CONFIDENCE_ORDER.index(level) if level in CONFIDENCE_ORDER else 2
    return CONFIDENCE_ORDER[min(idx + 1, 2)]


def contextual_risk(cvss, context) -> float:
    """FR-15: CVSS adjusted by asset context, capped at 10.
    Detection confidence is shown beside the score, not folded into it."""
    mult = 1.0
    if to_bool(context.get("internet_facing")):
        mult += 0.3
    if to_bool(context.get("sensitive_data")):
        mult += 0.2
    mult *= _CRIT_MULT.get(context.get("criticality", "medium"), 1.0)
    return round(min(10.0, float(cvss or 0) * mult), 1)


def priority_from_risk(score) -> str:
    """FR-16 priority bands."""
    if score >= 9.0:
        return "P1"
    if score >= 7.0:
        return "P2"
    if score >= 4.0:
        return "P3"
    return "P4"


def _normalise_mitigation(value, cve_id):
    ref = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    if isinstance(value, dict) and str(value.get("summary", "")).strip():
        refs = [r for r in value.get("references", []) if r] or [ref]
        out = {
            "summary": str(value["summary"]).strip(),
            "steps": [str(s) for s in value.get("steps", []) if str(s).strip()],
            "references": refs,
            "source": value.get("source", "engine"),
        }
        for extra in ("note", "model"):        # why AI failed / which model answered
            if value.get(extra):
                out[extra] = str(value[extra])
        return out
    if isinstance(value, str) and value.strip():
        return {"summary": value.strip(), "steps": [], "references": [ref],
                "source": "engine"}
    return {"summary": FALLBACK_MITIGATION, "steps": [], "references": [ref],
            "source": "fallback"}


def finalise(target, profile, hosts, context) -> dict:
    """Fill derived fields, order findings by priority band and build the summary."""
    by_sev = {s: 0 for s in SEVERITY_ORDER}
    by_prio = {p: 0 for p in PRIORITY_ORDER}
    open_ports = assessed = cve_count = 0
    top = None

    for host in hosts:
        host.setdefault("hostname", "")
        host.setdefault("state", "up")
        for port in host.setdefault("ports", []):
            open_ports += 1
            port.setdefault("product", "")
            port.setdefault("version", "")
            port.setdefault("cves", [])
            port["confidence"] = port.get("confidence") or detection_confidence(
                port["product"], port["version"])
            # FR-10: no version string means no CVE lookup, recorded as such.
            if "assessed" not in port:
                port["assessed"] = bool(port["version"])
                if not port["assessed"]:
                    port["not_assessed_reason"] = "No version string detected"
            port.setdefault("not_assessed_reason", "")
            if port["assessed"]:
                assessed += 1

            for cve in port["cves"]:
                cve.setdefault("cvss_version", "3.1")
                cve.setdefault("description", "")
                cve.setdefault("match_method", "cpe")
                cve["severity"] = str(cve.get("severity") or severity_from_cvss(
                    cve.get("cvss"), cve["cvss_version"])).upper()
                if "confidence" not in cve:
                    cve["confidence"] = (lower_confidence(port["confidence"])
                                         if cve["match_method"] == "keyword"
                                         else port["confidence"])
                if cve.get("risk_score") is None:
                    cve["risk_score"] = contextual_risk(cve.get("cvss"), context)
                cve["priority"] = cve.get("priority") or priority_from_risk(cve["risk_score"])
                cve["mitigation"] = _normalise_mitigation(cve.get("mitigation"), cve["id"])

                by_sev[cve["severity"] if cve["severity"] in by_sev else "NONE"] += 1
                by_prio[cve["priority"] if cve["priority"] in by_prio else "P4"] += 1
                cve_count += 1
                if top is None or _finding_key(cve) < _finding_key(top):
                    top = {**cve, "host": host["ip"], "port": port["port"],
                           "service": port.get("service", "")}

            port["cves"].sort(key=_finding_key)
            port["max_risk"] = max((c["risk_score"] for c in port["cves"]), default=0)
        host["ports"].sort(key=lambda p: -p["max_risk"])

    not_assessed = open_ports - assessed
    return {
        "target": target,
        "profile": profile,
        "context": context,
        "hosts": hosts,
        "summary": {
            "hosts_up": sum(1 for h in hosts if h["state"] == "up"),
            "open_ports": open_ports,
            "assessed": assessed,
            "not_assessed": not_assessed,
            "complete": not_assessed == 0,          # NFR-06
            "cves": cve_count,
            "by_severity": by_sev,
            "by_priority": by_prio,
            "top_finding": top,
        },
    }


def _finding_key(cve):
    """Sort by priority band first, then by risk score (highest first)."""
    prio = cve.get("priority", "P4")
    rank = PRIORITY_ORDER.index(prio) if prio in PRIORITY_ORDER else 9
    return (rank, -float(cve.get("risk_score") or 0))


def flat_findings(result: dict) -> list:
    """One row per CVE, in priority order, for tables and reports."""
    rows = []
    for host in result.get("hosts", []):
        for port in host.get("ports", []):
            for cve in port.get("cves", []):
                rows.append({**cve, "host": host["ip"], "hostname": host.get("hostname", ""),
                             "port": port["port"], "protocol": port.get("protocol", "tcp"),
                             "service": port.get("service", ""),
                             "product": port.get("product", ""),
                             "version": port.get("version", "")})
    rows.sort(key=_finding_key)
    return rows


def coverage_rows(result: dict) -> list:
    """FR-20: every open port with its assessment status."""
    rows = []
    for host in result.get("hosts", []):
        for port in host.get("ports", []):
            rows.append({
                "host": host["ip"], "port": port["port"],
                "protocol": port.get("protocol", "tcp"),
                "service": port.get("service", ""),
                "product": port.get("product", ""), "version": port.get("version", ""),
                "assessed": port.get("assessed", False),
                "reason": port.get("not_assessed_reason", ""),
                "cves": len(port.get("cves", [])),
            })
    return rows


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def run(cfg, target, profile, context, emit, cancel_event=None, backend=None) -> dict:
    """Run a scan. `emit(stage, percent, message)` reports progress.
    `backend` overrides cfg["backend"] ("demo" or "engine").
    Raises ScanCancelled if `cancel_event` is set during the scan."""

    def report(stage, pct, msg):
        if cancel_event is not None and cancel_event.is_set():
            raise ScanCancelled()
        emit(stage, int(pct), msg)

    def wait(seconds):
        if cancel_event is not None and cancel_event.wait(seconds):
            raise ScanCancelled()

    backend = backend or cfg.get("backend", "demo")
    args = cfg["profiles"][profile]["args"]
    if backend == "demo":
        hosts = _demo_scan(target, report, wait)
    elif backend == "engine":
        from .engine.runner import run_engine
        hosts = run_engine(cfg, target, args, context, report, wait)
    else:
        raise ValueError(f"Unknown backend '{backend}' in config.yaml")

    result = finalise(target, profile, hosts, context)
    result["backend"] = backend
    s = result["summary"]
    report("done", 100, f"Finished: {s['cves']} CVEs, {s['assessed']}/{s['open_ports']} "
                        f"services assessed")
    return result


# --------------------------------------------------------------------------
# Demo backend: realistic sample data for UI development and the viva demo
# --------------------------------------------------------------------------
def _m(summary, steps):
    return {"summary": summary, "steps": steps, "references": [], "source": "demo"}


_DEMO_PORTS = [
    {"port": 21, "protocol": "tcp", "service": "ftp", "product": "vsftpd",
     "version": "2.3.4", "cves": [
        {"id": "CVE-2011-2523", "cvss": 9.8, "cvss_version": "3.1",
         "description": "vsftpd 2.3.4 as distributed contained a backdoor that opens "
                        "a shell on port 6200 when a username ends with ':)'.",
         "mitigation": _m(
             "This FTP server build is backdoored and gives attackers a remote shell.",
             ["Replace vsftpd with a clean package from your distribution and verify "
              "its checksum.",
              "Block inbound TCP 6200 at the firewall.",
              "If FTP is not needed, disable it; otherwise move to SFTP."])}]},
    {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH",
     "version": "7.4", "cves": [
        {"id": "CVE-2023-38408", "cvss": 9.8, "cvss_version": "3.1",
         "description": "The PKCS#11 feature in ssh-agent can lead to remote code "
                        "execution when an agent is forwarded to an attacker-controlled "
                        "system.",
         "mitigation": _m(
             "Upgrade OpenSSH and stop forwarding the SSH agent to untrusted hosts.",
             ["Upgrade OpenSSH to 9.3p2 or later.",
              "Set 'ForwardAgent no' in ssh_config by default."])},
        {"id": "CVE-2018-15473", "cvss": 5.3, "cvss_version": "3.0",
         "description": "OpenSSH through 7.7 allows username enumeration because it "
                        "responds differently to valid and invalid users.",
         "mitigation": _m(
             "Attackers can learn which usernames exist, which helps password guessing.",
             ["Upgrade OpenSSH to 7.8 or later.",
              "Disable password logins and use key-based authentication.",
              "Rate-limit SSH with fail2ban or firewall rules."])}]},
    {"port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd",
     "version": "2.4.49", "cves": [
        {"id": "CVE-2021-42013", "cvss": 9.8, "cvss_version": "3.1",
         "description": "Path traversal and remote code execution in Apache 2.4.49 and "
                        "2.4.50 when CGI is enabled (incomplete fix for CVE-2021-41773).",
         "mitigation": _m(
             "The web server can be made to run attacker commands.",
             ["Upgrade Apache httpd to 2.4.51 or later.",
              "Until patched, disable mod_cgi and confirm 'Require all denied' "
              "protects directories outside the web root."])},
        {"id": "CVE-2021-41773", "cvss": 7.5, "cvss_version": "3.1",
         "description": "Path traversal in Apache 2.4.49 lets attackers map URLs to "
                        "files outside the document root.",
         "mitigation": _m(
             "Files outside the website folder can be read by anyone.",
             ["Upgrade Apache httpd to 2.4.51 or later."])}]},
    {"port": 443, "protocol": "tcp", "service": "https", "product": "nginx",
     "version": "1.18.0", "assessed": False,
     "not_assessed_reason": "NVD request failed (HTTP 503), not 'no vulnerabilities'",
     "cves": []},
    {"port": 3306, "protocol": "tcp", "service": "mysql", "product": "MySQL",
     "version": "5.7.30", "cves": [
        {"id": "CVE-2020-14812", "cvss": 4.9, "cvss_version": "3.1",
         "match_method": "keyword",
         "description": "Vulnerability in the MySQL Server Locking component allows a "
                        "high-privileged attacker to cause a denial of service.",
         "mitigation": _m(
             "A database admin account could crash the server.",
             ["Apply the latest MySQL 5.7 patch release.",
              "Bind MySQL to 127.0.0.1 or an internal interface; never expose 3306."])}]},
    {"port": 8080, "protocol": "tcp", "service": "http-proxy", "product": "",
     "version": "", "cves": []},
]


def _demo_ip(target):
    try:
        net = ipaddress.ip_network(target, strict=False)
        hosts = list(net.hosts()) or [net.network_address]
        return str(hosts[0])
    except ValueError:
        return "192.168.56.101"


def _demo_scan(target, report, wait):
    ports = copy.deepcopy(_DEMO_PORTS)
    report("scan", 3, f"[demo] nmap scan of {target} started")
    for i, p in enumerate(ports):
        wait(0.5)
        label = f"{p['product']} {p['version']}".strip() or "version unknown"
        report("scan", 5 + 35 * (i + 1) // len(ports),
               f"Discovered {p['port']}/{p['protocol']} open  {p['service']}  {label}")

    report("parse", 42, "Normalising scan output into service records")
    wait(0.3)

    lookups = [p for p in ports if p["version"]]
    for i, p in enumerate(lookups):
        wait(0.6)
        pct = 45 + 30 * (i + 1) // len(lookups)
        if p.get("assessed") is False:
            report("cve", pct, f"NVD: {p['product']} {p['version']} -> request failed (HTTP 503)")
        else:
            method = p["cves"][0].get("match_method", "cpe") if p["cves"] else "cpe"
            report("cve", pct, f"NVD ({method}): {p['product']} {p['version']} -> "
                               f"{len(p['cves'])} CVE(s)")
    for p in ports:
        if not p["version"]:
            report("cve", 75, f"Skipped {p['port']}/{p['protocol']}: no version detected")

    report("risk", 80, "Applying asset context to CVSS scores")
    wait(0.4)
    report("mitigation", 92, "Generating mitigation recommendations")
    wait(0.5)

    is_name = not target[:1].isdigit() and ":" not in target
    return [{"ip": _demo_ip(target), "hostname": target if is_name else "",
             "state": "up", "ports": ports}]
