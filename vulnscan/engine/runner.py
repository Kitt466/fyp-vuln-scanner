"""Orchestrates the real pipeline: Nmap -> parse -> NVD -> risk -> mitigation.

A failure affecting one service never stops the assessment (NFR-02): that
service is marked as not assessed with the reason, and the scan continues.
"""
from .. import pipeline
from ..config import find_nmap
from . import mitigation as mit
from .nmap_scanner import DISCOVERED_RE, PROGRESS_RE, detects_versions, run_scan
from .nvd_client import NVDClient

NVD_LINK = "https://nvd.nist.gov/vuln/detail/{}"


def run_engine(cfg, target, nmap_args, context, report, wait):
    nmap_path = find_nmap(cfg)
    if not nmap_path:
        raise RuntimeError("Nmap was not found. Install it from https://nmap.org/download.html "
                           "or set nmap.path in config.yaml.")

    # ---- 1. Nmap scan (0-40%) -------------------------------------------
    report("scan", 2, f"nmap {nmap_args} {target}")
    state = {"pct": 3}

    def on_line(line):
        m = PROGRESS_RE.match(line)
        if m:
            # Each Nmap phase restarts at 0%; keep the bar moving forward only.
            pct = 5 + int(float(m.group("pct")) * 0.33)
            state["pct"] = max(state["pct"], min(pct, 38))
            report("scan", state["pct"], f"{m.group('phase')}: {float(m.group('pct')):.0f}% done")
            return
        m = DISCOVERED_RE.match(line)
        if m:
            report("scan", state["pct"],
                   f"Discovered open port {m.group('port')}/{m.group('proto')} on {m.group('host')}")
            return
        if line.startswith(("WARNING", "Warning", "NOTE", "Note:")):
            report("scan", state["pct"], line)
        else:
            report("scan", state["pct"], "")   # lets cancellation take effect promptly

    hosts = run_scan(nmap_path, nmap_args, target, on_line)
    open_ports = sum(len(h["ports"]) for h in hosts)
    report("parse", 42, f"{len(hosts)} host(s) up, {open_ports} open port(s)")
    for h in hosts:
        if h.get("os"):
            report("parse", 43, f"OS guess for {h['ip']}: {h['os']}")
    if not hosts:
        report("parse", 44, "No hosts responded. Check the target is up and reachable.")

    # ---- 2. CVE correlation (45-75%) --------------------------------------
    versions = detects_versions(nmap_args)
    nvd = NVDClient(cfg["nvd"])
    ports = [(h, p) for h in hosts for p in h["ports"]]
    for i, (host, port) in enumerate(ports, 1):
        pct = 45 + int(30 * i / max(len(ports), 1))
        label = f"{port['port']}/{port['protocol']} {port['product']} {port['version']}".strip()
        if port.get("method") == "table":
            port["confidence"] = "Low"   # service guessed from the port number only
        if not versions:
            port["assessed"] = False
            port["not_assessed_reason"] = ("Scan profile does not detect versions; choose "
                                           "Service detection or higher")
            report("cve", pct, f"Skipped {label}: profile has no version detection")
            continue
        if not port["version"]:
            port["assessed"] = False
            port["not_assessed_reason"] = "No version string detected"   # FR-10
            report("cve", pct, f"Skipped {label}: no version detected")
            continue

        result = nvd.lookup(port["product"] or port["service"], port["version"],
                            port.get("cpe"), wait)
        if not result.ok:                                                # FR-11
            port["assessed"] = False
            port["not_assessed_reason"] = f"NVD request failed ({result.error})"
            report("cve", pct, f"NVD lookup failed for {label}: {result.error}")
            continue
        port["assessed"] = True
        port["cves"] = result.cves
        extra = (f", showing the {len(result.cves)} highest-scored of {result.found}"
                 if result.found > len(result.cves) else "")
        report("cve", pct, f"NVD ({result.method}): {label} -> {len(result.cves)} CVE(s){extra}")

    # ---- 3. Risk scoring (75-88%) -----------------------------------------
    report("risk", 78, "Applying asset context to CVSS scores")
    findings = []
    for host, port in ports:
        for cve in port.get("cves", []):
            cve["risk_score"] = pipeline.contextual_risk(cve["cvss"], context)
            cve["priority"] = pipeline.priority_from_risk(cve["risk_score"])
            findings.append((cve, host, port))
    findings.sort(key=lambda f: pipeline._finding_key(f[0]))

    # ---- 4. Mitigation (88-99%) -------------------------------------------
    apply_mitigation(cfg, findings, context, report, wait)
    return hosts


def _refs(cve):
    return [NVD_LINK.format(cve["id"])] + cve.get("nvd_references", [])


def apply_mitigation(cfg, findings, context, report, wait, stage="mitigation",
                     start_pct=88, end_pct=99):
    """Generate AI advice for (cve, host, port) triples in priority order.
    Returns the number of findings that received AI advice."""
    gen = mit.MitigationGenerator(cfg["gemini"])
    if findings and not gen.enabled:
        report(stage, start_pct + 2, "No GEMINI_API_KEY set: using fallback guidance")
    total = min(len(findings), gen.max_findings)
    done = 0
    for i, (cve, host, port) in enumerate(findings):
        refs = _refs(cve)
        if not gen.enabled:
            cve["mitigation"] = {"summary": mit.DISABLED_TEXT, "steps": [],
                                 "references": refs, "source": "fallback"}
            continue
        if i >= gen.max_findings:
            cve["mitigation"] = {"summary": mit.LIMIT_TEXT, "steps": [],
                                 "references": refs, "source": "fallback"}
            continue
        pct = start_pct + int((end_pct - start_pct) * (i + 1) / total)
        report(stage, pct, f"Generating recommendation {i + 1}/{total}: {cve['id']}")
        finding = {**cve, "service": port["service"], "product": port["product"],
                   "version": port["version"], "port": port["port"],
                   "protocol": port["protocol"]}
        already_stopped = bool(gen.stopped)
        advice = gen.generate(finding, context, wait)
        if advice:
            done += 1
            cve["mitigation"] = {**advice, "references": refs, "source": "ai",
                                 "model": gen.used_model}
        else:
            if not already_stopped:
                report(stage, pct, f"AI recommendation for {cve['id']} unavailable "
                                   f"({gen.last_error}); using fallback")
            cve["mitigation"] = {"summary": pipeline.FALLBACK_MITIGATION, "steps": [],
                                 "references": refs, "source": "fallback",
                                 "note": f"AI unavailable: {gen.last_error}"}
    return done


def retry_targets(result):
    """Findings whose AI advice failed or was skipped, in priority order."""
    out = []
    for host in result.get("hosts", []):
        for port in host.get("ports", []):
            for cve in port.get("cves", []):
                if cve.get("mitigation", {}).get("source") == "fallback":
                    out.append((cve, host, port))
    out.sort(key=lambda f: pipeline._finding_key(f[0]))
    return out


def retry_mitigation(cfg, result, report, wait):
    """Re-request AI advice for an existing result (no re-scan). Updates it in place."""
    targets = retry_targets(result)
    if not targets:
        report("mitigation", 100, "Every finding already has AI advice")
        return 0
    report("mitigation", 2, f"Retrying AI advice for {len(targets)} finding(s)")
    done = apply_mitigation(cfg, targets, result.get("context", {}), report, wait,
                            start_pct=5, end_pct=95)
    for cve, _host, _port in targets:     # re-normalise the replaced entries
        cve["mitigation"] = pipeline._normalise_mitigation(cve["mitigation"], cve["id"])
    report("done", 100, f"AI advice added for {done} of {len(targets)} finding(s)")
    return done
