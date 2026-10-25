"""Nmap scanning (FR-01..FR-04).

Nmap is run as a subprocess (never through a shell) so the GUI can show live
progress and cancel a scan. Results are read from Nmap's XML output (-oX), which
also carries the CPE identifiers used for structured NVD matching (FR-08).
"""
import os
import re
import shlex
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


class NmapError(RuntimeError):
    """Nmap failed to run or exited with an error."""


PROGRESS_RE = re.compile(r"^(?P<phase>[A-Za-z][\w /-]*?) Timing: About (?P<pct>[\d.]+)% done")
DISCOVERED_RE = re.compile(r"^Discovered open port (?P<port>\d+)/(?P<proto>\w+) on (?P<host>\S+)")


def build_command(nmap_path, profile_args, target, xml_path):
    """Profile args come from config.yaml; the target was validated beforehand,
    so nothing typed by the user can add Nmap options."""
    return [nmap_path, *shlex.split(profile_args), "-v", "--stats-every", "5s",
            "-oX", xml_path, target]


def detects_versions(profile_args) -> bool:
    args = shlex.split(profile_args)
    return "-sV" in args or "-A" in args


def run_scan(nmap_path, profile_args, target, on_line):
    """Run Nmap and return parsed hosts.

    `on_line(text)` receives each line of Nmap's console output as it arrives;
    it may raise (e.g. ScanCancelled), in which case Nmap is terminated."""
    fd, xml_path = tempfile.mkstemp(prefix="vulnscan-", suffix=".xml")
    os.close(fd)
    kwargs = {}
    if sys.platform.startswith("win"):
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    try:
        proc = subprocess.Popen(
            build_command(nmap_path, profile_args, target, xml_path),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            text=True, errors="replace", bufsize=1, **kwargs)
    except OSError as exc:
        os.remove(xml_path)
        raise NmapError(f"Could not start Nmap ({nmap_path}): {exc}") from exc

    tail = []
    try:
        for raw in proc.stdout:
            line = raw.rstrip()
            if not line:
                continue
            tail = (tail + [line])[-25:]
            on_line(line)
        code = proc.wait()
        if code != 0:
            raise NmapError(explain_failure(tail, code))
        with open(xml_path, encoding="utf-8", errors="replace") as fh:
            xml = fh.read()
        if not xml.strip():
            raise NmapError("Nmap produced no XML output.")
        return parse_xml(xml)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if proc.stdout:
            proc.stdout.close()
        try:
            os.remove(xml_path)
        except OSError:
            pass


def explain_failure(tail, code) -> str:
    text = "\n".join(tail)
    low = text.lower()
    if "requires root privileges" in low or "you requested a scan type which requires root" in low:
        return ("This scan profile needs administrator/root rights (e.g. OS detection). "
                "Run VulnScan as administrator on Windows or with sudo on Linux, or pick "
                "the Service detection profile.")
    if "npcap" in low or "winpcap" in low or "dnet: failed to open device" in low:
        return ("Nmap could not use the network driver. Reinstall Nmap and make sure "
                "Npcap is installed (it is offered during Nmap setup).")
    if "failed to resolve" in low:
        return "The hostname could not be resolved. Check the target name or use an IP address."
    last = [l for l in tail if l.strip()][-4:]
    return f"Nmap exited with code {code}: " + " | ".join(last)


def parse_xml(xml_text) -> list:
    """Normalise Nmap XML into host/port records (FR-04)."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapError(f"Could not read Nmap output: {exc}") from exc

    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        if status is None or status.get("state") != "up":
            continue
        addr = h.find("address[@addrtype='ipv4']")
        if addr is None:
            addr = h.find("address[@addrtype='ipv6']")
        if addr is None:
            continue
        name_el = h.find("hostnames/hostname")
        os_el = h.find("os/osmatch")
        host = {
            "ip": addr.get("addr"),
            "hostname": name_el.get("name", "") if name_el is not None else "",
            "state": "up",
            "os": (f"{os_el.get('name')} ({os_el.get('accuracy')}% match)"
                   if os_el is not None else ""),
            "ports": [],
        }
        for p in h.findall("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = p.find("service")
            get = (lambda k: svc.get(k, "") if svc is not None else "")
            host["ports"].append({
                "port": int(p.get("portid")),
                "protocol": p.get("protocol", "tcp"),
                "service": get("name") or "unknown",
                "product": get("product"),
                "version": get("version"),
                "extrainfo": get("extrainfo"),
                "method": get("method"),          # "probed" or "table" (guessed from port)
                "cpe": [c.text for c in (svc.findall("cpe") if svc is not None else []) if c.text],
                "scripts": {s.get("id"): s.get("output", "") for s in p.findall("script")},
            })
        hosts.append(host)
    return hosts
