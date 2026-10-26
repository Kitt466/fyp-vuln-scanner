"""Configuration loading and platform helpers (NFR-08, NFR-09, NFR-11)."""
import copy
import os
import shutil
import subprocess
import sys

try:
    import yaml
except ImportError:  # the app still runs on built-in defaults
    yaml = None

APP_NAME = "VulnScan"

DEFAULTS = {
    "backend": "engine",
    "nmap": {"path": ""},
    "profiles": {
        "quick": {"label": "Quick", "description": "Top 100 TCP ports",
                  "args": "-T4 -F"},
        "service": {"label": "Service detection",
                    "description": "Top 1000 TCP ports with version detection",
                    "args": "-sV -T4 --top-ports 1000"},
        "os": {"label": "OS detection",
               "description": "Service detection plus OS fingerprinting",
               "args": "-sV -O -T4 --top-ports 1000", "requires_admin": True},
        "vuln": {"label": "Vulnerability script",
                 "description": "Service detection plus vuln NSE scripts",
                 "args": "-sV --script vuln -T4 --top-ports 1000"},
        "full": {"label": "Full scan", "description": "All 65535 TCP ports",
                 "args": "-sV -T4 -p-"},
    },
    "default_profile": "service",
    "nvd": {
        "base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "timeout_seconds": 15,
        "delay_without_key": 6.0,
        "delay_with_key": 0.6,
        "results_per_page": 50,
        "max_cves_per_service": 20,
        "retries": 2,
    },
    "gemini": {"models": ["gemini-3.8-flash", "gemini-3.5-flash-lite", "gemini-2.5-flash"],
               "timeout_seconds": 30,
               "delay_seconds": 6.5, "max_findings": 15,
               "retry_backoff_seconds": [8, 20]},
    "limits": {"max_addresses": 256},
}


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def app_dir() -> str:
    """Folder holding the executable (frozen) or the project root (source)."""
    if is_frozen():
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def user_data_dir() -> str:
    """Per-user writable folder for the history database."""
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    path = os.path.join(base, APP_NAME)
    os.makedirs(path, exist_ok=True)
    return path


def _bundled_config() -> str:
    if is_frozen():
        return os.path.join(getattr(sys, "_MEIPASS", app_dir()), "vulnscan", "config.yaml")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")


def config_search_paths():
    """First match wins: env override, next to the exe, user folder, bundled default."""
    return [
        os.environ.get("VULNSCAN_CONFIG", ""),
        os.path.join(app_dir(), "config.yaml"),
        os.path.join(user_data_dir(), "config.yaml"),
        _bundled_config(),
    ]


def _merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config() -> dict:
    cfg = copy.deepcopy(DEFAULTS)
    source = "built-in defaults"
    if yaml is not None:
        for path in config_search_paths():
            if path and os.path.isfile(path):
                with open(path, encoding="utf-8") as fh:
                    data = yaml.safe_load(fh) or {}
                if isinstance(data, dict):
                    cfg = _merge(cfg, data)
                    source = path
                break
    cfg["_source"] = source

    # NFR-09: secrets only ever come from the environment.
    cfg["nvd"]["api_key"] = os.environ.get("NVD_API_KEY", "").strip()
    cfg["gemini"]["api_key"] = os.environ.get("GEMINI_API_KEY", "").strip()
    if os.environ.get("VULNSCAN_BACKEND"):
        cfg["backend"] = os.environ["VULNSCAN_BACKEND"].strip().lower()

    if cfg.get("default_profile") not in cfg["profiles"]:
        cfg["default_profile"] = next(iter(cfg["profiles"]))
    return cfg


# --------------------------------------------------------------------------
# Nmap resolution (NFR-08)
# --------------------------------------------------------------------------
_WINDOWS_NMAP = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
]


def find_nmap(cfg: dict):
    """Return the Nmap binary path for this platform, or None."""
    configured = (cfg.get("nmap") or {}).get("path") or ""
    if configured and os.path.isfile(configured):
        return configured
    found = shutil.which("nmap")
    if found:
        return found
    if sys.platform.startswith("win"):
        for candidate in _WINDOWS_NMAP:
            if os.path.isfile(candidate):
                return candidate
    return None


def nmap_version(path):
    """Return e.g. '7.94', or None if Nmap can't be run."""
    if not path:
        return None
    kwargs = {}
    if sys.platform.startswith("win"):
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW: no console flash
    try:
        out = subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=10, **kwargs
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for token in out.split():
        if token[:1].isdigit():
            return token
    return None


def is_admin() -> bool:
    """True when running elevated (needed for -O OS detection)."""
    try:
        if sys.platform.startswith("win"):
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False
