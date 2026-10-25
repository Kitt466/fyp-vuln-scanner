"""Input validation. Nothing the user types is passed to Nmap unchecked:
targets are validated here and Nmap arguments come only from config profiles."""
import ipaddress
import re

CRITICALITY = ("low", "medium", "high")

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def validate_target(raw: str, max_addresses: int = 256) -> str:
    """Return a normalised target or raise ValueError with a user-facing message."""
    target = (raw or "").strip()
    if not target:
        raise ValueError("Enter a target IP address, CIDR range or hostname.")
    if target.startswith("-"):
        raise ValueError("Target cannot start with '-'.")

    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        net = None

    if net is not None:
        if net.num_addresses > max_addresses:
            raise ValueError(
                f"Range too large ({net.num_addresses} addresses). "
                f"Maximum is {max_addresses}."
            )
        return str(net) if "/" in target else str(net.network_address)

    if _HOSTNAME_RE.match(target):
        return target.lower()

    raise ValueError("Enter a valid IPv4/IPv6 address, CIDR range or hostname.")


def to_bool(value) -> bool:
    """Normalise "on"/"true"/"1"/True to a real bool (fixes the bool/str mix-up)."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on", "y"}


def clean_context(raw: dict) -> dict:
    """FR-13: asset name, business function, criticality, exposure, sensitive data."""
    criticality = str(raw.get("criticality") or "medium").lower()
    if criticality not in CRITICALITY:
        criticality = "medium"
    return {
        "asset_name": str(raw.get("asset_name") or "").strip()[:80],
        "business_function": str(raw.get("business_function") or "").strip()[:120],
        "criticality": criticality,
        "internet_facing": to_bool(raw.get("internet_facing")),
        "sensitive_data": to_bool(raw.get("sensitive_data")),
    }
