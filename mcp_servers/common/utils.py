import hashlib
import ipaddress
from datetime import datetime


def hash_content(content: str | bytes) -> str:
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def normalize_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return ip.strip()


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def timestamp_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def severity_to_score(severity: str) -> float:
    mapping = {
        "info": 0.0,
        "low": 2.5,
        "medium": 5.0,
        "high": 7.5,
        "critical": 10.0,
    }
    return mapping.get(severity.lower(), 0.0)
