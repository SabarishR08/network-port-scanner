from __future__ import annotations

import ipaddress
import re
import socket
from typing import Iterable


def classify_target_type(ip: str) -> str:
    if ip.startswith("127."):
        return "localhost"
    if ip.startswith("10.") or ip.startswith("192.168."):
        return "private"
    return "public"


def resolve_target(target: str) -> str:
    return socket.gethostbyname(target)


def is_private_or_loopback(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
        return parsed.is_private or parsed.is_loopback
    except ValueError:
        return False


def is_allowed_in_safe_mode(target: str, resolved_ip: str) -> bool:
    if target.strip().lower() == "scanme.nmap.org":
        return True
    if resolved_ip == "127.0.0.1":
        return True
    return is_private_or_loopback(resolved_ip)


def get_public_scan_warning(resolved_ip: str) -> str | None:
    if classify_target_type(resolved_ip) == "public":
        return "Ensure you have permission to scan this target"
    return None


def parse_risk_line(line: str) -> tuple[str, str]:
    normalized = " ".join((line or "").strip().split())
    match = re.match(r"^Risk:\s*(Low|Medium|High|Unknown)\s*\|\s*Reason:\s*(.+)$", normalized, flags=re.IGNORECASE)
    if not match:
        return "Unknown", "Unable to analyze"
    risk = match.group(1).capitalize()
    reason = match.group(2).strip()
    return risk, reason or "Unable to analyze"


def sanitize_filename(input_text: str, fallback: str = "target") -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", input_text or "")
    return safe[:60] or fallback


def build_recommendations(open_ports: Iterable[dict]) -> list[str]:
    recs: set[str] = set()
    for row in open_ports:
        service = str(row.get("service", "")).upper()
        port = int(row.get("port", 0))

        if "SSH" in service or port == 22:
            recs.add("SSH detected: disable password login and enforce key-based authentication")
        if "HTTP" in service or port in {80, 8080}:
            recs.add("HTTP service detected: redirect traffic to HTTPS and enable TLS")
        if "HTTPS" in service or port == 443:
            recs.add("HTTPS detected: use modern TLS settings and disable weak ciphers")
        if "RDP" in service or port == 3389:
            recs.add("RDP exposed: restrict access with firewall rules and MFA")
        if "MYSQL" in service or port == 3306:
            recs.add("MySQL detected: restrict remote access and rotate credentials")
        if "POSTGRESQL" in service or port == 5432:
            recs.add("PostgreSQL detected: bind to trusted interfaces and enforce strong auth")

    if not recs:
        recs.add("No critical service hardening suggestions generated for current open ports")

    return sorted(recs)
