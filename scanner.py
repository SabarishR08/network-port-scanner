from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass
from queue import Empty, Queue

TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139,
    143, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587,
    631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723,
    1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000,
    5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646,
    7070, 8000, 8008, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153,
    49154, 49155, 49156, 49157,
]

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    6379: "REDIS",
    8080: "HTTP-ALT",
}

SCAN_PROFILES = {
    "quick_scan": {"ports": TOP_100_PORTS, "timeout": 0.4, "max_workers": 300},
    "full_scan": {"start_port": 1, "end_port": 65535, "timeout": 0.25, "max_workers": 700},
    "stealth_scan": {"start_port": 1, "end_port": 1024, "timeout": 1.2, "max_workers": 40},
    "web_scan": {"ports": [80, 443, 8080], "timeout": 0.6, "max_workers": 120},
}

LEGACY_PROFILE_MAP = {
    "quick": "quick_scan",
    "extended": None,
    "full": "full_scan",
}


@dataclass(frozen=True)
class ScanConfig:
    target_input: str
    resolved_ip: str
    ports: list[int]
    timeout: float
    max_workers: int
    banner_grab: bool


def now() -> float:
    return time.time()


def normalize_profile_name(profile: str | None) -> str | None:
    if not profile:
        return None
    profile = profile.strip().lower()
    return LEGACY_PROFILE_MAP.get(profile, profile)


def resolve_ports_and_settings(
    profile: str | None,
    start_port: int | None,
    end_port: int | None,
    timeout: float | None,
    max_workers: int | None,
) -> tuple[list[int], float, int]:
    normalized = normalize_profile_name(profile)

    if normalized == "extended":
        normalized = None

    if normalized in SCAN_PROFILES:
        profile_cfg = SCAN_PROFILES[normalized]
        if "ports" in profile_cfg:
            ports = list(profile_cfg["ports"])
        else:
            ports = list(range(profile_cfg["start_port"], profile_cfg["end_port"] + 1))
        return (
            ports,
            float(timeout if timeout is not None else profile_cfg["timeout"]),
            int(max_workers if max_workers is not None else profile_cfg["max_workers"]),
        )

    if start_port is None or end_port is None:
        raise ValueError("Provide a valid profile or both start_port and end_port")
    if start_port < 1 or end_port > 65535 or start_port > end_port:
        raise ValueError("Port range must be within 1-65535 and start_port <= end_port")

    return (
        list(range(start_port, end_port + 1)),
        float(timeout if timeout is not None else 0.5),
        int(max_workers if max_workers is not None else 200),
    )


def probe_banner(ip: str, port: int, timeout: float, host_for_http: str = "localhost") -> tuple[str, str]:
    probe_timeout = max(0.2, min(timeout, 2.0))
    raw = ""
    detected_service = ""

    try:
        with socket.create_connection((ip, port), timeout=probe_timeout) as sock:
            sock.settimeout(probe_timeout)

            if port in {22}:
                raw = sock.recv(256).decode("utf-8", errors="replace").strip()
                if raw.upper().startswith("SSH-"):
                    detected_service = "SSH"
            elif port in {80, 8080, 8000, 8008, 8081, 8443}:
                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {host_for_http}\r\n"
                    "Connection: close\r\n"
                    "User-Agent: PowerScan/1.0\r\n\r\n"
                ).encode("ascii", errors="ignore")
                sock.sendall(request)
                raw = sock.recv(1024).decode("utf-8", errors="replace").strip()
                if "HTTP/" in raw.upper():
                    detected_service = "HTTP"
            else:
                raw = sock.recv(256).decode("utf-8", errors="replace").strip()
    except Exception:
        return "", ""

    return detected_service, " ".join(raw.split())[:200]


def parse_service_and_version(base_service: str, banner: str) -> tuple[str, str]:
    service = base_service or "Unknown"
    version = ""

    normalized = (banner or "").strip()
    upper = normalized.upper()

    if upper.startswith("SSH-"):
        service = "SSH"
        version = normalized.replace("SSH-", "", 1).strip()
    elif "SERVER:" in upper and "HTTP" in upper:
        service = "HTTP"
        parts = normalized.split("Server:", 1)
        if len(parts) > 1:
            version = parts[1].split("\n", 1)[0].strip()
    elif "OPENSSH" in upper:
        service = "SSH"
        version = "OpenSSH"

    if not version and normalized:
        version = normalized[:60]

    return service, version


def scan_ports(config: ScanConfig) -> dict:
    q: Queue[int] = Queue()
    for p in config.ports:
        q.put(p)

    open_ports: list[dict] = []
    errors: list[str] = []
    scanned_count = 0
    lock = threading.Lock()

    def worker() -> None:
        nonlocal scanned_count
        while True:
            try:
                port = q.get_nowait()
            except Empty:
                return

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(config.timeout)
                    if sock.connect_ex((config.resolved_ip, port)) == 0:
                        base = COMMON_PORTS.get(port, "Unknown")
                        banner = ""
                        if config.banner_grab:
                            detected_service, raw_banner = probe_banner(
                                config.resolved_ip,
                                port,
                                config.timeout,
                                host_for_http=config.target_input,
                            )
                            if detected_service and base == "Unknown":
                                base = detected_service
                            banner = raw_banner

                        service, version = parse_service_and_version(base, banner)
                        display_banner = version if version else banner

                        with lock:
                            open_ports.append({
                                "port": port,
                                "service": service,
                                "banner": display_banner,
                            })
            except Exception as exc:
                with lock:
                    if len(errors) < 50:
                        errors.append(f"Port {port}: {exc}")
            finally:
                with lock:
                    scanned_count += 1
                q.task_done()

    thread_count = max(1, min(config.max_workers, len(config.ports)))
    workers = [threading.Thread(target=worker, daemon=True) for _ in range(thread_count)]

    started_at = now()
    for t in workers:
        t.start()
    for t in workers:
        t.join()
    finished_at = now()

    open_ports.sort(key=lambda row: row["port"])

    return {
        "scanned_count": scanned_count,
        "total_ports": len(config.ports),
        "open_ports": open_ports,
        "errors": errors,
        "elapsed_seconds": round(max(0.0, finished_at - started_at), 2),
        "started_at": started_at,
        "finished_at": finished_at,
    }
