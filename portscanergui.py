import io
import json
import os
import re
import socket
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from queue import Empty, Queue

from flask import Flask, jsonify, render_template, request, send_file

# Service map can be extended as needed.
COMMON_PORTS = {
    7: "Echo",
    9: "Discard",
    13: "Daytime",
    19: "Chargen",
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    37: "Time",
    43: "WHOIS",
    49: "TACACS",
    53: "DNS",
    69: "TFTP",
    70: "Gopher",
    79: "Finger",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    88: "Kerberos",
    109: "POP2",
    110: "POP3",
    111: "RPCBind",
    113: "Ident",
    119: "NNTP",
    123: "NTP",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    427: "SLP",
    443: "HTTPS",
    444: "SNPP",
    445: "SMB",
    465: "SMTPS",
    500: "ISAKMP",
    512: "Exec",
    513: "Login",
    514: "Syslog",
    515: "LPD",
    520: "RIP",
    548: "AFP",
    554: "RTSP",
    563: "NNTPS",
    623: "IPMI",
    631: "IPP",
    636: "LDAPS",
    646: "LDP",
    691: "MS-Exchange",
    853: "DNS-over-TLS",
    873: "rsync",
    902: "VMware-Auth",
    989: "FTPS-Data",
    990: "FTPS",
    992: "TelnetS",
    587: "Submission",
    993: "IMAPS",
    995: "POP3S",
    1025: "MS-RPC-EPMAP",
    1080: "SOCKS",
    1194: "OpenVPN",
    1241: "Nessus",
    1311: "Dell-OpenManage",
    1434: "MSSQL-Browser",
    1433: "MSSQL",
    1521: "Oracle",
    1701: "L2TP",
    1723: "PPTP",
    1812: "RADIUS",
    1813: "RADIUS-Accounting",
    1883: "MQTT",
    1900: "SSDP",
    1935: "RTMP",
    2000: "Cisco-SCCP",
    2048: "NFS-Lockd",
    2049: "NFS",
    2181: "ZooKeeper",
    2375: "Docker",
    2376: "Docker-TLS",
    2483: "Oracle-DB",
    2484: "Oracle-DB-TLS",
    27017: "MongoDB",
    2775: "SMPP",
    3000: "Node-Dev",
    3128: "Squid",
    3260: "iSCSI",
    3268: "LDAP-GC",
    3269: "LDAPS-GC",
    3306: "MySQL",
    3478: "STUN",
    3690: "Subversion",
    4000: "Remote-Anything",
    4369: "Erlang-EPMD",
    4444: "Remote-Shell-Alt",
    4500: "IPsec-NAT-T",
    5000: "UPnP",
    5060: "SIP",
    5061: "SIP-TLS",
    5222: "XMPP-Client",
    5269: "XMPP-Server",
    5353: "mDNS",
    5432: "PostgreSQL",
    5433: "PostgreSQL-Alt",
    3389: "RDP",
    5555: "Android-Debug-Bridge",
    5672: "AMQP",
    5683: "CoAP",
    5900: "VNC",
    5901: "VNC-1",
    5938: "TeamViewer",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6000: "X11",
    6443: "Kubernetes-API",
    6379: "Redis",
    6667: "IRC",
    7001: "WebLogic",
    7002: "WebLogic-SSL",
    7199: "Cassandra-JMX",
    7474: "Neo4j-HTTP",
    7687: "Neo4j-Bolt",
    8000: "HTTP-Alt",
    8008: "HTTP-Alt",
    8010: "XMPP-FileTransfer",
    8081: "HTTP-Alt-1",
    8088: "HTTP-Alt-2",
    8080: "HTTP-Alt",
    8161: "ActiveMQ-Web",
    8448: "Matrix-Federation",
    8443: "HTTPS-Alt",
    8883: "MQTT-TLS",
    8888: "HTTP-Alt-3",
    9000: "SonarQube",
    9042: "Cassandra",
    9092: "Kafka",
    9093: "Kafka-Controller",
    9099: "Prometheus-Exporter",
    9160: "Cassandra-Thrift",
    9200: "Elasticsearch",
    9300: "Elasticsearch-Transport",
    9418: "Git",
    11211: "Memcached",
    15672: "RabbitMQ-Management",
    27018: "MongoDB-Shard",
    27019: "MongoDB-Config",
    50000: "DB2",
}


def _now() -> float:
    return time.time()


@dataclass
class ScanJob:
    job_id: str
    target_input: str
    resolved_ip: str
    start_port: int
    end_port: int
    timeout: float
    max_workers: int
    banner_grab: bool = False
    status: str = "queued"
    created_at: float = field(default_factory=_now)
    started_at: float | None = None
    finished_at: float | None = None
    scanned_count: int = 0
    total_ports: int = 0
    open_ports: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    _stop_event: threading.Event = field(default_factory=threading.Event)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _thread: threading.Thread | None = None

    def stop(self) -> None:
        self._stop_event.set()
        with self._lock:
            if self.status in {"queued", "running"}:
                self.status = "stopping"

    def is_active(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def elapsed(self) -> float:
        if not self.started_at:
            return 0.0
        end = self.finished_at if self.finished_at else _now()
        return max(0.0, end - self.started_at)


app = Flask(__name__)
JOBS: dict[str, ScanJob] = {}
JOBS_LOCK = threading.Lock()
DB_LOCK = threading.Lock()
DB_PATH = "scan_history.db"
MAX_ACTIVE_JOBS = 3
MAX_STORED_JOBS = 50


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with DB_LOCK:
        with get_db_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    job_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    resolved_ip TEXT NOT NULL,
                    start_port INTEGER NOT NULL,
                    end_port INTEGER NOT NULL,
                    timeout REAL NOT NULL,
                    max_workers INTEGER NOT NULL,
                    banner_grab INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL,
                    started_at REAL,
                    finished_at REAL,
                    elapsed_seconds REAL,
                    scanned_count INTEGER,
                    total_ports INTEGER,
                    open_count INTEGER,
                    error_count INTEGER
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_open_ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    service TEXT NOT NULL,
                    banner TEXT,
                    FOREIGN KEY(job_id) REFERENCES scan_jobs(job_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_errors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    error_text TEXT NOT NULL,
                    FOREIGN KEY(job_id) REFERENCES scan_jobs(job_id)
                )
                """
            )
            conn.commit()


# Ensure the DB schema exists when the module is imported by gunicorn.
init_db()


def persist_job(snapshot: dict) -> None:
    with DB_LOCK:
        with get_db_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scan_jobs (
                    job_id, target, resolved_ip, start_port, end_port, timeout, max_workers,
                    banner_grab, status, created_at, started_at, finished_at, elapsed_seconds,
                    scanned_count, total_ports, open_count, error_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot["job_id"],
                    snapshot["target"],
                    snapshot["resolved_ip"],
                    snapshot["start_port"],
                    snapshot["end_port"],
                    snapshot["timeout"],
                    snapshot["max_workers"],
                    1 if snapshot.get("banner_grab") else 0,
                    snapshot["status"],
                    snapshot["created_at"],
                    snapshot["started_at"],
                    snapshot["finished_at"],
                    snapshot["elapsed_seconds"],
                    snapshot["scanned_count"],
                    snapshot["total_ports"],
                    snapshot["open_count"],
                    len(snapshot["errors"]),
                ),
            )
            conn.execute("DELETE FROM scan_open_ports WHERE job_id = ?", (snapshot["job_id"],))
            conn.execute("DELETE FROM scan_errors WHERE job_id = ?", (snapshot["job_id"],))
            conn.executemany(
                "INSERT INTO scan_open_ports (job_id, port, service, banner) VALUES (?, ?, ?, ?)",
                [
                    (
                        snapshot["job_id"],
                        row["port"],
                        row["service"],
                        row.get("banner") or "",
                    )
                    for row in snapshot["open_ports"]
                ],
            )
            conn.executemany(
                "INSERT INTO scan_errors (job_id, error_text) VALUES (?, ?)",
                [(snapshot["job_id"], item) for item in snapshot["errors"]],
            )
            conn.commit()


def fetch_job_from_db(job_id: str) -> dict | None:
    with DB_LOCK:
        with get_db_connection() as conn:
            job_row = conn.execute("SELECT * FROM scan_jobs WHERE job_id = ?", (job_id,)).fetchone()
            if not job_row:
                return None

            open_rows = conn.execute(
                "SELECT port, service, banner FROM scan_open_ports WHERE job_id = ? ORDER BY port ASC",
                (job_id,),
            ).fetchall()
            error_rows = conn.execute(
                "SELECT error_text FROM scan_errors WHERE job_id = ? ORDER BY id ASC",
                (job_id,),
            ).fetchall()

    open_ports = [
        {
            "port": row["port"],
            "service": row["service"],
            "banner": row["banner"] or "",
        }
        for row in open_rows
    ]
    errors = [row["error_text"] for row in error_rows]

    return {
        "job_id": job_row["job_id"],
        "status": job_row["status"],
        "target": job_row["target"],
        "resolved_ip": job_row["resolved_ip"],
        "start_port": job_row["start_port"],
        "end_port": job_row["end_port"],
        "timeout": job_row["timeout"],
        "max_workers": job_row["max_workers"],
        "banner_grab": bool(job_row["banner_grab"]),
        "scanned_count": job_row["scanned_count"],
        "total_ports": job_row["total_ports"],
        "open_count": len(open_ports),
        "open_ports": open_ports,
        "errors": errors,
        "elapsed_seconds": job_row["elapsed_seconds"],
        "created_at": job_row["created_at"],
        "started_at": job_row["started_at"],
        "finished_at": job_row["finished_at"],
    }


def fetch_history(limit: int = 25) -> list[dict]:
    with DB_LOCK:
        with get_db_connection() as conn:
            rows = conn.execute(
                """
                SELECT job_id, target, resolved_ip, status, start_port, end_port, open_count,
                       elapsed_seconds, created_at, finished_at, banner_grab
                FROM scan_jobs
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

    return [
        {
            "job_id": row["job_id"],
            "target": row["target"],
            "resolved_ip": row["resolved_ip"],
            "status": row["status"],
            "start_port": row["start_port"],
            "end_port": row["end_port"],
            "open_count": row["open_count"],
            "elapsed_seconds": row["elapsed_seconds"],
            "created_at": row["created_at"],
            "finished_at": row["finished_at"],
            "banner_grab": bool(row["banner_grab"]),
        }
        for row in rows
    ]


def csv_escape(value: str) -> str:
    safe = str(value).replace('"', '""')
    return f'"{safe}"'


def grab_banner(ip: str, port: int, timeout: float) -> str:
    # Keep this lightweight and optional to avoid slowing scans heavily.
    probe_timeout = max(0.2, min(timeout, 1.0))
    try:
        with socket.create_connection((ip, port), timeout=probe_timeout) as sock:
            sock.settimeout(probe_timeout)

            if port in {80, 8080, 8000, 8008, 8081, 8088, 8443}:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            elif port in {25, 587}:
                sock.sendall(b"EHLO scanner.local\r\n")
            elif port == 21:
                sock.sendall(b"QUIT\r\n")
            elif port in {110, 995}:
                sock.sendall(b"QUIT\r\n")
            elif port in {143, 993}:
                sock.sendall(b"a001 CAPABILITY\r\n")

            data = sock.recv(256)
            text = data.decode("utf-8", errors="replace").strip()
            return text[:160]
    except Exception:
        return ""


def cleanup_finished_jobs_locked() -> None:
    finished = []
    for job in JOBS.values():
        if job.status in {"completed", "stopped"} and not job.is_active():
            finished.append(job)

    if len(JOBS) <= MAX_STORED_JOBS:
        return

    # Evict oldest completed/stopped jobs first and keep active jobs intact.
    finished_sorted = sorted(finished, key=lambda item: item.created_at)
    overflow = len(JOBS) - MAX_STORED_JOBS
    for job in finished_sorted[:overflow]:
        JOBS.pop(job.job_id, None)


def validate_scan_request(payload: dict) -> tuple[bool, str]:
    required = ["target", "start_port", "end_port", "timeout", "max_workers"]
    if any(key not in payload for key in required):
        return False, "Missing required fields."

    target = str(payload.get("target", "")).strip()
    if not target:
        return False, "Target is required."

    try:
        start_port = int(payload["start_port"])
        end_port = int(payload["end_port"])
        timeout = float(payload["timeout"])
        max_workers = int(payload["max_workers"])
    except (TypeError, ValueError):
        return False, "Invalid numeric values in request."

    if start_port < 0 or end_port > 65535 or start_port > end_port:
        return False, "Port range must be between 0 and 65535 and start <= end."
    if timeout < 0.01 or timeout > 10:
        return False, "Timeout must be between 0.01 and 10 seconds."
    if max_workers < 1 or max_workers > 1000:
        return False, "Max workers must be between 1 and 1000."

    return True, ""


def run_scan(job: ScanJob) -> None:
    job.started_at = _now()
    job.total_ports = (job.end_port - job.start_port) + 1
    with job._lock:
        job.status = "running"

    ports = Queue()
    for port in range(job.start_port, job.end_port + 1):
        ports.put(port)

    worker_count = max(1, min(job.max_workers, job.total_ports))
    threads: list[threading.Thread] = []
    for _ in range(worker_count):
        thread = threading.Thread(target=scan_worker, args=(job, ports), daemon=True)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    with job._lock:
        if job._stop_event.is_set():
            job.status = "stopped"
        elif job.status in {"running", "stopping"}:
            job.status = "completed"
        job.finished_at = _now()

    persist_job(job_to_dict(job))


def scan_worker(job: ScanJob, ports: Queue) -> None:
    while True:
        if job._stop_event.is_set():
            return
        try:
            port = ports.get_nowait()
        except Empty:
            return

        scan_one_port(job, port)
        ports.task_done()


def scan_one_port(job: ScanJob, port: int) -> None:
    try:
        if job._stop_event.is_set():
            return
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(job.timeout)
            result = sock.connect_ex((job.resolved_ip, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                banner = ""
                if job.banner_grab:
                    banner = grab_banner(job.resolved_ip, port, job.timeout)
                with job._lock:
                    job.open_ports.append({"port": port, "service": service, "banner": banner})
    except Exception as exc:
        with job._lock:
            if len(job.errors) < 30:
                job.errors.append(f"Port {port}: {exc}")
    finally:
        with job._lock:
            job.scanned_count += 1


def job_to_dict(job: ScanJob) -> dict:
    with job._lock:
        open_ports_sorted = sorted(job.open_ports, key=lambda row: row["port"])
        response = {
            "job_id": job.job_id,
            "status": job.status,
            "target": job.target_input,
            "resolved_ip": job.resolved_ip,
            "start_port": job.start_port,
            "end_port": job.end_port,
            "timeout": job.timeout,
            "max_workers": job.max_workers,
            "banner_grab": job.banner_grab,
            "scanned_count": job.scanned_count,
            "total_ports": job.total_ports,
            "open_count": len(open_ports_sorted),
            "open_ports": open_ports_sorted,
            "errors": list(job.errors),
            "elapsed_seconds": round(job.elapsed(), 2),
            "created_at": job.created_at,
            "started_at": job.started_at,
            "finished_at": job.finished_at,
        }
    return response


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/scan/start")
def start_scan():
    if request.content_length and request.content_length > 10_000:
        return jsonify({"ok": False, "error": "Request payload is too large."}), 413

    payload = request.get_json(silent=True) or {}
    is_valid, message = validate_scan_request(payload)
    if not is_valid:
        return jsonify({"ok": False, "error": message}), 400

    target = str(payload["target"]).strip()
    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        return jsonify({"ok": False, "error": f"Unable to resolve target: {exc}"}), 400

    job = ScanJob(
        job_id=uuid.uuid4().hex,
        target_input=target,
        resolved_ip=resolved_ip,
        start_port=int(payload["start_port"]),
        end_port=int(payload["end_port"]),
        timeout=float(payload["timeout"]),
        max_workers=int(payload["max_workers"]),
        banner_grab=bool(payload.get("banner_grab", False)),
    )

    thread = threading.Thread(target=run_scan, args=(job,), daemon=True)
    job._thread = thread

    with JOBS_LOCK:
        active_jobs = [item for item in JOBS.values() if item.status in {"queued", "running", "stopping"} and item.is_active()]
        if len(active_jobs) >= MAX_ACTIVE_JOBS:
            return jsonify({"ok": False, "error": "Too many active scans. Please wait for a running scan to finish."}), 429
        JOBS[job.job_id] = job
        cleanup_finished_jobs_locked()

    thread.start()
    return jsonify({"ok": True, "job": job_to_dict(job)})


@app.post("/api/scan/<job_id>/stop")
def stop_scan(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({"ok": False, "error": "Scan job not found."}), 404

    job.stop()
    return jsonify({"ok": True, "job": job_to_dict(job)})


@app.get("/api/scan/<job_id>/status")
def scan_status(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job:
        return jsonify({"ok": True, "job": job_to_dict(job)})

    snapshot = fetch_job_from_db(job_id)
    if not snapshot:
        return jsonify({"ok": False, "error": "Scan job not found."}), 404
    return jsonify({"ok": True, "job": snapshot})


@app.get("/api/scan/<job_id>/export")
def export_scan(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job:
        snapshot = job_to_dict(job)
    else:
        snapshot = fetch_job_from_db(job_id)
        if not snapshot:
            return jsonify({"ok": False, "error": "Scan job not found."}), 404

    export_format = request.args.get("format", "txt").strip().lower()
    if export_format not in {"txt", "csv", "json"}:
        return jsonify({"ok": False, "error": "Unsupported export format."}), 400

    if export_format == "txt":
        lines = [
            "Network Port Scan Results",
            f"Target: {snapshot['target']}",
            f"Resolved IP: {snapshot['resolved_ip']}",
            f"Range: {snapshot['start_port']} - {snapshot['end_port']}",
            f"Status: {snapshot['status']}",
            f"Elapsed: {snapshot['elapsed_seconds']} seconds",
            f"Banner Grab: {'Enabled' if snapshot.get('banner_grab') else 'Disabled'}",
            "",
            "Open Ports:",
        ]
        if snapshot["open_ports"]:
            for row in snapshot["open_ports"]:
                banner = f" | Banner: {row.get('banner', '')}" if row.get("banner") else ""
                lines.append(f"- {row['port']} ({row['service']}){banner}")
        else:
            lines.append("- None")
        if snapshot["errors"]:
            lines.extend(["", "Errors:"])
            lines.extend([f"- {item}" for item in snapshot["errors"]])
        content = "\n".join(lines)
        file_obj = io.BytesIO(content.encode("utf-8"))
        mime = "text/plain"
        ext = "txt"
    elif export_format == "csv":
        rows = ["port,service,banner"]
        for row in snapshot["open_ports"]:
            rows.append(
                ",".join(
                    [
                        str(row["port"]),
                        csv_escape(row["service"]),
                        csv_escape(row.get("banner", "")),
                    ]
                )
            )
        content = "\n".join(rows)
        file_obj = io.BytesIO(content.encode("utf-8"))
        mime = "text/csv"
        ext = "csv"
    else:
        file_obj = io.BytesIO(json.dumps({"job": snapshot}, indent=2).encode("utf-8"))
        mime = "application/json"
        ext = "json"

    safe_target = re.sub(r"[^A-Za-z0-9._-]", "_", snapshot["target"])[:60] or "target"
    name = f"scan_{safe_target}_{int(_now())}.{ext}"
    return send_file(file_obj, as_attachment=True, download_name=name, mimetype=mime)


@app.get("/api/history")
def history_list():
    raw_limit = request.args.get("limit", "25")
    try:
        limit = int(raw_limit)
    except ValueError:
        return jsonify({"ok": False, "error": "Invalid limit."}), 400
    limit = max(1, min(limit, 100))
    return jsonify({"ok": True, "items": fetch_history(limit)})


@app.get("/api/history/<job_id>")
def history_item(job_id: str):
    snapshot = fetch_job_from_db(job_id)
    if not snapshot:
        return jsonify({"ok": False, "error": "History item not found."}), 404
    return jsonify({"ok": True, "job": snapshot})


def main() -> None:
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)


if __name__ == "__main__":
    main()
