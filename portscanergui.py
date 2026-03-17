import io
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field

from flask import Flask, jsonify, render_template, request, send_file

# Service map can be extended as needed.
COMMON_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    123: "NTP",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    1723: "PPTP",
    1883: "MQTT",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5672: "AMQP",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
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
    if timeout <= 0 or timeout > 10:
        return False, "Timeout must be between 0.01 and 10 seconds."
    if max_workers < 1 or max_workers > 1000:
        return False, "Max workers must be between 1 and 1000."

    return True, ""


def run_scan(job: ScanJob) -> None:
    job.started_at = _now()
    job.total_ports = (job.end_port - job.start_port) + 1
    with job._lock:
        job.status = "running"

    semaphore = threading.Semaphore(job.max_workers)
    threads: list[threading.Thread] = []

    for port in range(job.start_port, job.end_port + 1):
        if job._stop_event.is_set():
            break
        semaphore.acquire()
        thread = threading.Thread(target=scan_one_port, args=(job, semaphore, port), daemon=True)
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


def scan_one_port(job: ScanJob, semaphore: threading.Semaphore, port: int) -> None:
    try:
        if job._stop_event.is_set():
            return
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(job.timeout)
            result = sock.connect_ex((job.resolved_ip, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                with job._lock:
                    job.open_ports.append({"port": port, "service": service})
    except Exception as exc:
        with job._lock:
            if len(job.errors) < 30:
                job.errors.append(f"Port {port}: {exc}")
    finally:
        with job._lock:
            job.scanned_count += 1
        semaphore.release()


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
    )

    thread = threading.Thread(target=run_scan, args=(job,), daemon=True)
    job._thread = thread

    with JOBS_LOCK:
        JOBS[job.job_id] = job

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
    if not job:
        return jsonify({"ok": False, "error": "Scan job not found."}), 404
    return jsonify({"ok": True, "job": job_to_dict(job)})


@app.get("/api/scan/<job_id>/export")
def export_scan(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({"ok": False, "error": "Scan job not found."}), 404

    snapshot = job_to_dict(job)
    lines = [
        "Network Port Scan Results",
        f"Target: {snapshot['target']}",
        f"Resolved IP: {snapshot['resolved_ip']}",
        f"Range: {snapshot['start_port']} - {snapshot['end_port']}",
        f"Status: {snapshot['status']}",
        f"Elapsed: {snapshot['elapsed_seconds']} seconds",
        "",
        "Open Ports:",
    ]

    if snapshot["open_ports"]:
        for row in snapshot["open_ports"]:
            lines.append(f"- {row['port']} ({row['service']})")
    else:
        lines.append("- None")

    if snapshot["errors"]:
        lines.extend(["", "Errors:"])
        lines.extend([f"- {item}" for item in snapshot["errors"]])

    content = "\n".join(lines)
    file_obj = io.BytesIO(content.encode("utf-8"))
    name = f"scan_{snapshot['target'].replace('.', '_')}_{int(_now())}.txt"
    return send_file(file_obj, as_attachment=True, download_name=name, mimetype="text/plain")


def main() -> None:
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
