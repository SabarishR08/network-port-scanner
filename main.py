from __future__ import annotations

import io
import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field

from flask import Flask, jsonify, render_template, request, send_file
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from analyzer import analyze_ports_risk_with_source
from config import SETTINGS
from scanner import ScanConfig, resolve_ports_and_settings, scan_ports
from utils import (
    build_recommendations,
    classify_target_type,
    get_public_scan_warning,
    is_allowed_in_safe_mode,
    parse_risk_line,
    resolve_target,
    sanitize_filename,
)

app = Flask(__name__)

DB_LOCK = threading.Lock()
JOBS_LOCK = threading.Lock()
JOBS: dict[str, "ScanJob"] = {}


@dataclass
class ScanJob:
    job_id: str
    target: str
    resolved_ip: str
    mode: str
    profile: str | None
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    snapshot: dict = field(default_factory=dict)
    warning: str | None = None
    thread: threading.Thread | None = None

    def is_active(self) -> bool:
        return bool(self.thread and self.thread.is_alive())


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(SETTINGS.db_path)
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
                    mode TEXT NOT NULL,
                    profile TEXT,
                    status TEXT NOT NULL,
                    warning TEXT,
                    created_at REAL,
                    finished_at REAL,
                    elapsed_seconds REAL,
                    scanned_count INTEGER,
                    total_ports INTEGER,
                    open_count INTEGER,
                    recommendations_json TEXT,
                    comparison_json TEXT
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
                    risk TEXT,
                    reason TEXT,
                    ai_source TEXT,
                    FOREIGN KEY(job_id) REFERENCES scan_jobs(job_id)
                )
                """
            )
            ensure_schema_migrations(conn)
            conn.commit()


def ensure_column(conn: sqlite3.Connection, table: str, column: str, ddl_suffix: str) -> None:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    existing = {row[1] for row in rows}
    if column not in existing:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_suffix}")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc).lower():
                raise


def ensure_schema_migrations(conn: sqlite3.Connection) -> None:
    ensure_column(conn, "scan_jobs", "start_port", "INTEGER DEFAULT 1")
    ensure_column(conn, "scan_jobs", "end_port", "INTEGER DEFAULT 65535")
    ensure_column(conn, "scan_jobs", "timeout", "REAL DEFAULT 0.5")
    ensure_column(conn, "scan_jobs", "max_workers", "INTEGER DEFAULT 200")
    ensure_column(conn, "scan_jobs", "banner_grab", "INTEGER DEFAULT 1")
    ensure_column(conn, "scan_jobs", "mode", "TEXT DEFAULT 'SAFE_MODE'")
    ensure_column(conn, "scan_jobs", "profile", "TEXT")
    ensure_column(conn, "scan_jobs", "warning", "TEXT")
    ensure_column(conn, "scan_jobs", "recommendations_json", "TEXT")
    ensure_column(conn, "scan_jobs", "comparison_json", "TEXT")

    ensure_column(conn, "scan_open_ports", "risk", "TEXT")
    ensure_column(conn, "scan_open_ports", "reason", "TEXT")
    ensure_column(conn, "scan_open_ports", "ai_source", "TEXT DEFAULT 'fallback'")


init_db()


def compare_with_previous(target: str, current_open_ports: list[dict], current_job_id: str) -> dict:
    current_set = {int(item["port"]) for item in current_open_ports}

    with DB_LOCK:
        with get_db_connection() as conn:
            previous = conn.execute(
                """
                SELECT job_id FROM scan_jobs
                WHERE target = ? AND status = 'completed' AND job_id != ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (target, current_job_id),
            ).fetchone()

            if not previous:
                return {
                    "new_ports": sorted(current_set),
                    "closed_ports": [],
                    "message": f"New ports detected: {len(current_set)}",
                }

            rows = conn.execute(
                "SELECT port FROM scan_open_ports WHERE job_id = ?",
                (previous["job_id"],),
            ).fetchall()

    previous_set = {int(r["port"]) for r in rows}
    new_ports = sorted(current_set - previous_set)
    closed_ports = sorted(previous_set - current_set)
    return {
        "new_ports": new_ports,
        "closed_ports": closed_ports,
        "message": f"New ports detected: {len(new_ports)}",
    }


def persist_snapshot(snapshot: dict) -> None:
    with DB_LOCK:
        with get_db_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scan_jobs (
                    job_id, target, resolved_ip, start_port, end_port, timeout, max_workers,
                    banner_grab, mode, profile, status, warning, created_at, finished_at,
                    elapsed_seconds, scanned_count, total_ports, open_count, recommendations_json,
                    comparison_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot["job_id"],
                    snapshot["target"],
                    snapshot["resolved_ip"],
                    snapshot.get("start_port", 1),
                    snapshot.get("end_port", 65535),
                    snapshot.get("timeout", 0.5),
                    snapshot.get("max_workers", 200),
                    1 if snapshot.get("banner_grab", True) else 0,
                    snapshot["mode"],
                    snapshot.get("profile"),
                    snapshot["status"],
                    snapshot.get("warning"),
                    snapshot["created_at"],
                    snapshot["finished_at"],
                    snapshot["elapsed_seconds"],
                    snapshot["scanned_count"],
                    snapshot["total_ports"],
                    snapshot["open_count"],
                    json.dumps(snapshot.get("recommendations", [])),
                    json.dumps(snapshot.get("comparison", {})),
                ),
            )
            conn.execute("DELETE FROM scan_open_ports WHERE job_id = ?", (snapshot["job_id"],))
            conn.executemany(
                """
                INSERT INTO scan_open_ports (job_id, port, service, banner, risk, reason, ai_source)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        snapshot["job_id"],
                        row["port"],
                        row["service"],
                        row.get("banner", ""),
                        row.get("risk", "Unknown"),
                        row.get("reason", "Unable to analyze"),
                        row.get("ai_source", "fallback"),
                    )
                    for row in snapshot["open_ports"]
                ],
            )
            conn.commit()


def fetch_snapshot(job_id: str) -> dict | None:
    with DB_LOCK:
        with get_db_connection() as conn:
            job_row = conn.execute("SELECT * FROM scan_jobs WHERE job_id = ?", (job_id,)).fetchone()
            if not job_row:
                return None
            ports = conn.execute(
                "SELECT port, service, banner, risk, reason, ai_source FROM scan_open_ports WHERE job_id = ? ORDER BY port ASC",
                (job_id,),
            ).fetchall()

    recommendations = json.loads(job_row["recommendations_json"] or "[]")
    comparison = json.loads(job_row["comparison_json"] or "{}")

    open_ports = [
        {
            "port": row["port"],
            "service": row["service"],
            "banner": row["banner"] or "",
            "risk": row["risk"] or "Unknown",
            "reason": row["reason"] or "Unable to analyze",
            "ai_source": row["ai_source"] or "fallback",
        }
        for row in ports
    ]

    return {
        "job_id": job_row["job_id"],
        "target": job_row["target"],
        "resolved_ip": job_row["resolved_ip"],
        "target_type": classify_target_type(job_row["resolved_ip"]),
        "mode": job_row["mode"],
        "profile": job_row["profile"],
        "status": job_row["status"],
        "warning": job_row["warning"],
        "created_at": job_row["created_at"],
        "finished_at": job_row["finished_at"],
        "elapsed_seconds": job_row["elapsed_seconds"],
        "scanned_count": job_row["scanned_count"],
        "total_ports": job_row["total_ports"],
        "open_count": len(open_ports),
        "open_ports": open_ports,
        "recommendations": recommendations,
        "comparison": comparison,
        "errors": [],
    }


def fetch_history(limit: int = 20) -> list[dict]:
    with DB_LOCK:
        with get_db_connection() as conn:
            rows = conn.execute(
                """
                SELECT job_id, target, resolved_ip, mode, profile, status, warning,
                      created_at, finished_at, elapsed_seconds, open_count,
                      start_port, end_port, banner_grab
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
            "mode": row["mode"],
            "profile": row["profile"],
            "status": row["status"],
            "warning": row["warning"],
            "created_at": row["created_at"],
            "finished_at": row["finished_at"],
            "elapsed_seconds": row["elapsed_seconds"],
            "open_count": row["open_count"],
            "start_port": row["start_port"],
            "end_port": row["end_port"],
            "banner_grab": bool(row["banner_grab"]),
        }
        for row in rows
    ]


def run_job(job: ScanJob, payload: dict) -> None:
    try:
        ports, timeout, max_workers = resolve_ports_and_settings(
            profile=job.profile,
            start_port=payload.get("start_port"),
            end_port=payload.get("end_port"),
            timeout=payload.get("timeout"),
            max_workers=payload.get("max_workers"),
        )

        banner_grab = bool(payload.get("banner_grab", True))
        scan_result = scan_ports(
            ScanConfig(
                target_input=job.target,
                resolved_ip=job.resolved_ip,
                ports=ports,
                timeout=timeout,
                max_workers=max_workers,
                banner_grab=banner_grab,
            )
        )
        start_port = min(ports) if ports else 1
        end_port = max(ports) if ports else 1

        risk_by_port = analyze_ports_risk_with_source(scan_result["open_ports"])
        enriched_ports: list[dict] = []
        for row in scan_result["open_ports"]:
            meta = risk_by_port.get(int(row["port"]), {"line": "Risk: Unknown | Reason: Unable to analyze", "source": "fallback"})
            risk_line = meta.get("line", "Risk: Unknown | Reason: Unable to analyze")
            risk, reason = parse_risk_line(risk_line)
            enriched_ports.append(
                {
                    "port": row["port"],
                    "service": row["service"],
                    "banner": row.get("banner", ""),
                    "risk": risk,
                    "reason": reason,
                    "ai_source": meta.get("source", "fallback"),
                }
            )

        recommendations = build_recommendations(enriched_ports)
        comparison = compare_with_previous(job.target, enriched_ports, job.job_id)

        snapshot = {
            "job_id": job.job_id,
            "target": job.target,
            "resolved_ip": job.resolved_ip,
            "target_type": classify_target_type(job.resolved_ip),
            "start_port": start_port,
            "end_port": end_port,
            "timeout": timeout,
            "max_workers": max_workers,
            "banner_grab": banner_grab,
            "mode": job.mode,
            "profile": job.profile,
            "status": "completed",
            "warning": job.warning,
            "created_at": job.created_at,
            "finished_at": scan_result["finished_at"],
            "elapsed_seconds": scan_result["elapsed_seconds"],
            "scanned_count": scan_result["scanned_count"],
            "total_ports": scan_result["total_ports"],
            "open_count": len(enriched_ports),
            "open_ports": enriched_ports,
            "recommendations": recommendations,
            "comparison": comparison,
            "errors": scan_result.get("errors", []),
        }

        job.status = "completed"
        job.finished_at = time.time()
        job.snapshot = snapshot
        persist_snapshot(snapshot)
    except Exception as exc:
        job.status = "failed"
        job.finished_at = time.time()
        snapshot = {
            "job_id": job.job_id,
            "target": job.target,
            "resolved_ip": job.resolved_ip,
            "target_type": classify_target_type(job.resolved_ip),
            "start_port": 1,
            "end_port": 1,
            "timeout": 0.5,
            "max_workers": 1,
            "banner_grab": False,
            "mode": job.mode,
            "profile": job.profile,
            "status": "failed",
            "warning": job.warning,
            "created_at": job.created_at,
            "finished_at": job.finished_at,
            "elapsed_seconds": round(max(0.0, job.finished_at - job.created_at), 2),
            "scanned_count": 0,
            "total_ports": 0,
            "open_count": 0,
            "open_ports": [],
            "recommendations": [],
            "comparison": {"new_ports": [], "closed_ports": [], "message": "New ports detected: 0"},
            "errors": [str(exc)],
        }
        job.snapshot = snapshot
        persist_snapshot(snapshot)


def validate_numeric_inputs(payload: dict) -> tuple[bool, str]:
    if payload.get("profile"):
        return True, ""

    required = ["start_port", "end_port", "timeout", "max_workers"]
    if any(key not in payload for key in required):
        return False, "Missing scan fields. Provide profile or start_port/end_port/timeout/max_workers"

    try:
        start_port = int(payload["start_port"])
        end_port = int(payload["end_port"])
        timeout = float(payload["timeout"])
        workers = int(payload["max_workers"])
    except (TypeError, ValueError):
        return False, "Invalid numeric values"

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        return False, "Port range must be 1..65535 and start_port <= end_port"
    if timeout < 0.05 or timeout > 10:
        return False, "Timeout must be between 0.05 and 10 seconds"
    if workers < 1 or workers > 1000:
        return False, "max_workers must be between 1 and 1000"
    return True, ""


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/scan/start")
def start_scan():
    payload = request.get_json(silent=True) or {}
    target = str(payload.get("target", "")).strip()
    if not target:
        return jsonify({"ok": False, "error": "Target is required"}), 400

    mode = str(payload.get("mode", SETTINGS.scan_mode)).strip().upper()
    if mode not in {"SAFE_MODE", "ADVANCED_MODE"}:
        return jsonify({"ok": False, "error": "mode must be SAFE_MODE or ADVANCED_MODE"}), 400

    valid, err = validate_numeric_inputs(payload)
    if not valid:
        return jsonify({"ok": False, "error": err}), 400

    try:
        resolved_ip = resolve_target(target)
    except Exception as exc:
        return jsonify({"ok": False, "error": f"Unable to resolve target: {exc}"}), 400

    if mode == "SAFE_MODE" and not is_allowed_in_safe_mode(target, resolved_ip):
        return jsonify(
            {
                "ok": False,
                "error": "SAFE_MODE blocks this target. Allowed: 127.0.0.1, scanme.nmap.org, private IP ranges",
            }
        ), 403

    with JOBS_LOCK:
        active_jobs = [j for j in JOBS.values() if j.is_active() and j.status in {"queued", "running"}]
        if len(active_jobs) >= SETTINGS.max_active_jobs:
            return jsonify({"ok": False, "error": "Too many active scans. Try again later."}), 429

        job = ScanJob(
            job_id=uuid.uuid4().hex,
            target=target,
            resolved_ip=resolved_ip,
            mode=mode,
            profile=payload.get("profile"),
            status="running",
            warning=get_public_scan_warning(resolved_ip),
        )
        thread = threading.Thread(target=run_job, args=(job, payload), daemon=True)
        job.thread = thread
        JOBS[job.job_id] = job
        thread.start()

    in_flight = {
        "job_id": job.job_id,
        "target": job.target,
        "resolved_ip": job.resolved_ip,
        "target_type": classify_target_type(job.resolved_ip),
        "start_port": 1,
        "end_port": 1,
        "timeout": float(payload.get("timeout", 0.5) or 0.5),
        "max_workers": int(payload.get("max_workers", 200) or 200),
        "banner_grab": bool(payload.get("banner_grab", True)),
        "mode": job.mode,
        "profile": job.profile,
        "status": "running",
        "warning": job.warning,
        "created_at": job.created_at,
        "finished_at": None,
        "elapsed_seconds": 0,
        "scanned_count": 0,
        "total_ports": 0,
        "open_count": 0,
        "open_ports": [],
        "recommendations": [],
        "comparison": {"new_ports": [], "closed_ports": [], "message": "New ports detected: 0"},
        "errors": [],
    }

    return jsonify({"ok": True, "job": in_flight})


@app.get("/api/scan/<job_id>/status")
def scan_status(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)

    if job:
        if job.status == "running":
            return jsonify(
                {
                    "ok": True,
                    "job": {
                        "job_id": job.job_id,
                        "target": job.target,
                        "resolved_ip": job.resolved_ip,
                        "target_type": classify_target_type(job.resolved_ip),
                        "mode": job.mode,
                        "profile": job.profile,
                        "status": "running",
                        "warning": job.warning,
                        "created_at": job.created_at,
                        "finished_at": job.finished_at,
                        "elapsed_seconds": round(max(0.0, time.time() - job.created_at), 2),
                        "scanned_count": 0,
                        "total_ports": 0,
                        "open_count": 0,
                        "open_ports": [],
                        "recommendations": [],
                        "comparison": {"new_ports": [], "closed_ports": [], "message": "New ports detected: 0"},
                        "errors": [],
                    },
                }
            )

        if job.snapshot:
            return jsonify({"ok": True, "job": job.snapshot})

    snapshot = fetch_snapshot(job_id)
    if not snapshot:
        return jsonify({"ok": False, "error": "Scan job not found"}), 404

    return jsonify({"ok": True, "job": snapshot})


@app.post("/api/scan/<job_id>/stop")
def stop_scan(job_id: str):
    # Current scanner runs finite threaded jobs; stop API kept for compatibility.
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({"ok": False, "error": "Scan job not found"}), 404
    return jsonify({"ok": True, "job": job.snapshot or {"job_id": job.job_id, "status": job.status}})


@app.get("/api/history")
def history_list():
    raw_limit = request.args.get("limit", "20")
    try:
        limit = max(1, min(100, int(raw_limit)))
    except ValueError:
        return jsonify({"ok": False, "error": "Invalid limit"}), 400

    return jsonify({"ok": True, "items": fetch_history(limit)})


@app.get("/api/history/<job_id>")
def history_item(job_id: str):
    snapshot = fetch_snapshot(job_id)
    if not snapshot:
        return jsonify({"ok": False, "error": "History item not found"}), 404
    return jsonify({"ok": True, "job": snapshot})


@app.get("/api/scan/<job_id>/export")
def export_scan(job_id: str):
    snapshot = fetch_snapshot(job_id)
    if not snapshot:
        return jsonify({"ok": False, "error": "Scan job not found"}), 404

    export_format = request.args.get("format", "txt").strip().lower()
    if export_format not in {"txt", "json", "pdf"}:
        return jsonify({"ok": False, "error": "Supported formats: txt, json, pdf"}), 400

    if export_format == "json":
        payload = {
            "target": snapshot["target"],
            "summary": {
                "status": snapshot["status"],
                "mode": snapshot["mode"],
                "target_type": snapshot["target_type"],
                "warning": snapshot.get("warning"),
                "open_count": snapshot["open_count"],
                "comparison": snapshot.get("comparison", {}),
            },
            "open_ports": snapshot["open_ports"],
            "recommendations": snapshot.get("recommendations", []),
        }
        file_obj = io.BytesIO(json.dumps(payload, indent=2).encode("utf-8"))
        mime = "application/json"
        ext = "json"
    elif export_format == "txt":
        lines = [
            "PowerScan Recon Report",
            f"Target: {snapshot['target']} ({snapshot['resolved_ip']})",
            f"Target Type: {snapshot['target_type']}",
            f"Status: {snapshot['status']}",
            f"Mode: {snapshot['mode']}",
            f"Warning: {snapshot.get('warning') or 'None'}",
            f"Elapsed: {snapshot['elapsed_seconds']} seconds",
            f"Open Ports: {snapshot['open_count']}",
            snapshot.get("comparison", {}).get("message", "New ports detected: 0"),
            "",
            "Open Port Analysis:",
        ]

        if snapshot["open_ports"]:
            for row in snapshot["open_ports"]:
                lines.append(
                    f"- {row['port']} | {row['service']} | Banner: {row.get('banner', '') or '-'} | "
                    f"Risk: {row.get('risk', 'Unknown')} | Reason: {row.get('reason', 'Unable to analyze')}"
                )
        else:
            lines.append("- No open ports detected")

        lines.append("")
        lines.append("Recommendations:")
        for rec in snapshot.get("recommendations", []):
            lines.append(f"- {rec}")

        file_obj = io.BytesIO("\n".join(lines).encode("utf-8"))
        mime = "text/plain"
        ext = "txt"
    else:
        buffer = io.BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        x = 48
        y = height - 48
        line_height = 14

        def write_line(text: str, bold: bool = False) -> None:
            nonlocal y
            if y < 60:
                pdf.showPage()
                y = height - 48
            pdf.setFont("Helvetica-Bold" if bold else "Helvetica", 10)
            pdf.drawString(x, y, text[:150])
            y -= line_height

        write_line("PowerScan Recon Report", bold=True)
        write_line(f"Target: {snapshot['target']} ({snapshot['resolved_ip']})")
        write_line(f"Target Type: {snapshot['target_type']}")
        write_line(f"Status: {snapshot['status']}")
        write_line(f"Mode: {snapshot['mode']}")
        write_line(f"Warning: {snapshot.get('warning') or 'None'}")
        write_line(f"Elapsed: {snapshot['elapsed_seconds']} seconds")
        write_line(f"Open Ports: {snapshot['open_count']}")
        write_line(snapshot.get("comparison", {}).get("message", "New ports detected: 0"))
        y -= 6

        write_line("Open Port Analysis:", bold=True)
        if snapshot["open_ports"]:
            for row in snapshot["open_ports"]:
                write_line(
                    f"{row['port']} | {row['service']} | Risk: {row.get('risk', 'Unknown')} | "
                    f"Source: {row.get('ai_source', 'fallback')}"
                )
                write_line(f"Reason: {row.get('reason', 'Unable to analyze')}")
                banner = row.get("banner", "") or "-"
                write_line(f"Banner: {banner}")
                y -= 4
        else:
            write_line("No open ports detected")

        y -= 6
        write_line("Recommendations:", bold=True)
        recs = snapshot.get("recommendations", [])
        if recs:
            for rec in recs:
                write_line(f"- {rec}")
        else:
            write_line("- No recommendations")

        pdf.save()
        buffer.seek(0)
        file_obj = buffer
        mime = "application/pdf"
        ext = "pdf"

    safe_target = sanitize_filename(snapshot["target"])
    name = f"powerscan_{safe_target}_{int(time.time())}.{ext}"
    return send_file(file_obj, as_attachment=True, download_name=name, mimetype=mime)


def main() -> None:
    app.run(host=SETTINGS.host, port=SETTINGS.port, debug=False)


if __name__ == "__main__":
    main()
