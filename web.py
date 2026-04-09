#!/usr/bin/env python3
"""
Multi-Agent Security Reviewer — Web UI

Flask app with real-time SSE streaming of the security scan pipeline.
Shows agent graph visualization, live findings, and final report.
"""
from __future__ import annotations

import asyncio
import json
import os
import queue
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import (
    Flask, render_template, request, jsonify,
    Response, send_from_directory, abort,
)

from config import ScanConfig, get_claude_auth_env, MODELS, DURATION_PRESETS, AGGRESSIVENESS
from pipeline import run_security_scan, PipelineState
from shared_memory import SharedMemory


# ═══════════════════════════════════════════════════════════════════
# APP SETUP
# ═══════════════════════════════════════════════════════════════════

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "security-reviewer-dev-key")

JOBS: dict[str, dict[str, Any]] = {}
JOB_QUEUES: dict[str, queue.Queue] = {}
JOB_STOP_EVENTS: dict[str, threading.Event] = {}

DEFAULT_CONFIG = ScanConfig()
DEFAULT_CONFIG.ensure_dirs()


# ═══════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/config")
def get_config():
    """Return available configuration options."""
    return jsonify({
        "models": list(MODELS.keys()),
        "durations": DURATION_PRESETS,
        "aggressiveness_levels": AGGRESSIVENESS,
    })


@app.route("/api/start", methods=["POST"])
def start_scan():
    """Start a new security scan."""
    data = request.get_json() or {}
    attack_brief = data.get("attack_brief", "").strip()
    if not attack_brief:
        return jsonify({"error": "attack_brief is required — describe the target and attack"}), 400

    # Build config from request
    config = ScanConfig()
    config.attack_brief = attack_brief

    # Duration
    duration_key = data.get("duration", "1hr")
    if duration_key in DURATION_PRESETS:
        config.scan_duration = DURATION_PRESETS[duration_key]
    elif data.get("duration_seconds"):
        config.scan_duration = int(data["duration_seconds"])

    # Model selection
    model_choice = data.get("model", "").strip()
    if model_choice in MODELS:
        config.master_model = MODELS[model_choice]

    # Aggressiveness
    aggr = data.get("aggressiveness", "active").strip()
    if aggr in AGGRESSIVENESS:
        config.aggressiveness = aggr

    # Max agents
    max_agents = data.get("max_agents")
    if max_agents:
        config.max_concurrent_agents = int(max_agents)

    # Browser Use API key (from request or env)
    browser_key = data.get("browser_use_api_key", "").strip()
    if browser_key:
        config.browser_use_api_key = browser_key

    config.ensure_dirs()

    job_id = uuid.uuid4().hex[:8]
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    workspace = config.get_run_workspace(run_id)

    JOB_QUEUES[job_id] = queue.Queue()
    JOB_STOP_EVENTS[job_id] = threading.Event()

    JOBS[job_id] = {
        "job_id": job_id,
        "run_id": run_id,
        "workspace": str(workspace),
        "status": "running",
        "attack_brief": attack_brief[:500],
        "started_at": datetime.now().isoformat(),
        "config": {
            "duration": config.scan_duration,
            "aggressiveness": config.aggressiveness,
            "model": model_choice or "opus",
            "max_agents": config.max_concurrent_agents,
        },
        "state": None,
    }

    def _run_bg():
        try:
            state = asyncio.run(run_security_scan(
                attack_brief=attack_brief,
                config=config,
                event_queue=JOB_QUEUES[job_id],
                stop_event=JOB_STOP_EVENTS[job_id],
            ))
            JOBS[job_id]["status"] = state.status
            JOBS[job_id]["state"] = state.to_dict()
        except Exception as e:
            JOBS[job_id]["status"] = "failed"
            JOB_QUEUES[job_id].put({
                "type": "pipeline_error",
                "error": str(e),
                "message": f"Scan failed: {e}",
            })

    thread = threading.Thread(target=_run_bg, daemon=True)
    thread.start()

    return jsonify({
        "job_id": job_id,
        "run_id": run_id,
        "workspace": str(workspace),
    })


@app.route("/api/stop/<job_id>", methods=["POST"])
def stop_scan(job_id: str):
    """Stop a running scan."""
    stop_event = JOB_STOP_EVENTS.get(job_id)
    if stop_event:
        stop_event.set()
        return jsonify({"status": "stopping"})
    return jsonify({"error": "Job not found"}), 404


@app.route("/api/status/<job_id>")
def get_status(job_id: str):
    """Get scan status."""
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


@app.route("/api/jobs")
def list_jobs():
    """List all jobs."""
    return jsonify(list(JOBS.values()))


@app.route("/api/events/<job_id>")
def stream_events(job_id: str):
    """SSE endpoint for real-time scan events."""
    q = JOB_QUEUES.get(job_id)
    if not q:
        abort(404)

    def generate():
        while True:
            try:
                event = q.get(timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") in ("pipeline_done", "pipeline_error", "pipeline_stopped", "pipeline_timeout"):
                    break
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.route("/api/findings/<job_id>")
def get_findings(job_id: str):
    """Get current findings for a job."""
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    workspace = Path(job["workspace"])
    findings_path = workspace / ".shared_memory" / "findings.json"
    if findings_path.exists():
        findings = json.loads(findings_path.read_text())
        return jsonify(findings)
    return jsonify([])


@app.route("/api/report/<job_id>")
def get_report(job_id: str):
    """Get the final report."""
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    workspace = Path(job["workspace"])
    report_path = workspace / "report.md"
    if report_path.exists():
        return Response(report_path.read_text(), mimetype="text/markdown")
    return jsonify({"error": "Report not yet generated"}), 404


@app.route("/api/download/<job_id>/report")
def download_report(job_id: str):
    """Download the report file."""
    job = JOBS.get(job_id)
    if not job:
        abort(404)
    workspace = Path(job["workspace"])
    report_path = workspace / "report.md"
    if not report_path.exists():
        abort(404)
    return send_from_directory(str(workspace), "report.md", as_attachment=True)


@app.route("/api/files/<job_id>/<path:filepath>")
def get_file(job_id: str, filepath: str):
    """Get any file from the job workspace."""
    job = JOBS.get(job_id)
    if not job:
        abort(404)
    workspace = Path(job["workspace"])
    full_path = workspace / filepath
    if not full_path.exists() or not full_path.is_file():
        abort(404)
    try:
        full_path.resolve().relative_to(workspace.resolve())
    except ValueError:
        abort(403)
    return send_from_directory(str(full_path.parent), full_path.name)


@app.route("/api/user-input/<job_id>", methods=["POST"])
def submit_user_input(job_id: str):
    """Submit additional user input (credentials, OTP, scope info) for a running scan."""
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    data = request.get_json() or {}
    answer = data.get("answer", "").strip()
    question = data.get("question", "").strip()
    if not answer:
        return jsonify({"error": "answer is required"}), 400

    workspace = Path(job["workspace"])
    try:
        sm = SharedMemory(workspace)
        sm.add_user_answer(question=question, answer=answer)
    except Exception as e:
        return jsonify({"error": f"Failed to store answer: {e}"}), 500

    # Also push an event so agents can see the answer in the log
    q = JOB_QUEUES.get(job_id)
    if q:
        q.put({
            "type": "user_answer",
            "timestamp": time.time(),
            "question": question[:200],
            "answer": answer[:200],
            "message": f"User provided input: {answer[:100]}",
        })

    return jsonify({"status": "ok", "message": "Answer saved to shared memory"})


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Multi-Agent Security Reviewer — Web UI")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5002)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    print(f"\n  Multi-Agent Security Reviewer")
    print(f"  http://localhost:{args.port}\n")

    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
