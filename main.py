#!/usr/bin/env python3
"""
Multi-Agent Security Reviewer — CLI Entry Point

Usage:
    # Start web UI
    python main.py web --port 5002

    # Run scan from CLI
    python main.py scan -i "Target: https://example.com. Tech: PHP/MySQL. Focus on SQLi and auth bypass."

    # From a file
    python main.py scan -i @brief.txt --duration 30min --aggressiveness aggressive --model opus
"""
from __future__ import annotations

import argparse
import asyncio
import json
import queue
import sys
import threading
import time
from pathlib import Path

from config import ScanConfig, MODELS, DURATION_PRESETS, AGGRESSIVENESS
from pipeline import run_security_scan


# ═══════════════════════════════════════════════════════════════════
# TERMINAL COLORS
# ═══════════════════════════════════════════════════════════════════

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"


def log(msg: str, color: str = ""):
    print(f"{color}{msg}{C.RESET}")


# ═══════════════════════════════════════════════════════════════════
# EVENT PRINTER (runs in background thread)
# ═══════════════════════════════════════════════════════════════════

def event_printer(q: queue.Queue, stop_flag: threading.Event):
    """Print pipeline events to terminal with colors."""
    while not stop_flag.is_set():
        try:
            event = q.get(timeout=1)
        except queue.Empty:
            continue

        etype = event.get("type", "")
        msg = event.get("message", "")
        ts = time.strftime("%H:%M:%S")

        if etype == "pipeline_start":
            log(f"\n{ts} {'='*60}", C.BOLD + C.GREEN)
            log(f"{ts}  Security Scan Started", C.BOLD + C.GREEN)
            brief = event.get('attack_brief', '')[:150].replace('\n', ' ')
            log(f"{ts}  Brief: {brief}", C.BOLD + C.CYAN)
            log(f"{ts}  Workspace: {event.get('workspace', '')}", C.DIM)
            log(f"{ts} {'='*60}\n", C.BOLD + C.GREEN)

        elif etype == "phase_start":
            phase = event.get("phase", "?")
            log(f"\n{ts} >>> Phase: {phase}", C.BOLD + C.CYAN)

        elif etype == "phase_done":
            phase = event.get("phase", "?")
            log(f"{ts} <<< Done: {phase}", C.GREEN)

        elif etype == "agent_start":
            agent = event.get("agent", "?")
            agent_type = event.get("agent_type", "")
            count = event.get("agent_count", 0)
            color_map = {
                "recon": C.BLUE, "injection": C.RED, "auth": C.YELLOW,
                "infrastructure": C.MAGENTA, "supply": C.CYAN,
                "advanced": C.BOLD + C.RED, "coordination": C.GREEN,
            }
            color = color_map.get(agent_type, C.YELLOW)
            log(f"{ts} [agent #{count}] {agent}", C.BOLD + color)

        elif etype == "task_started":
            log(f"{ts} [task] started: {event.get('task_id', '?')}", C.DIM)

        elif etype == "task_progress":
            log(f"{ts} [task] {msg}", C.DIM)

        elif etype == "task_done":
            status = event.get("status", "?")
            findings = event.get("findings_update", {})
            total = findings.get("total", 0)
            crit = findings.get("critical", 0)
            high = findings.get("high", 0)
            findings_str = f" | findings: {total} (C:{crit} H:{high})" if total else ""
            log(f"{ts} [task] done ({status}){findings_str}", C.DIM)

        elif etype == "master_text":
            for line in msg.split("\n")[:5]:
                log(f"{ts}   {line[:150]}", C.WHITE)

        elif etype == "master_thinking":
            preview = msg[:120].replace("\n", " ")
            log(f"{ts}   (thinking) {preview}...", C.MAGENTA)

        elif etype == "master_tool":
            tool = event.get("tool", "?")
            summary = event.get("summary", "")[:100]
            log(f"{ts}   >> {tool}: {summary}", C.YELLOW)

        elif etype in ("pipeline_done", "pipeline_stopped", "pipeline_timeout"):
            total = event.get("total_findings", 0)
            crit = event.get("critical", 0)
            high = event.get("high", 0)
            medium = event.get("medium", 0)
            low = event.get("low", 0)
            agents = event.get("agents_spawned", 0)
            report = event.get("report_path", "")

            log(f"\n{ts} {'='*60}", C.BOLD + C.GREEN)
            log(f"{ts}  Scan {event.get('status', 'done')}", C.BOLD + C.GREEN)
            log(f"{ts}  Agents spawned: {agents}", C.BOLD)
            if total:
                log(f"{ts}  Findings: {total} total", C.BOLD)
                if crit:
                    log(f"{ts}    Critical: {crit}", C.BOLD + C.BG_RED)
                if high:
                    log(f"{ts}    High:     {high}", C.BOLD + C.RED)
                if medium:
                    log(f"{ts}    Medium:   {medium}", C.BOLD + C.YELLOW)
                if low:
                    log(f"{ts}    Low:      {low}", C.DIM)
            if report:
                log(f"{ts}  Report: {report}", C.BOLD + C.CYAN)
            log(f"{ts} {'='*60}\n", C.BOLD + C.GREEN)
            break

        elif etype == "pipeline_error":
            error = event.get("error", "Unknown error")
            log(f"\n{ts} ERROR: {error}", C.BOLD + C.RED)
            break

        elif etype == "heartbeat":
            pass

        else:
            if msg:
                log(f"{ts} [{etype}] {msg[:150]}", C.DIM)


# ═══════════════════════════════════════════════════════════════════
# COMMANDS
# ═══════════════════════════════════════════════════════════════════

def cmd_web(args):
    """Start the web UI."""
    from web import app
    log(f"\n  Multi-Agent Security Reviewer — Web UI", C.BOLD + C.CYAN)
    log(f"  http://localhost:{args.port}\n", C.BOLD)
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


def cmd_scan(args):
    """Run the security scan from CLI."""
    attack_brief = args.input
    # Support @filename syntax to read brief from a file
    if attack_brief.startswith("@"):
        brief_path = Path(attack_brief[1:])
        if not brief_path.exists():
            log(f"File not found: {brief_path}", C.RED)
            sys.exit(1)
        attack_brief = brief_path.read_text().strip()

    if not attack_brief:
        log("Attack brief is required. Describe the target, tech stack, and attack focus.", C.RED)
        sys.exit(1)

    # Build config
    config = ScanConfig()
    config.attack_brief = attack_brief

    if args.duration:
        if args.duration in DURATION_PRESETS:
            config.scan_duration = DURATION_PRESETS[args.duration]
        else:
            try:
                config.scan_duration = int(args.duration)
            except ValueError:
                log(f"Invalid duration: {args.duration}", C.RED)
                sys.exit(1)

    if args.aggressiveness:
        config.aggressiveness = args.aggressiveness

    if args.model:
        if args.model in MODELS:
            config.master_model = MODELS[args.model]

    if args.max_agents:
        config.max_concurrent_agents = args.max_agents

    if args.max_turns:
        config.master_max_turns = args.max_turns

    # Event queue for terminal output
    event_queue = queue.Queue()
    stop_flag = threading.Event()
    printer = threading.Thread(target=event_printer, args=(event_queue, stop_flag), daemon=True)
    printer.start()

    # Show brief preview (first 200 chars)
    brief_preview = attack_brief[:200].replace("\n", " ")
    log(f"\n  Multi-Agent Security Reviewer", C.BOLD + C.CYAN)
    log(f"  Brief: {brief_preview}{'...' if len(attack_brief) > 200 else ''}", C.BOLD)
    log(f"  Duration: {config.scan_duration}s, Aggressiveness: {config.aggressiveness}", C.DIM)
    log(f"  Model: {config.master_model}, Max agents: {config.max_concurrent_agents}", C.DIM)

    try:
        state = asyncio.run(run_security_scan(
            attack_brief=attack_brief,
            config=config,
            event_queue=event_queue,
        ))

        stop_flag.set()
        printer.join(timeout=2)

        d = state.to_dict()
        log(f"\n{'='*60}", C.BOLD)
        log(f"  Status:     {d['status']}", C.BOLD)
        log(f"  Duration:   {d['elapsed_s']}s", C.DIM)
        log(f"  Workspace:  {d['workspace']}", C.DIM)
        log(f"  Tokens:     {d['total_input_tokens']}in + {d['total_output_tokens']}out", C.DIM)
        log(f"  Cost:       ${d['total_cost_usd']}", C.DIM)
        log(f"  Agents:     {d['agents_spawned']}", C.BOLD)
        log(f"  Findings:   {d['total_findings']} total", C.BOLD)
        if d["critical"]:
            log(f"    Critical: {d['critical']}", C.BOLD + C.RED)
        if d["high"]:
            log(f"    High:     {d['high']}", C.RED)
        if d["medium"]:
            log(f"    Medium:   {d['medium']}", C.YELLOW)
        if d["low"]:
            log(f"    Low:      {d['low']}", C.DIM)
        if d["report_path"]:
            log(f"  Report:     {d['report_path']}", C.BOLD + C.CYAN)
        if d["errors"]:
            log(f"  Errors:", C.RED)
            for err in d["errors"]:
                log(f"    - {err}", C.RED)
        log(f"{'='*60}\n", C.BOLD)

    except KeyboardInterrupt:
        stop_flag.set()
        log("\nInterrupted by user.", C.YELLOW)
        sys.exit(1)
    except Exception as e:
        stop_flag.set()
        log(f"\nFatal error: {e}", C.BOLD + C.RED)
        import traceback
        traceback.print_exc()
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════
# CLI PARSER
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Multi-Agent Security Reviewer — AI-Powered Vulnerability Assessment"
    )
    subparsers = parser.add_subparsers(dest="command")

    # ── web ──
    web_parser = subparsers.add_parser("web", help="Start web UI")
    web_parser.add_argument("--host", default="0.0.0.0")
    web_parser.add_argument("--port", type=int, default=5002)
    web_parser.add_argument("--debug", action="store_true")

    # ── scan ──
    scan_parser = subparsers.add_parser("scan", help="Run security scan from CLI")
    scan_parser.add_argument(
        "--input", "-i", required=True,
        help="Attack brief: describe target, tech stack, URLs, and attack focus. Use @file.txt to read from file.",
    )
    scan_parser.add_argument(
        "--duration", "-d", default="1hr",
        help="Scan duration: 15min, 30min, 1hr, 2hr, 4hr, or seconds (default: 1hr)",
    )
    scan_parser.add_argument(
        "--aggressiveness", "-a", default="active",
        choices=["passive", "active", "aggressive"],
        help="Scan aggressiveness level (default: active)",
    )
    scan_parser.add_argument(
        "--model", "-m", default="opus",
        choices=list(MODELS.keys()),
        help="Master agent model (default: opus)",
    )
    scan_parser.add_argument(
        "--max-agents", type=int, default=None,
        help="Max concurrent agents (default: 50)",
    )
    scan_parser.add_argument(
        "--max-turns", type=int, default=None,
        help="Max master agent turns (default: 500)",
    )

    args = parser.parse_args()

    if args.command == "web":
        cmd_web(args)
    elif args.command == "scan":
        cmd_scan(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
