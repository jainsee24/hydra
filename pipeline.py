#!/usr/bin/env python3
"""
Multi-Agent Security Reviewer — Pipeline Runner

Thin wrapper that:
1. Builds the master orchestrator prompt
2. Builds subagent definitions
3. Launches a single Opus master agent with the Agent tool
4. Streams events to an optional SSE queue for the web UI

The master agent decides everything: ordering, parallelism, iteration.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import time

logger = logging.getLogger(__name__)
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from claude_agent_sdk import (
    query,
    ClaudeAgentOptions,
    AgentDefinition,
    ResultMessage,
    SystemMessage,
    AssistantMessage,
    UserMessage,
    TextBlock,
    ThinkingBlock,
    ToolUseBlock,
    ToolResultBlock,
    TaskStartedMessage,
    TaskProgressMessage,
    TaskNotificationMessage,
)

from config import ScanConfig, get_claude_auth_env
from agents.definitions import build_agent_definitions
from prompts.master_orchestrator import build_master_prompt
from shared_memory import SharedMemory


# ═══════════════════════════════════════════════════════════════════
# EVENT SYSTEM
# ═══════════════════════════════════════════════════════════════════

def push_event(q: queue.Queue | None, event_type: str, data: dict):
    """Push event to SSE queue if available."""
    if q:
        q.put({"type": event_type, "timestamp": time.time(), **data})


# ═══════════════════════════════════════════════════════════════════
# PIPELINE STATE
# ═══════════════════════════════════════════════════════════════════

@dataclass
class PipelineState:
    """Tracks the state of the entire security scan."""
    run_id: str = ""
    workspace: Path = None
    attack_brief: str = ""
    status: str = "pending"  # pending, running, completed, failed, stopped
    current_phase: str = ""
    phases_completed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost_usd: float = 0.0

    # Scan results (populated from shared memory)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    endpoints_discovered: int = 0
    agents_spawned: int = 0
    exploit_chains: int = 0
    report_path: str = ""

    # Active agents tracking
    active_agents: dict = field(default_factory=dict)  # task_id -> {name, status, started}

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "workspace": str(self.workspace) if self.workspace else "",
            "attack_brief": self.attack_brief[:200] if self.attack_brief else "",
            "status": self.status,
            "current_phase": self.current_phase,
            "phases_completed": self.phases_completed,
            "errors": self.errors,
            "elapsed_s": round(time.time() - self.start_time, 1) if self.start_time else 0,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cost_usd": round(self.total_cost_usd, 4),
            "total_findings": self.total_findings,
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "info": self.info_count,
            "endpoints_discovered": self.endpoints_discovered,
            "agents_spawned": self.agents_spawned,
            "exploit_chains": self.exploit_chains,
            "report_path": self.report_path,
            "active_agents": self.active_agents,
        }


# ═══════════════════════════════════════════════════════════════════
# MESSAGE HANDLER
# ═══════════════════════════════════════════════════════════════════

def _summarize_tool_input(tool_input: dict) -> str:
    """Short summary of tool input for logging."""
    if not isinstance(tool_input, dict):
        return str(tool_input)[:80]
    for key in ("file_path", "path", "command", "pattern", "description"):
        if key in tool_input:
            val = str(tool_input[key])
            return val[:120] + ("..." if len(val) > 120 else "")
    return str(tool_input)[:80]


def handle_message(
    message,
    state: PipelineState,
    event_queue: queue.Queue | None,
    shared_memory: SharedMemory | None = None,
):
    """Handle and route every message from the master agent stream."""

    # ── Result: pipeline complete ──
    if isinstance(message, ResultMessage):
        result_text = getattr(message, "result", "") or ""
        cost = getattr(message, "total_cost_usd", None)
        usage = getattr(message, "usage", None)

        if cost:
            state.total_cost_usd = cost
        if isinstance(usage, dict):
            state.total_input_tokens += usage.get("input_tokens", 0) or 0
            state.total_output_tokens += usage.get("output_tokens", 0) or 0

        push_event(event_queue, "master_result", {
            "message": result_text[:2000],
        })
        return result_text

    # ── System messages ──
    if isinstance(message, SystemMessage):
        return None

    # ── Assistant messages (text, thinking, tool calls) ──
    if isinstance(message, AssistantMessage):
        content = getattr(message, "content", [])
        for block in content:
            if isinstance(block, ThinkingBlock):
                thinking = getattr(block, "thinking", "")
                if thinking:
                    push_event(event_queue, "master_thinking", {
                        "message": thinking[:500],
                    })

            elif isinstance(block, TextBlock):
                text = getattr(block, "text", "")
                if text:
                    push_event(event_queue, "master_text", {
                        "message": text[:1000],
                    })
                    _detect_phase(text, state, event_queue)

            elif isinstance(block, ToolUseBlock):
                name = getattr(block, "name", "?")
                tool_input = getattr(block, "input", {})
                if not isinstance(tool_input, dict):
                    tool_input = {}

                if name == "AskUserQuestion":
                    question_text = tool_input.get("question", "") or tool_input.get("text", "") or str(tool_input)
                    push_event(event_queue, "user_question", {
                        "question": question_text[:2000],
                        "message": f"Agent needs input: {question_text[:200]}",
                    })
                elif name == "Agent":
                    agent_desc = tool_input.get("description", "")
                    agent_prompt = tool_input.get("prompt", "")[:200]
                    agent_type = _classify_agent(agent_desc)
                    state.agents_spawned += 1
                    push_event(event_queue, "agent_start", {
                        "agent": agent_desc or "subagent",
                        "agent_type": agent_type,
                        "message": f"Spawning: {agent_desc}",
                        "prompt_preview": agent_prompt,
                        "agent_count": state.agents_spawned,
                    })
                else:
                    summary = _summarize_tool_input(tool_input)
                    push_event(event_queue, "master_tool", {
                        "tool": name,
                        "summary": summary,
                        "message": f"{name}: {summary}",
                    })

            elif isinstance(block, ToolResultBlock):
                raw = getattr(block, "content", "")
                if isinstance(raw, list):
                    parts = [getattr(item, "text", str(item)) for item in raw]
                    raw = "\n".join(parts)
                if isinstance(raw, str) and raw:
                    push_event(event_queue, "master_tool_result", {
                        "content": raw[:2000],
                    })

        return None

    # ── Task events (subagent lifecycle) ──
    if isinstance(message, TaskStartedMessage):
        task_id = getattr(message, "task_id", "?")
        state.active_agents[task_id] = {
            "status": "running",
            "started": time.time(),
        }
        push_event(event_queue, "task_started", {
            "task_id": task_id,
            "message": f"Agent started: {task_id}",
        })
        return None

    if isinstance(message, TaskProgressMessage):
        task_id = getattr(message, "task_id", "?")
        usage = getattr(message, "usage", None)
        tool_count = getattr(message, "tool_use_count", None)
        duration = getattr(message, "duration_ms", None)
        parts = []
        if usage:
            inp = getattr(usage, "input_tokens", 0) or 0
            out = getattr(usage, "output_tokens", 0) or 0
            if inp or out:
                parts.append(f"tokens={inp}+{out}")
        if tool_count:
            parts.append(f"tools={tool_count}")
        if duration:
            parts.append(f"{duration/1000:.1f}s")
        push_event(event_queue, "task_progress", {
            "task_id": task_id,
            "message": " ".join(parts) if parts else f"task={task_id}",
        })
        return None

    if isinstance(message, TaskNotificationMessage):
        task_id = getattr(message, "task_id", "?")
        status = getattr(message, "status", None)
        status_str = getattr(status, "value", str(status)) if status else ""

        # Update active agents
        if task_id in state.active_agents:
            state.active_agents[task_id]["status"] = status_str

        # Update findings from shared memory and emit new_finding events
        if shared_memory:
            summary = shared_memory.get_summary()
            old_count = state.total_findings
            state.total_findings = summary["total_findings"]
            state.critical_count = summary["critical"]
            state.high_count = summary["high"]
            state.medium_count = summary["medium"]
            state.low_count = summary["low"]
            state.info_count = summary["info"]

            # Emit events for new findings
            if state.total_findings > old_count:
                all_findings = shared_memory.get_findings()
                for finding in all_findings[old_count:]:
                    if not isinstance(finding, dict):
                        continue
                    sev = finding.get("severity", "info")
                    title = finding.get("title", finding.get("type", "Unknown"))
                    push_event(event_queue, "new_finding", {
                        "severity": sev,
                        "title": title,
                        "cvss": finding.get("cvss_score", ""),
                        "endpoint": finding.get("endpoint", ""),
                        "message": f"[{sev.upper()}] {title}",
                    })
            state.endpoints_discovered = summary["endpoints_discovered"]
            state.exploit_chains = summary["exploit_chains"]

        push_event(event_queue, "task_done", {
            "task_id": task_id,
            "status": status_str,
            "message": f"Agent done: {task_id} ({status_str})",
            "findings_update": {
                "total": state.total_findings,
                "critical": state.critical_count,
                "high": state.high_count,
                "medium": state.medium_count,
                "low": state.low_count,
                "info": state.info_count,
            },
        })
        return None

    return None


def _classify_agent(desc: str) -> str:
    """Classify agent type from description for UI visualization."""
    desc_lower = desc.lower()
    if any(w in desc_lower for w in ["recon", "scan", "crawl", "fingerprint", "dns", "subdomain", "port"]):
        return "recon"
    if any(w in desc_lower for w in ["sqli", "xss", "injection", "ssti", "xxe", "ldap", "nosql", "command"]):
        return "injection"
    if any(w in desc_lower for w in ["auth", "session", "jwt", "csrf", "idor", "bypass"]):
        return "auth"
    if any(w in desc_lower for w in ["ssrf", "cors", "header", "ssl", "tls", "redirect"]):
        return "infrastructure"
    if any(w in desc_lower for w in ["secret", "dependency", "api", "fuzz", "upload", "traversal"]):
        return "supply"
    if any(w in desc_lower for w in ["business", "race", "deserial", "graphql", "websocket"]):
        return "advanced"
    if any(w in desc_lower for w in ["dedup", "chain", "false positive", "report"]):
        return "coordination"
    return "other"


def _detect_phase(text: str, state: PipelineState, event_queue: queue.Queue | None):
    """Detect phase transitions from master agent text output."""
    text_lower = text.lower()
    phase_keywords = {
        "recon": ["starting recon", "reconnaissance", "mapping attack surface", "scanning", "crawling", "fingerprint"],
        "analysis": ["analyzing attack surface", "attack surface analysis", "deciding which"],
        "injection_attack": ["testing injection", "sql injection", "xss", "command injection", "template injection"],
        "auth_attack": ["testing auth", "authentication", "session", "jwt", "csrf", "idor"],
        "infra_attack": ["testing infrastructure", "ssrf", "cors", "headers", "ssl", "tls"],
        "supply_chain": ["scanning secrets", "dependency", "api fuzz", "file upload", "path traversal"],
        "advanced_attack": ["business logic", "race condition", "deserialization", "graphql", "websocket"],
        "brute_force": ["brute force", "credential stuffing", "default credential", "otp brute", "otp bypass", "password reset attack", "rate limit"],
        "payment_attack": ["payment", "price manipulation", "merchant key", "callback bypass", "transaction"],
        "info_recon": ["information disclosure", "source map", "stack trace", "debug endpoint", "pusher", "realtime channel"],
        "coordination": ["deduplicat", "exploit chain", "false positive", "coordinating"],
        "reporting": ["generating report", "final report", "assessment report", "writing report"],
    }

    for phase, keywords in phase_keywords.items():
        if any(kw in text_lower for kw in keywords):
            if state.current_phase != phase:
                if state.current_phase and state.current_phase not in state.phases_completed:
                    state.phases_completed.append(state.current_phase)
                    push_event(event_queue, "phase_done", {
                        "phase": state.current_phase,
                        "message": f"Completed: {state.current_phase}",
                    })
                state.current_phase = phase
                push_event(event_queue, "phase_start", {
                    "phase": phase,
                    "message": f"Starting: {phase}",
                })
            break


# ═══════════════════════════════════════════════════════════════════
# MAIN PIPELINE RUNNER
# ═══════════════════════════════════════════════════════════════════

async def run_security_scan(
    *,
    attack_brief: str,
    config: ScanConfig | None = None,
    event_queue: queue.Queue | None = None,
    stop_event=None,
) -> PipelineState:
    """
    Run the full security scan pipeline.

    Launches a single Opus master agent that orchestrates all subagents
    dynamically via the Agent tool.
    """
    if config is None:
        config = ScanConfig()
    config.attack_brief = attack_brief
    config.ensure_dirs()

    # Create unique run workspace
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    workspace = config.get_run_workspace(run_id)

    # Create workspace subdirectories
    for subdir in ["recon", "findings", "coordination"]:
        (workspace / subdir).mkdir(parents=True, exist_ok=True)

    # Save attack brief to workspace for agents to reference
    (workspace / "attack_brief.txt").write_text(attack_brief)

    # Initialize shared memory
    shared_memory = SharedMemory(workspace)

    # Initialize state
    state = PipelineState(
        run_id=run_id,
        workspace=workspace,
        attack_brief=attack_brief[:500],
        status="running",
        start_time=time.time(),
    )

    push_event(event_queue, "pipeline_start", {
        "run_id": run_id,
        "workspace": str(workspace),
        "attack_brief": attack_brief[:200],
        "message": f"Security scan started",
    })

    # Build subagent definitions (with browser port if enabled)
    agent_defs = build_agent_definitions(str(workspace), config)

    # Convert to AgentDefinition objects for Claude SDK
    sdk_agents = {}
    for name, defn in agent_defs.items():
        sdk_agents[name] = AgentDefinition(
            description=defn["description"],
            prompt=defn["prompt"],
            model=defn["model"],
            tools=defn["tools"],
        )

    # Build master prompt
    master_prompt = build_master_prompt(
        attack_brief=attack_brief,
        config=config,
        workspace=workspace,
    )

    # Save prompt for debugging
    (workspace / "master_prompt.txt").write_text(master_prompt)

    # Run the master orchestrator agent
    result_text = ""
    try:
        async for message in query(
            prompt=master_prompt,
            options=ClaudeAgentOptions(
                model=config.master_model,
                cwd=str(workspace),
                allowed_tools=[
                    "Read", "Write", "Bash", "Glob", "Grep",
                    "Agent", "WebSearch", "WebFetch",
                ],
                agents=sdk_agents,
                permission_mode="acceptEdits",
                max_turns=config.master_max_turns,
                env={
                    **get_claude_auth_env(),
                    **({"BROWSER_USE_API_KEY": config.browser_use_api_key} if config.browser_use_api_key else {}),
                    **({"AGENT_BROWSER_PROVIDER": "browseruse"} if config.browser_use_api_key else {}),
                },
            ),
        ):
            # Check stop signal
            if stop_event and stop_event.is_set():
                state.status = "stopped"
                push_event(event_queue, "pipeline_stopped", {
                    "message": "Scan stopped by user",
                })
                break

            # Check time budget
            elapsed = time.time() - state.start_time
            if elapsed > config.scan_duration:
                state.status = "timeout"
                push_event(event_queue, "pipeline_timeout", {
                    "message": f"Scan timed out after {config.scan_duration}s",
                })
                break

            result = handle_message(message, state, event_queue, shared_memory)
            if result is not None and isinstance(result, str):
                result_text = result

    except Exception as e:
        state.status = "failed"
        state.errors.append(str(e))
        push_event(event_queue, "pipeline_error", {
            "error": str(e),
            "message": f"Scan failed: {e}",
        })
    else:
        if state.status == "running":
            state.status = "completed"

    # Final scan of shared memory for results
    summary = shared_memory.get_summary()
    state.total_findings = summary["total_findings"]
    state.critical_count = summary["critical"]
    state.high_count = summary["high"]
    state.medium_count = summary["medium"]
    state.low_count = summary["low"]
    state.info_count = summary["info"]
    state.endpoints_discovered = summary["endpoints_discovered"]
    state.exploit_chains = summary["exploit_chains"]

    # Check for report
    report_path = workspace / "report.md"
    if report_path.exists():
        state.report_path = str(report_path)

    state.end_time = time.time()

    # Complete remaining phase
    if state.current_phase and state.current_phase not in state.phases_completed:
        state.phases_completed.append(state.current_phase)

    # Save final state
    state_path = workspace / "scan_state.json"
    state_path.write_text(json.dumps(state.to_dict(), indent=2, default=str))

    push_event(event_queue, "pipeline_done", {
        "status": state.status,
        "message": f"Scan {state.status} — {state.to_dict()['elapsed_s']}s",
        "total_findings": state.total_findings,
        "critical": state.critical_count,
        "high": state.high_count,
        "medium": state.medium_count,
        "low": state.low_count,
        "agents_spawned": state.agents_spawned,
        "report_path": state.report_path,
    })

    return state
