"""
Multi-Agent Security Reviewer — Configuration

Supports Claude OAuth (preferred) or API key authentication.
Routes intensive tasks to Opus, lighter tasks to Sonnet, recon to Haiku.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

_auth_logged = False


def get_claude_auth_env() -> dict[str, str]:
    """Build env dict for Claude Agent SDK.

    Auth resolution order:
    1. ANTHROPIC_AUTH_TOKEN env var (explicit OAuth token)
    2. ANTHROPIC_API_KEY env var (explicit API key)
    3. Empty dict — claude_agent_sdk inherits auth from the Claude Code
       session automatically (OAuth via VS Code extension / CLI login).
       This is the normal case; no env vars needed.
    """
    global _auth_logged
    env = {}

    auth_token = os.getenv("ANTHROPIC_AUTH_TOKEN")
    if auth_token:
        env["ANTHROPIC_AUTH_TOKEN"] = auth_token
        if not _auth_logged:
            logger.info("Using ANTHROPIC_AUTH_TOKEN (OAuth)")
            _auth_logged = True
        return env

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if api_key:
        env["ANTHROPIC_API_KEY"] = api_key
        if not _auth_logged:
            logger.info("Using ANTHROPIC_API_KEY")
            _auth_logged = True
        return env

    # No explicit env vars — SDK will inherit auth from Claude Code session
    if not _auth_logged:
        logger.info("Using inherited Claude Code session auth (no explicit key needed)")
        _auth_logged = True
    return env


# ═══════════════════════════════════════════════════════════════════
# MODEL ROUTING
# ═══════════════════════════════════════════════════════════════════

MODELS = {
    "opus": "claude-opus-4-6",
    "sonnet": "claude-sonnet-4-6",
    "haiku": "claude-haiku-4-5-20251001",
}

_OPUS_TASKS = {
    "master_orchestrator",
    "exploit_chainer",
    "business_logic",
    "report_generator",
    "race_condition",
    "ai_prompt_injection",
    "toxic_flow",
}

_HAIKU_TASKS = {
    "subdomain_scan",
    "port_scan",
    "tech_fingerprint",
    "dns_enum",
    "crawler",
    "header_analysis",
    "ssl_tls",
}


def model_for_task(task_type: str) -> str:
    """Return the appropriate model for a given task type."""
    if task_type in _OPUS_TASKS:
        return MODELS["opus"]
    if task_type in _HAIKU_TASKS:
        return MODELS["haiku"]
    return MODELS["sonnet"]


# ═══════════════════════════════════════════════════════════════════
# SCAN AGGRESSIVENESS LEVELS
# ═══════════════════════════════════════════════════════════════════

AGGRESSIVENESS = {
    "passive": "Only observe, no active probing. Read headers, crawl public pages, check TLS.",
    "active": "Send crafted requests to test for vulnerabilities. No destructive payloads.",
    "aggressive": "Full attack simulation. SQLi, XSS, fuzzing with payloads. Authorized pentest only.",
}

# ═══════════════════════════════════════════════════════════════════
# SCAN DURATION PRESETS (seconds)
# ═══════════════════════════════════════════════════════════════════

DURATION_PRESETS = {
    "15min": 900,
    "30min": 1800,
    "1hr": 3600,
    "2hr": 7200,
    "4hr": 14400,
}


# ═══════════════════════════════════════════════════════════════════
# PIPELINE CONFIG
# ═══════════════════════════════════════════════════════════════════

@dataclass
class ScanConfig:
    """Full configuration for the security review pipeline."""

    # ── Project paths ──
    base_dir: Path = field(default_factory=lambda: Path(__file__).parent)
    workspace_dir: Path = None

    # ── Target ──
    attack_brief: str = ""  # Free-form description of target, URLs, tech stack, attack focus

    # ── Scan parameters ──
    scan_duration: int = 3600  # seconds
    aggressiveness: str = "active"  # passive, active, aggressive
    max_concurrent_agents: int = 50

    # ── Master agent ──
    master_model: str = MODELS["opus"]
    master_max_turns: int = 500

    # ── Browser automation (agent-browser + Browser Use cloud) ──
    browser_use_api_key: str = field(default_factory=lambda: os.getenv("BROWSER_USE_API_KEY", ""))

    # ── Web UI ──
    host: str = "0.0.0.0"
    port: int = 5002

    def __post_init__(self):
        if self.workspace_dir is None:
            self.workspace_dir = self.base_dir / "workspace"

    def ensure_dirs(self):
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

    def get_run_workspace(self, run_id: str) -> Path:
        ws = self.workspace_dir / run_id
        ws.mkdir(parents=True, exist_ok=True)
        return ws
