"""
Multi-Agent Security Reviewer — Shared Memory

File-based shared state for agent coordination. Agents read/write JSON files
in the workspace to share discoveries, avoid duplication, and chain exploits.

No Redis dependency — uses filesystem with atomic writes for simplicity.
"""
from __future__ import annotations

import json
import fcntl
import time
from pathlib import Path
from typing import Any


class SharedMemory:
    """File-based shared memory for coordinating security agents."""

    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.memory_dir = workspace / ".shared_memory"
        self.memory_dir.mkdir(parents=True, exist_ok=True)

        # Initialize memory files
        self._init_file("discovered_endpoints.json", [])
        self._init_file("discovered_params.json", [])
        self._init_file("discovered_technologies.json", [])
        self._init_file("findings.json", [])
        self._init_file("agent_claims.json", {})
        self._init_file("attack_surface.json", {
            "subdomains": [],
            "open_ports": [],
            "endpoints": [],
            "forms": [],
            "api_routes": [],
            "file_upload_points": [],
            "auth_endpoints": [],
            "websocket_endpoints": [],
            "graphql_endpoints": [],
        })
        self._init_file("exploit_chains.json", [])
        self._init_file("user_answers.json", [])

    def _init_file(self, name: str, default: Any):
        path = self.memory_dir / name
        if not path.exists():
            self._atomic_write(path, default)

    def _atomic_write(self, path: Path, data: Any):
        """Write JSON atomically with file locking."""
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, default=str))
        tmp.rename(path)

    def _read_locked(self, name: str) -> Any:
        path = self.memory_dir / name
        if not path.exists():
            return None
        with open(path, "r") as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                return json.load(f)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    def _append_locked(self, name: str, item: Any):
        path = self.memory_dir / name
        with open(path, "r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                data = json.load(f)
                data.append(item)
                f.seek(0)
                f.truncate()
                json.dump(data, f, indent=2, default=str)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    def _update_dict_locked(self, name: str, key: str, value: Any):
        path = self.memory_dir / name
        with open(path, "r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                data = json.load(f)
                if isinstance(data.get(key), list):
                    if isinstance(value, list):
                        existing = set(json.dumps(x, sort_keys=True) for x in data[key])
                        for v in value:
                            if json.dumps(v, sort_keys=True) not in existing:
                                data[key].append(v)
                    else:
                        data[key].append(value)
                else:
                    data[key] = value
                f.seek(0)
                f.truncate()
                json.dump(data, f, indent=2, default=str)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    # ── Public API ──

    def add_endpoint(self, endpoint: dict):
        """Register a discovered endpoint: {url, method, params, source_agent}"""
        self._append_locked("discovered_endpoints.json", {
            **endpoint,
            "timestamp": time.time(),
        })

    def add_finding(self, finding: dict):
        """Register a vulnerability finding with CVSS score."""
        self._append_locked("findings.json", {
            **finding,
            "timestamp": time.time(),
        })

    def add_technology(self, tech: dict):
        """Register discovered technology: {name, version, category}"""
        self._append_locked("discovered_technologies.json", {
            **tech,
            "timestamp": time.time(),
        })

    def claim_target(self, agent_id: str, target_desc: str) -> bool:
        """Claim a specific attack target to avoid duplication. Returns True if claimed."""
        path = self.memory_dir / "agent_claims.json"
        with open(path, "r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                data = json.load(f)
                if target_desc in data:
                    return False  # Already claimed
                data[target_desc] = {
                    "agent_id": agent_id,
                    "timestamp": time.time(),
                }
                f.seek(0)
                f.truncate()
                json.dump(data, f, indent=2, default=str)
                return True
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    def update_attack_surface(self, category: str, items: list):
        """Add items to attack surface category."""
        self._update_dict_locked("attack_surface.json", category, items)

    def add_exploit_chain(self, chain: dict):
        """Register an exploit chain combining multiple findings."""
        self._append_locked("exploit_chains.json", {
            **chain,
            "timestamp": time.time(),
        })

    def get_findings(self) -> list:
        return self._read_locked("findings.json") or []

    def get_attack_surface(self) -> dict:
        return self._read_locked("attack_surface.json") or {}

    def get_endpoints(self) -> list:
        return self._read_locked("discovered_endpoints.json") or []

    def get_technologies(self) -> list:
        return self._read_locked("discovered_technologies.json") or []

    def get_claims(self) -> dict:
        return self._read_locked("agent_claims.json") or {}

    def get_exploit_chains(self) -> list:
        return self._read_locked("exploit_chains.json") or []

    def add_user_answer(self, question: str, answer: str):
        """Store a user-provided answer for agents to read."""
        self._append_locked("user_answers.json", {
            "question": question,
            "answer": answer,
            "timestamp": time.time(),
        })

    def get_user_answers(self) -> list:
        return self._read_locked("user_answers.json") or []

    def get_summary(self) -> dict:
        """Get a summary of all shared memory for master agent context."""
        findings = self.get_findings()
        # Filter out any non-dict entries (agents may append strings by mistake)
        dict_findings = [f for f in findings if isinstance(f, dict)]
        surface = self.get_attack_surface()
        return {
            "total_findings": len(dict_findings),
            "critical": sum(1 for f in dict_findings if f.get("severity") == "critical"),
            "high": sum(1 for f in dict_findings if f.get("severity") == "high"),
            "medium": sum(1 for f in dict_findings if f.get("severity") == "medium"),
            "low": sum(1 for f in dict_findings if f.get("severity") == "low"),
            "info": sum(1 for f in dict_findings if f.get("severity") == "info"),
            "endpoints_discovered": len(self.get_endpoints()),
            "technologies": len(self.get_technologies()),
            "exploit_chains": len(self.get_exploit_chains()),
            "attack_surface": {k: len(v) for k, v in surface.items() if isinstance(v, list)},
            "active_claims": len(self.get_claims()),
        }


def build_shared_memory_prompt(workspace: str) -> str:
    """Build a prompt section explaining shared memory to agents."""
    return f"""## Shared Memory System

You have access to a shared memory system at {workspace}/.shared_memory/
All agents read and write to these JSON files to coordinate:

### Files you can READ (to understand what others found):
- `discovered_endpoints.json` — URLs, methods, params found by recon agents
- `discovered_technologies.json` — Server tech, frameworks, versions detected
- `findings.json` — All vulnerabilities found so far (check before testing same thing)
- `agent_claims.json` — What targets are already claimed by other agents
- `attack_surface.json` — Full attack surface map (subdomains, ports, endpoints, forms, APIs)
- `exploit_chains.json` — Combined attack chains discovered
- `user_answers.json` — Answers provided by the human operator (credentials, OTP codes, scope clarifications, etc.)

### IMPORTANT: Check user_answers.json FIRST
Before using AskUserQuestion, READ `user_answers.json` — the operator may have already provided the info you need (credentials, OTP codes, API keys, scope clarifications). If AskUserQuestion fails or times out, ALWAYS check user_answers.json as a fallback.

### Files you WRITE to (to share your discoveries):
1. Before testing a target, READ agent_claims.json to check if another agent already claimed it.
2. Write your claim: append your agent ID + target to agent_claims.json
3. After EXPLOITING a vulnerability (NOT just suspecting one), append to findings.json:
```json
{{
  "id": "VULN-<type>-<number>",
  "type": "<vulnerability_type>",
  "severity": "critical|high|medium|low",
  "cvss_score": 8.5,
  "proof_type": "exploited|verified|demonstrated",
  "title": "What you ACTUALLY DID (not what might be possible)",
  "description": "What the vulnerability is and what you proved",
  "endpoint": "https://exact-url.com/path",
  "method": "POST",
  "exact_request": "Full curl command or agent-browser commands used",
  "exact_response": "The actual response proving exploitation (truncated to key part)",
  "screenshot": "findings/VULN-XSS-001_proof.png",
  "reproduction_steps": ["Step 1: Run this command...", "Step 2: Observe..."],
  "impact": "Concrete: attacker can do X (not 'could potentially').",
  "remediation": "how to fix with code example",
  "cwe": "CWE-89",
  "owasp": "A03:2021"
}}
```
**DO NOT write to findings.json if you only SUSPECT a vulnerability.**
**ONLY write when you have exact_request + exact_response proving it.**
4. If you discover new endpoints, forms, or API routes, append to discovered_endpoints.json
5. If you find technology info (server, framework, version), append to discovered_technologies.json

### Coordination Rules:
- ALWAYS check findings.json before testing — don't duplicate work
- ALWAYS check agent_claims.json before starting work on a target
- If you find something that could be CHAINED with another agent's finding, write to exploit_chains.json
- Read other agents' findings for inspiration — e.g., if SSRF found, try SSRF→internal port scan
"""
