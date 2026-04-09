# Multi-Agent Security Reviewer

AI-powered multi-agent security vulnerability scanner.
Uses a single Opus master orchestrator that dynamically spawns 50-100 specialized security agents.

## Architecture

**Master Orchestrator** (Opus, 500 turns) — decides everything: ordering, parallelism, agent count.
Uses the Agent tool to spawn subagents from `agents/definitions.py`.

Key files:
- `config.py` — Scan config (auth, models, duration, aggressiveness)
- `shared_memory.py` — File-based shared state for agent coordination
- `agents/definitions.py` — 43 subagent definitions with security-specific prompts
- `prompts/master_orchestrator.py` — Master agent prompt builder
- `pipeline.py` — Thin wrapper: builds prompt → launches master agent → streams events
- `web.py` — Flask web UI with SSE real-time streaming + D3 agent graph
- `main.py` — CLI entry point

## Subagents (~30)

**Recon**: subdomain_scanner, port_scanner, tech_fingerprinter, dns_enumerator, crawler
**Injection**: sqli_agent, xss_agent, command_injection_agent, ssti_agent, xxe_agent, ldap_injection_agent, nosql_injection_agent
**Auth/Session**: auth_bypass_agent, session_hijack_agent, jwt_attack_agent, csrf_agent, idor_agent
**Infrastructure**: ssrf_agent, cors_agent, header_analysis_agent, ssl_tls_agent, open_redirect_agent
**Code/Supply**: secret_scanner, dependency_scanner, api_fuzzer, file_upload_agent, path_traversal_agent
**Advanced**: business_logic_agent, race_condition_agent, deserialization_agent, graphql_agent, websocket_agent
**Aggressive**: brute_force_agent, otp_bypass_agent, password_reset_agent, credential_stuffing_agent, payment_fraud_agent, info_disclosure_agent, realtime_channel_agent
**AI/LLM Security**: mcp_tool_poisoning_agent, ai_prompt_injection_agent, supply_chain_deep_agent, toxic_flow_agent, cloud_metadata_ssrf_agent
**Protocol/Cache**: http_smuggling_agent, cache_attack_agent, client_side_attack_agent, subdomain_takeover_agent, email_injection_agent
**Coordination**: dedup_coordinator, exploit_chainer, false_positive_filter, report_generator

## Pipeline Flow (master agent decides)

```
Recon (5 agents parallel) → Attack Surface Analysis →
Parallel Attack (30-80 agents: injection, auth, infra, supply, advanced, AI/LLM) →
Coordination (dedup, chain, FP filter) → Report Generation
```

## Browser Automation — `agent-browser` + Browser Use Cloud

Agents use `agent-browser` CLI for real browser-based attacks with stealth, anti-detection,
CAPTCHA solving, and residential proxies via Browser Use cloud API.

No local Playwright/Chrome needed. No server process. Agents call `agent-browser` via Bash.

### Browser-enabled agents:
xss_agent, csrf_agent, client_side_attack_agent, payment_fraud_agent, session_hijack_agent,
cors_agent, open_redirect_agent, crawler, business_logic_agent, info_disclosure_agent,
auth_bypass_agent, brute_force_agent

### What browser adds over curl:
- JS execution (verify XSS actually fires alert())
- Form interaction (fill, submit, handle client-side validation, CAPTCHA)
- Payment form manipulation (hidden field modification via JS)
- Cookie/localStorage/sessionStorage extraction
- Network traffic capture, interception, HAR recording
- Screenshot evidence
- Stealth browsing (anti-bot detection bypass)

### Setup:
```bash
npm install -g agent-browser
agent-browser install
export BROWSER_USE_API_KEY="bu_..."
```

## Shared Memory

Agents coordinate via `{workspace}/.shared_memory/` JSON files:
- `discovered_endpoints.json` — URLs found by recon
- `findings.json` — All vulnerabilities (with CVSS scores)
- `agent_claims.json` — Prevents duplicate work
- `attack_surface.json` — Full surface map
- `exploit_chains.json` — Combined attack paths

## Usage

```bash
# Web UI
python main.py web --port 5002

# CLI — attack brief describes target, tech stack, and focus areas
python main.py scan -i "Target: https://example.com. Tech: PHP/MySQL. Focus on SQLi and auth bypass."
python main.py scan -i @brief.txt --duration 30min --aggressiveness aggressive
python main.py scan -i "https://shop.example.com — e-commerce, Razorpay payments, test everything" --model sonnet --max-agents 100
```

## Auth

Inherits auth automatically from Claude Code session (VS Code extension or CLI login).
No ANTHROPIC_API_KEY needed. Falls back to ANTHROPIC_AUTH_TOKEN or ANTHROPIC_API_KEY env vars if set.

## Model Routing

- **Opus**: master orchestrator, exploit_chainer, business_logic_agent, report_generator, ai_prompt_injection_agent, toxic_flow_agent
- **Sonnet**: injection, auth, infrastructure, supply chain, advanced, MCP/cloud agents
- **Haiku**: recon agents (cheap, high-volume)

## Security Standards

Findings mapped to:
- OWASP Top 10 (2021)
- CWE Top 25 (2025)
- CVSS v3.1 scoring
