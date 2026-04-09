"""
Browser automation via agent-browser CLI.

Agents call `agent-browser` commands directly via Bash.
Uses Browser Use cloud API (BROWSER_USE_API_KEY) for stealth browsers
with anti-detection, CAPTCHA solving, and residential proxies.

No local Playwright/Chrome needed. No server process to manage.

Setup:
    npm install -g agent-browser
    agent-browser install
    export BROWSER_USE_API_KEY="bu_..."
"""
