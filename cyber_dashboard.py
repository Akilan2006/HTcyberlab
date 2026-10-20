from flask import Flask, render_template, redirect, url_for, request, jsonify
from pathlib import Path
import subprocess
import os
import requests
import json
from datetime import datetime

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

BASE = Path(r"C:\CyberLab")
HTTP_LOG = BASE / "http_events.log"
FIREWALL_LOG = Path(r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log")
ENV_FILE = BASE / ".env"
KALI_IP = "192.168.56.102"
TARGET_PORT = "8080"


def get_gemini_api_key():
    """Retrieves Google Studio API key securely from environment or server-side .env file."""
    # 1. System environment
    key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if key and key.strip():
        return key.strip()

    # 2. Server-side protected .env file
    if ENV_FILE.exists():
        try:
            for line in ENV_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line.startswith("GEMINI_API_KEY="):
                    val = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if val:
                        return val
        except OSError:
            pass
    return ""




def read_http_events():
    if not HTTP_LOG.exists():
        return []
    try:
        lines = HTTP_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
        return [line for line in lines if f"source={KALI_IP}" in line][-12:][::-1]
    except OSError:
        return []


def get_total_http_count():
    if not HTTP_LOG.exists():
        return 0
    try:
        lines = HTTP_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
        return sum(1 for line in lines if f"source={KALI_IP}" in line)
    except OSError:
        return 0


def clear_kali_http_events():
    if not HTTP_LOG.exists():
        return
    try:
        lines = HTTP_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
        remaining = [line for line in lines if f"source={KALI_IP}" not in line and line.strip()]
        new_content = "\n".join(remaining) + ("\n" if remaining else "")
        HTTP_LOG.write_text(new_content, encoding="utf-8")
    except OSError:
        pass


def read_firewall_events():
    if not FIREWALL_LOG.exists():
        return [], 0

    fields = None
    events = []
    drops = 0

    try:
        with FIREWALL_LOG.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#Fields:"):
                    fields = line[len("#Fields:"):].split()
                    continue
                if not line or line.startswith("#") or not fields:
                    continue

                parts = line.split()
                if len(parts) < len(fields):
                    continue

                row = dict(zip(fields, parts))
                if row.get("src-ip") != KALI_IP:
                    continue

                action = row.get("action", "").upper()
                if action not in ("DROP", "ALLOW"):
                    continue

                if action == "DROP":
                    drops += 1

                events.append({
                    "time": f"{row.get('date', '')} {row.get('time', '')}",
                    "action": action,
                    "port": row.get("dst-port", "?")
                })
    except OSError:
        pass

    return events[-12:][::-1], drops


def get_rule_status():
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=CyberLab - Block Kali"],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0:
            lines = [line.strip().lower() for line in result.stdout.splitlines()]
            is_enabled = any(line.startswith("enabled:") and "yes" in line for line in lines)
            is_block = any(line.startswith("action:") and "block" in line for line in lines)
            if is_enabled and is_block:
                return "ON"
            else:
                return "OFF"
        elif "no rules match" in result.stdout.lower():
            return "OFF"
    except (OSError, subprocess.TimeoutExpired):
        pass

    # Fallback to PowerShell if netsh is not available
    command = (
        "$r = Get-NetFirewallRule -DisplayName 'CyberLab - Block Kali' "
        "-ErrorAction SilentlyContinue | "
        "Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' }; "
        "if ($r) { 'ON' } else { 'OFF' }"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", command],
            capture_output=True, text=True, timeout=4
        )
        if result.returncode == 0:
            output = result.stdout.strip().upper()
            if output in ("ON", "OFF"):
                return output
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "UNKNOWN"


def query_gemini_api(api_key: str, prompt: str):
    """Calls Gemini REST API using preferred models with fallback."""
    models = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]
    last_error = ""

    for model in models:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = {
            "contents": [
                {
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "temperature": 0.3,
                "maxOutputTokens": 2048
            }
        }
        try:
            resp = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=25)
            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        return parts[0].get("text", "")
            else:
                error_msg = resp.text
                try:
                    error_json = resp.json()
                    error_msg = error_json.get("error", {}).get("message", resp.text)
                except Exception:
                    pass
                last_error = f"{model} returned HTTP {resp.status_code}: {error_msg}"
                # If error is invalid API key, no need to retry other models
                if resp.status_code == 400 and "API_KEY_INVALID" in error_msg:
                    return f"Error: Invalid Google Studio API Key. Please verify your API key."
        except requests.RequestException as e:
            last_error = f"Network request error: {str(e)}"

    return f"Error communicating with Gemini: {last_error}"


@app.route("/")
def dashboard():
    http_events = read_http_events()
    firewall_events, drop_count = read_firewall_events()
    return render_template(
        "dashboard.html",
        http_events=http_events,
        http_count=get_total_http_count(),
        firewall_events=firewall_events,
        drop_count=drop_count,
        rule_status=get_rule_status()
    )


@app.route("/api/live-data")
def live_data():
    """Provides real-time JSON telemetry for non-blocking dynamic dashboard polling."""
    http_events = read_http_events()
    firewall_events, drop_count = read_firewall_events()
    return jsonify({
        "http_events": http_events,
        "http_count": get_total_http_count(),
        "firewall_events": firewall_events,
        "drop_count": drop_count,
        "rule_status": get_rule_status()
    })


@app.route("/api/soc-analyst", methods=["POST"])
def soc_analyst():
    data = request.get_json(silent=True) or {}
    user_query = data.get("query", "").strip()

    # API key is read exclusively from server-side .env — never from the browser
    api_key = get_gemini_api_key()
    if not api_key:
        return jsonify({
            "status": "error",
            "error_code": "NO_API_KEY",
            "message": "Google Studio API key not configured. Set GEMINI_API_KEY in C:\\CyberLab\\.env"
        }), 400


    # Gather full contextual telemetry
    http_events = read_http_events()
    http_count = get_total_http_count()
    firewall_events, drop_count = read_firewall_events()
    rule_status = get_rule_status()

    # Build SOC context prompt
    telemetry_summary = f"""
=== CYBERLAB SOC TELEMETRY CONTEXT ===
- Monitored Windows Lab Target: 192.168.56.2 (Web Service Port: {TARGET_PORT})
- Threat Actor Source: Kali Linux ({KALI_IP})
- Active Windows Firewall Rule ('CyberLab - Block Kali'): {rule_status}
- Total HTTP Requests Logged from Kali: {http_count}
- Total Firewall DROP Events from Kali: {drop_count}

=== RECENT HTTP SERVER REQUESTS (from Kali {KALI_IP}) ===
{chr(10).join(http_events) if http_events else "No HTTP requests currently logged."}

=== RECENT WINDOWS FIREWALL EVENTS (for Kali {KALI_IP}) ===
{json.dumps(firewall_events, indent=2) if firewall_events else "No matching firewall events logged."}
"""

    analyst_instruction = f"""
You are a Senior Cyber Defense SOC Analyst (Tier 2/Tier 3) monitoring an enterprise Windows lab host being tested or attacked by an external machine (Kali Linux {KALI_IP}).

Analyze the telemetry above carefully. 
{f"The user/operator is asking: '{user_query}'" if user_query else "Perform a comprehensive SOC Triage and Threat Interpretation."}

Structure your response clearly using the following sections in clean Markdown:

### 🛡️ Threat Assessment & Severity
State current Threat Level (`CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` or `BENIGN`) with a brief 1-line justification.

### 🔍 Threat Interpretation & Attacker TTPs
- Explain what the attacker on Kali Linux is currently doing (e.g. reconnaissance, web endpoint discovery, automated port probing, payload testing, or dormant).
- Reference MITRE ATT&CK tactics/techniques if applicable (e.g., T1046 Network Service Discovery, T1190 Exploit Public-Facing Application).

### 🧱 Defense Correlation (Firewall vs Service)
- Correlate the Windows Firewall rule status with the logged events.
- Clarify whether the attack is actively penetrating to the application layer (HTTP server reached) or successfully intercepted/dropped at Layer 3/4 by the Windows Filtering Platform.

### 📋 Recommended Next Investigation Steps & Actions
- Provide 3-4 bullet points of immediate actionable steps.
- Include exact commands where helpful (e.g. PowerShell `Set-NetFirewallRule`, `netsh`, checking open sockets with `Get-NetTCPConnection`, or verification commands from Kali).
"""

    full_prompt = f"{telemetry_summary}\n\n{analyst_instruction}"
    analysis = query_gemini_api(api_key, full_prompt)

    return jsonify({
        "status": "success",
        "analysis": analysis,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "rule_status": rule_status,
        "http_count": http_count,
        "drop_count": drop_count
    })


@app.route("/clear-kali-requests", methods=["POST", "GET"])
@app.route("/clear_kali_requests", methods=["POST", "GET"])
def clear_kali_requests():
    clear_kali_http_events()
    if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
        return jsonify({"status": "success", "message": "Kali requests cleared"})
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
