#!/usr/bin/env python3
"""
AgentShield Command Line Interface.
Runs as an autonomous transparent reverse proxy by default.
"""

import sys
import os
import argparse
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from agentshield.core.firewall import AIFirewall
from agentshield.core.pii_dlp import PIISanitizer
from agentshield.core.tool_gatekeeper import ToolGatekeeper
from agentshield.core.audit_logger import AuditLogger
from agentshield.proxy.server import run_proxy_server

def scan_input(text: str):
    fw = AIFirewall()
    dlp = PIISanitizer()
    logger = AuditLogger()

    print(f"\n[AgentShield Inspection] Scanning input ({len(text)} characters)...")
    fw_res = fw.inspect_prompt(text)
    sanitized_text, dlp_res = dlp.scan_and_redact(text)

    allowed = fw_res["allowed"] and not dlp_res["has_sensitive_data"]
    status_str = "🟢 ALLOWED" if allowed else "🔴 BLOCKED / INTERCEPTED"

    print(f"Status           : {status_str}")
    print(f"Inspection Speed : {fw_res['latency_ms']} ms (SLA < 5.0ms)")
    print(f"Injection Threats: {fw_res['threat_count']}")
    print(f"Sensitive Data   : {dlp_res['findings_count']} items found")

    if dlp_res["has_sensitive_data"]:
        print(f"\nSanitized Output :\n{sanitized_text}")

    if not fw_res["allowed"]:
        print("\nViolations:")
        for v in fw_res["violations"]:
            print(f"  • [{v['rule']}] matched: '{v['matched']}'")

    audit = logger.log_event("CLI_PROMPT_SCAN", {
        "verdict": "ALLOW" if allowed else "BLOCK",
        "latency_ms": fw_res["latency_ms"],
        "threats": fw_res["threat_count"],
        "dlp": dlp_res["findings_count"]
    })
    print(f"\nAudit Block Hash : {audit['hash'][:16]}...\n")

def main():
    p = argparse.ArgumentParser(
        description="AgentShield: Autonomous Runtime AI Security Firewall & Gateway",
        epilog="Default behavior: running 'agentshield' with no arguments starts the autonomous proxy server on port 8080."
    )
    sub = p.add_subparsers(dest="command")

    # 1. Start Autonomous Server (Primary Mode)
    start_p = sub.add_parser("start", help="Start the autonomous transparent proxy firewall (Zero-config)")
    start_p.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    start_p.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    start_p.add_argument("--upstream", default=None, help="Optional upstream LLM API URL to forward to (e.g. https://api.openai.com)")

    # 2. Manual inspection commands (Optional utilities)
    scan_p = sub.add_parser("scan", help="One-shot prompt scan for jailbreaks & leaks")
    scan_p.add_argument("text", help="Prompt text to inspect")

    tool_p = sub.add_parser("gate", help="Authorize a tool call before execution")
    tool_p.add_argument("tool", help="Tool name")
    tool_p.add_argument("args", help="Arguments as JSON string")

    verify_p = sub.add_parser("verify-audit", help="Verify cryptographic integrity of an audit log file")
    verify_p.add_argument("logfile", help="Path to audit log JSONL file")

    args = p.parse_args()

    if args.command in ["start", None]:
        host = getattr(args, "host", "127.0.0.1")
        port = getattr(args, "port", 8080)
        upstream = getattr(args, "upstream", None)
        run_proxy_server(host=host, port=port, upstream=upstream)
    elif args.command == "scan":
        scan_input(args.text)
    elif args.command == "gate":
        gk = ToolGatekeeper()
        try:
            parsed_args = json.loads(args.args)
        except Exception:
            parsed_args = {"raw": args.args}
        res = gk.authorize_tool_call(args.tool, parsed_args)
        print(json.dumps(res, indent=2))
    elif args.command == "verify-audit":
        logger = AuditLogger()
        res = logger.verify_chain(args.logfile)
        print(json.dumps(res, indent=2))
    else:
        p.print_help()

if __name__ == "__main__":
    main()
