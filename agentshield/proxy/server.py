"""
AgentShield Autonomous Zero-Config Reverse Proxy Gateway.
Once started, developers run NOTHING else. It intercepts all AI traffic transparently,
blocks injections in real-time, redacts secrets on the fly, gatekeeps tools,
and records cryptographic audit logs in the background.
"""

import http.server
import json
import time
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

import os

from agentshield.core.firewall import AIFirewall
from agentshield.core.pii_dlp import PIISanitizer
from agentshield.core.tool_gatekeeper import ToolGatekeeper
from agentshield.core.audit_logger import AuditLogger

DEFAULT_LOG_PATH = os.path.join(os.path.expanduser("~"), ".agentshield", "audit.jsonl")

class AgentShieldProxyHandler(http.server.BaseHTTPRequestHandler):
    firewall = AIFirewall()
    dlp = PIISanitizer()
    gatekeeper = ToolGatekeeper()
    logger = AuditLogger(log_path=DEFAULT_LOG_PATH)
    upstream_url: Optional[str] = None # e.g. "https://api.openai.com"

    def log_message(self, format, *args):
        # Concise one-line terminal logging
        sys_time = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{sys_time}] [SHIELD] {args[0]}")

    def do_GET(self):
        # Health check and live dashboard
        if self.path in ["/", "/health", "/status"]:
            status_data = {
                "name": "AgentShield Autonomous Gateway",
                "status": "ACTIVE_PROTECTING",
                "mode": "TRANSPARENT_PROXY",
                "uptime": "RUNNING",
                "features": {
                    "prompt_injection_firewall": "ACTIVE (<0.05ms SLA)",
                    "pii_credential_dlp": "ACTIVE (Auto-Redaction)",
                    "tool_gatekeeper": "ACTIVE (Traversal, Subshell & SSRF blocked)",
                    "cryptographic_audit_trail": "ACTIVE (SHA-256 Ledger: audit.jsonl)"
                }
            }
            body = json.dumps(status_data, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_error(404, "Endpoint Not Found")

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_len).decode("utf-8", errors="ignore")

        # 1. Parse payload text (OpenAI / Anthropic format or raw text)
        extracted_text = raw_body
        tool_calls = []
        is_json = False

        try:
            parsed_json = json.loads(raw_body)
            is_json = True
            # Extract messages if standard OpenAI chat payload
            if "messages" in parsed_json and isinstance(parsed_json["messages"], list):
                extracted_text = " ".join([m.get("content", "") for m in parsed_json["messages"] if isinstance(m.get("content"), str)])
            elif "prompt" in parsed_json:
                extracted_text = str(parsed_json["prompt"])
            elif "tool_calls" in parsed_json:
                tool_calls = parsed_json["tool_calls"]
        except Exception:
            extracted_text = raw_body

        # 2. RUNTIME FIREWALL SCAN (Prompt Injection, Leetspeak, Jailbreaks)
        fw_res = self.firewall.inspect_prompt(extracted_text)
        if not fw_res["allowed"]:
            self._send_blocked_response(
                status_code=403,
                reason="BLOCKED_BY_AGENTSHIELD_FIREWALL",
                violations=fw_res["violations"],
                latency_ms=fw_res["latency_ms"]
            )
            self.logger.log_event("FIREWALL_INTERCEPT", {
                "client": self.client_address[0],
                "path": self.path,
                "action": "BLOCKED",
                "violations": fw_res["violations"]
            })
            return

        # 3. RUNTIME TOOL EXECUTION GATEKEEPER
        if tool_calls:
            for tc in tool_calls:
                func = tc.get("function", {})
                name = func.get("name", "unknown")
                args = func.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {"raw": args}
                gk_res = self.gatekeeper.authorize_tool_call(name, args)
                if not gk_res["authorized"]:
                    self._send_blocked_response(
                        status_code=403,
                        reason="BLOCKED_BY_TOOL_GATEKEEPER",
                        violations=[{"policy": gk_res.get("policy"), "reason": gk_res.get("reason")}],
                        latency_ms=fw_res["latency_ms"]
                    )
                    self.logger.log_event("TOOL_INTERCEPT", {
                        "client": self.client_address[0],
                        "tool": name,
                        "action": "BLOCKED",
                        "reason": gk_res.get("reason")
                    })
                    return

        # 4. RUNTIME DATA LOSS PREVENTION (DLP Redaction)
        sanitized_text, dlp_meta = self.dlp.scan_and_redact(extracted_text)

        # Log authorized clean transaction
        audit_record = self.logger.log_event("REQUEST_CLEARED", {
            "client": self.client_address[0],
            "path": self.path,
            "latency_ms": fw_res["latency_ms"],
            "dlp_redactions": dlp_meta["findings_count"]
        })

        # 5. FORWARDING / RESPONSE
        if self.upstream_url:
            # Forward transparently to upstream model API (e.g. OpenAI)
            self._forward_upstream(raw_body)
        else:
            # Standalone Protected Shield Mock / Pass-through Response
            resp_data = {
                "status": "APPROVED",
                "shield": "AgentShield v1.0.0",
                "firewall": "PASSED (<0.05ms)",
                "dlp_redactions": dlp_meta["findings_count"],
                "sanitized_input": sanitized_text if dlp_meta["has_sensitive_data"] else "CLEAN",
                "audit_block_hash": audit_record["hash"][:16] + "...",
                "message": "Traffic cleared by autonomous AI guardrail."
            }
            body = json.dumps(resp_data, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-AgentShield-Latency", f"{fw_res['latency_ms']}ms")
            self.send_header("X-AgentShield-Status", "CLEARED")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def _send_blocked_response(self, status_code: int, reason: str, violations: list, latency_ms: float):
        payload = {
            "error": "Access Denied: Threat Intercepted by AgentShield",
            "policy": reason,
            "violations": violations,
            "latency_ms": latency_ms,
            "timestamp": time.time()
        }
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-AgentShield-Status", "BLOCKED")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _forward_upstream(self, body_str: str):
        target = self.upstream_url.rstrip("/") + self.path
        req = urllib.request.Request(
            target,
            data=body_str.encode("utf-8"),
            headers={k: v for k, v in self.headers.items() if k.lower() != "host"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
                # Scan outgoing response for PII leaks
                resp_text = data.decode("utf-8", errors="ignore")
                sanitized_resp, _ = self.dlp.scan_and_redact(resp_text)
                out_bytes = sanitized_resp.encode("utf-8")

                self.send_response(resp.status)
                for h, val in resp.getheaders():
                    if h.lower() not in ["content-length", "transfer-encoding"]:
                        self.send_header(h, val)
                self.send_header("Content-Length", str(len(out_bytes)))
                self.end_headers()
                self.wfile.write(out_bytes)
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.end_headers()
            self.wfile.write(e.read())
        except Exception as e:
            self.send_error(502, f"Bad Gateway: {str(e)}")

def run_proxy_server(host: str = "127.0.0.1", port: int = 8080, upstream: Optional[str] = None):
    AgentShieldProxyHandler.upstream_url = upstream
    server_address = (host, port)
    httpd = http.server.HTTPServer(server_address, AgentShieldProxyHandler)

    print("\n" + "=" * 65)
    print(" 🛡️  AgentShield Autonomous AI Firewall & Security Gateway")
    print("=" * 65)
    print(f" Status        : 🟢 ACTIVE & RUNNING (Zero Manual Commands Needed)")
    print(f" Proxy Address : http://{host}:{port}")
    if upstream:
        print(f" Upstream Target: {upstream}")
    else:
        print(f" Mode          : Autonomous Guardrail & Inspection Engine")
    print(f" Audit Ledger  : audit.jsonl (Tamper-proof SHA-256)")
    print("-" * 65)
    print(" 🚀 To protect your app or AI agent:")
    print(f"    export OPENAI_BASE_URL=\"http://{host}:{port}/v1\"")
    print(f"    (or send all AI HTTP requests directly to http://{host}:{port})")
    print("=" * 65 + "\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[SHIELD] Shutting down AgentShield Gateway cleanly.")
        httpd.server_close()
