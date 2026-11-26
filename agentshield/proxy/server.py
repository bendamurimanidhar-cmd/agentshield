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
from agentshield.core.jsonwalk import iter_strings, map_strings
from agentshield import __version__

MAX_BODY_BYTES = 10 * 1024 * 1024
UPSTREAM_TIMEOUT_S = 300  # long completions routinely take over 30 s
DROP_REQUEST_HEADERS = {"host", "content-length", "accept-encoding", "connection", "keep-alive", "transfer-encoding"}
DROP_RESPONSE_HEADERS = {"content-length", "transfer-encoding", "content-encoding", "connection", "keep-alive"}
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
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            if content_len > MAX_BODY_BYTES:
                self.send_error(413, "Payload Too Large")
                return
            raw_body = self.rfile.read(content_len).decode("utf-8", errors="ignore")

            # 1. Parse payload (any JSON shape: OpenAI, Anthropic, list-form content, or raw text)
            tool_calls = []
            try:
                parsed_json = json.loads(raw_body)
                is_json = True
            except ValueError:
                parsed_json, is_json = None, False
            if is_json:
                # Inspect every string in the body, not only messages[].content: list-form content
                # parts and fields like Anthropic's "system" were previously skipped entirely.
                extracted_text = " ".join(iter_strings(parsed_json))
                if isinstance(parsed_json, dict) and isinstance(parsed_json.get("tool_calls"), list):
                    tool_calls = parsed_json["tool_calls"]
            else:
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

            # 4. RUNTIME DATA LOSS PREVENTION: redact each string value, so the JSON stays valid
            redactions = 0
            def redact(text: str) -> str:
                nonlocal redactions
                out, meta = self.dlp.scan_and_redact(text)
                redactions += meta["findings_count"]
                return out
            if is_json:
                sanitized = map_strings(parsed_json, redact)
                payload_to_forward = json.dumps(sanitized)
            else:
                sanitized = payload_to_forward = redact(raw_body)

            # Log authorized clean transaction
            audit_record = self.logger.log_event("REQUEST_CLEARED", {
                "client": self.client_address[0],
                "path": self.path,
                "latency_ms": fw_res["latency_ms"],
                "dlp_redactions": redactions
            })

            # 5. FORWARDING / RESPONSE
            if self.upstream_url:
                self._forward_upstream(payload_to_forward)
            else:
                # Standalone Protected Shield Mock / Pass-through Response
                resp_data = {
                    "status": "APPROVED",
                    "shield": f"AgentShield v{__version__}",
                    "firewall": "PASSED (<0.05ms)",
                    "dlp_redactions": redactions,
                    "sanitized_input": sanitized if redactions else "CLEAN",
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
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.send_error(500, f"Internal Error: {str(e)}")

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
        # Drop headers that no longer match the (possibly redacted) body, and ask for an
        # uncompressed reply so the response DLP scan can read it.
        headers = {k: v for k, v in self.headers.items() if k.lower() not in DROP_REQUEST_HEADERS}
        headers["Accept-Encoding"] = "identity"
        req = urllib.request.Request(target, data=body_str.encode("utf-8"), headers=headers, method="POST")
        try:
            resp = urllib.request.urlopen(req, timeout=UPSTREAM_TIMEOUT_S)
        except urllib.error.HTTPError as e:
            resp = e  # upstream 4xx/5xx: relay it like any other response
        except Exception as e:
            self.send_error(502, f"Bad Gateway: {str(e)}")
            return
        with resp:
            # Scan outgoing response for PII leaks
            sanitized_resp, _ = self.dlp.scan_and_redact(resp.read().decode("utf-8", errors="ignore"))
            out_bytes = sanitized_resp.encode("utf-8")
            self.send_response(resp.status)
            for h, val in resp.headers.items():
                if h.lower() not in DROP_RESPONSE_HEADERS:
                    self.send_header(h, val)
            self.send_header("Content-Length", str(len(out_bytes)))
            self.end_headers()
            self.wfile.write(out_bytes)

class ConcurrentThreadingHTTPServer(http.server.ThreadingHTTPServer):
    request_queue_size = 256
    daemon_threads = True

def run_proxy_server(host: str = "127.0.0.1", port: int = 8080, upstream: Optional[str] = None):
    AgentShieldProxyHandler.upstream_url = upstream
    server_address = (host, port)
    # Use ConcurrentThreadingHTTPServer with request_queue_size=256 for high-concurrency multi-agent swarms
    httpd = ConcurrentThreadingHTTPServer(server_address, AgentShieldProxyHandler)

    print("\n" + "=" * 65)
    print(" 🛡️  AgentShield Autonomous AI Firewall & Security Gateway")
    print("=" * 65)
    print(f" Status        : 🟢 ACTIVE & RUNNING (Zero Manual Commands Needed)")
    print(f" Proxy Address : http://{host}:{port}")
    if upstream:
        print(f" Upstream Target: {upstream}")
    else:
        print(f" Mode          : Autonomous Guardrail & Inspection Engine")
    print(f" Audit Ledger  : {DEFAULT_LOG_PATH} (Tamper-evident SHA-256)")
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
