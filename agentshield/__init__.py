"""
AgentShield: High-Performance Autonomous AI Runtime Security & Firewall Gateway.
"""

from agentshield.core.firewall import AIFirewall
from agentshield.core.pii_dlp import PIISanitizer
from agentshield.core.tool_gatekeeper import ToolGatekeeper
from agentshield.core.audit_logger import AuditLogger
from agentshield.proxy.server import run_proxy_server

__version__ = "1.0.0"

def protect(host: str = "127.0.0.1", port: int = 8080, upstream: str = None):
    """One-line activation: launches the autonomous shield proxy server."""
    run_proxy_server(host=host, port=port, upstream=upstream)

__all__ = [
    "AIFirewall",
    "PIISanitizer",
    "ToolGatekeeper",
    "AuditLogger",
    "run_proxy_server",
    "protect"
]
