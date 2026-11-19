"""
AgentShield Tool & API Execution Gatekeeper.
Validates tool invocations, intercepts destructive commands, path traversal,
command injection, SSRF, and enforces least privilege.
"""

import re
import urllib.parse
from typing import Dict, Any, List

class ToolGatekeeper:
    def __init__(self, allowed_tools: List[str] = None):
        self.allowed_tools = allowed_tools or ["read_file", "search_web", "query_database", "run_test"]

        # Destructive execution signatures
        self.destructive_patterns = [
            re.compile(r'\brm\s+-(?:rf|fr|r)\b', re.IGNORECASE),
            re.compile(r'\bmkfs\b', re.IGNORECASE),
            re.compile(r'\bdd\s+if=', re.IGNORECASE),
            re.compile(r':\(\)\s*\{\s*:\|:&\s*\};:', re.IGNORECASE),
            re.compile(r'\b(?:shutdown|reboot|halt|init\s+0)\b', re.IGNORECASE),
            re.compile(r'\bchmod\s+(?:-R\s+)?(?:777|a\+rwx)\b', re.IGNORECASE),
            re.compile(r'\bsudo\b', re.IGNORECASE),
            re.compile(r'>\s*/dev/sd[a-z]', re.IGNORECASE),
            re.compile(r'(?:curl|wget).*?\|\s*(?:sh|bash)', re.IGNORECASE)
        ]

        # Directory traversal & sensitive system paths (covers ../, ..\, .\./, etc.)
        self.path_traversal_patterns = [
            re.compile(r'(?:\.\.[/\\]|\.[/\\]\.)', re.IGNORECASE),
            re.compile(r'/(?:etc/(?:passwd|shadow|sudoers)|var/run/docker\.sock|proc/kcore)', re.IGNORECASE),
            re.compile(r'C:\\Windows\\System32\\config\\SAM', re.IGNORECASE),
            re.compile(r'[\x00]', re.IGNORECASE) # Null byte truncation
        ]

        # Shell command substitution & piping
        self.cmd_injection_patterns = [
            re.compile(r'\$\(.*?\)', re.DOTALL),
            re.compile(r'`.*?`', re.DOTALL),
            re.compile(r'[;&|]\s*(?:rm|cat|curl|wget|nc|sh|bash|python|perl)\b', re.IGNORECASE)
        ]

        # SSRF & Private Network / Cloud Metadata Targets
        self.ssrf_patterns = [
            re.compile(r'\b(?:https?://)?169\.254\.169\.254\b', re.IGNORECASE), # Cloud Metadata
            re.compile(r'\b(?:https?://)?(?:127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0)(?::\d+)?\b', re.IGNORECASE),
            re.compile(r'\b(?:https?://)?(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2[0-9]|3[01])\.\d+\.\d+)(?::\d+)?\b', re.IGNORECASE)
        ]

    def _get_decoded_variants(self, raw: str) -> List[str]:
        variants = [raw]
        # Recursively unquote up to 3 layers to defeat double/triple URL encoding
        curr = raw
        for _ in range(3):
            unq = urllib.parse.unquote(curr)
            if unq != curr:
                variants.append(unq)
                curr = unq
            else:
                break
        return variants

    def authorize_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        # 1. Tool Whitelist Check
        if self.allowed_tools and tool_name not in self.allowed_tools:
            return {
                "authorized": False,
                "reason": f"Tool '{tool_name}' is not in the authorized whitelist.",
                "policy": "TOOL_WHITELIST_VIOLATION"
            }

        raw_arg_str = str(arguments)
        variants = self._get_decoded_variants(raw_arg_str)

        for arg_str in variants:
            # 2. Inspect Arguments for Destructive Shell Code
            for pattern in self.destructive_patterns:
                m = pattern.search(arg_str)
                if m:
                    return {
                        "authorized": False,
                        "reason": f"Destructive command detected: '{m.group(0)}'",
                        "policy": "DESTRUCTIVE_EXECUTION_BLOCKED"
                    }

            # 3. Path Traversal & System File Access Check
            for pattern in self.path_traversal_patterns:
                m = pattern.search(arg_str)
                if m:
                    return {
                        "authorized": False,
                        "reason": f"Path traversal / restricted system path detected: '{m.group(0)}'",
                        "policy": "PATH_TRAVERSAL_BLOCKED"
                    }

            # 4. Command Substitution & Piping Injection Check
            for pattern in self.cmd_injection_patterns:
                m = pattern.search(arg_str)
                if m:
                    return {
                        "authorized": False,
                        "reason": f"Command substitution / shell injection detected: '{m.group(0)}'",
                        "policy": "SHELL_INJECTION_BLOCKED"
                    }

            # 5. SSRF / Private IP Targeting Check (for search / network calls)
            for pattern in self.ssrf_patterns:
                m = pattern.search(arg_str)
                if m:
                    return {
                        "authorized": False,
                        "reason": f"SSRF / Cloud metadata / Private IP access blocked: '{m.group(0)}'",
                        "policy": "SSRF_PROHIBITED"
                    }

        return {
            "authorized": True,
            "tool_name": tool_name,
            "status": "APPROVED"
        }
