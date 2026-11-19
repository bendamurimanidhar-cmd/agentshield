"""
AgentShield Data Loss Prevention (DLP) & PII Sanitizer.
Detects and redacts credentials, private keys, JWTs, API tokens, and sensitive personal data.
"""

import re
from typing import Dict, Any, Tuple, List

class PIISanitizer:
    def __init__(self):
        self.dlp_rules = {
            "PRIVATE_KEY": re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
            "JWT_TOKEN": re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'),
            "OPENAI_KEY": re.compile(r'\bsk-[a-zA-Z0-9]{32,}\b', re.IGNORECASE),
            "GCP_API_KEY": re.compile(r'\bAIza[0-9A-Za-z-_]{30,40}\b'),
            "AWS_ACCESS_KEY": re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
            "GITHUB_TOKEN": re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{36,}\b', re.IGNORECASE),
            "SLACK_TOKEN": re.compile(r'\bxox[baprs]-[0-9a-zA-Z-]{10,}\b'),
            "GENERIC_SECRET": re.compile(r'(?:api[_-]?key|secret|password|bearer)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', re.IGNORECASE),
            "CREDIT_CARD": re.compile(r'\b(?:\d{4}[ -]?){3}\d{4}\b'),
            "SSN": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            "EMAIL": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        }

    def scan_and_redact(self, text: str) -> Tuple[str, Dict[str, Any]]:
        findings = []
        spans_to_replace = [] # List of (start, end, replacement_tag, rule_name)

        for rule_name, pattern in self.dlp_rules.items():
            for m in pattern.finditer(text):
                # If rule has a capture group (like generic secret), redact group 1, else whole match
                if m.lastindex and m.lastindex >= 1:
                    start, end = m.span(1)
                else:
                    start, end = m.span(0)
                spans_to_replace.append((start, end, f"[REDACTED_{rule_name}]", rule_name))
                findings.append({"type": rule_name, "value_length": end - start})

        # Sort spans in reverse order by start index so replacements do not alter preceding offsets
        spans_to_replace.sort(key=lambda s: s[0], reverse=True)

        sanitized = text
        for start, end, tag, _ in spans_to_replace:
            sanitized = sanitized[:start] + tag + sanitized[end:]

        return sanitized, {
            "has_sensitive_data": len(findings) > 0,
            "findings_count": len(findings),
            "findings": findings
        }
