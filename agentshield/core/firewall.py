"""
AgentShield High-Performance Runtime AI Firewall.
Scans incoming prompts and outputs in <5ms for prompt injection, jailbreaks,
obfuscation (leetspeak, zero-width, spaced-out), and system prompt leaks.
"""

import re
import time
import base64
import unicodedata
import urllib.parse
from typing import Dict, Any, List

class AIFirewall:
    def __init__(self, max_input_len: int = 65536):
        self.max_input_len = max_input_len

        # Leetspeak translation table
        self.leet_map = {
            '@': 'a', '4': 'a',
            '8': 'b',
            '3': 'e',
            '1': 'i', '!': 'i', '|': 'i',
            '0': 'o',
            '5': 's', '$': 's',
            '7': 't'
        }

        # 1. Standard Spaced Injection & Jailbreak Signatures
        self.injection_patterns = [
            re.compile(r'\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)', re.IGNORECASE),
            re.compile(r'\bdisregard\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)', re.IGNORECASE),
            re.compile(r'\bforget\s+(all\s+)?(previous|prior)\s+(instructions|prompts|rules)', re.IGNORECASE),
            re.compile(r'\b(dan\s+mode|jailbreak|unfiltered\s+mode|god\s+mode)\b', re.IGNORECASE),
            re.compile(r'\byou\s+are\s+now\s+in\s+developer\s+mode\b', re.IGNORECASE),
            re.compile(r'\bact\s+as\s+(an?\s+)?(?:(?:evil|unrestricted|unconstrained|nefarious|unethical|jailbroken|bad)\s*)+(?:ai|agent|assistant|bot|llm|model)\b', re.IGNORECASE),
            re.compile(r'\byou\s+have\s+no\s+(rules|restrictions|filters|limits)\b', re.IGNORECASE),
            re.compile(r'\bwhat\s+is\s+your\s+system\s+prompt\b', re.IGNORECASE),
            re.compile(r'\brepeat\s+(all\s+)?(the\s+)?(initial|original|system)\s+(instructions|prompts)', re.IGNORECASE),
            re.compile(r'\boutput\s+the\s+text\s+above\b', re.IGNORECASE),
            re.compile(r'\breveal\s+your\s+(system\s+|hidden\s+)?(prompt|instructions)\b', re.IGNORECASE),
            re.compile(r'(\[system\]|\[system_instruction\]|<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|---\s*(?:begin|end)\s*system\s*(?:prompt|instructions)\s*---)', re.IGNORECASE),
            re.compile(r'<script.*?>.*?</script>', re.IGNORECASE | re.DOTALL),
            re.compile(r'\bjavascript:\s*', re.IGNORECASE),
            re.compile(r'\bbase64\s+decode.*?(?:rm\s+-rf|sudo|chmod|cat\s+/etc)', re.IGNORECASE)
        ]

        # 2. Spaceless Invariant Signatures (catches extreme character spacing, punctuation, & concatenation)
        self.spaceless_patterns = [
            re.compile(r'ignore(?:all)?(?:previous|prior|above)(?:instructions|prompts|rules)', re.IGNORECASE),
            re.compile(r'disregard(?:all)?(?:previous|prior|above)(?:instructions|prompts|rules)', re.IGNORECASE),
            re.compile(r'forget(?:all)?(?:previous|prior)(?:instructions|prompts|rules)', re.IGNORECASE),
            re.compile(r'(?:danmode|jailbreak|unfilteredmode|developermode|godmode)', re.IGNORECASE),
            re.compile(r'whatisyoursystemprompt', re.IGNORECASE),
            re.compile(r'repeat(?:all)?(?:the)?(?:initial|original|system)(?:instructions|prompts)', re.IGNORECASE),
            re.compile(r'outputthetextabove', re.IGNORECASE),
            re.compile(r'revealyour(?:system|hidden)?(?:prompt|instructions)', re.IGNORECASE),
            re.compile(r'actas(?:an?)?(?:evil|unrestricted|unconstrained|nefarious|unethical|jailbroken|bad)+(?:ai|agent|assistant|bot|llm|model)', re.IGNORECASE)
        ]

    def _normalize_text(self, text: str) -> str:
        normalized = unicodedata.normalize('NFKD', text)
        normalized = re.sub(r'[\u200b-\u200f\ufeff\u00ad\u2060]', '', normalized)
        # Compact single-space letter sequences
        compacted = re.sub(r'(?<=\b[a-zA-Z0-9]) (?=[a-zA-Z0-9]\b)', '', normalized)
        compacted = re.sub(r'(?<=\b[a-zA-Z0-9]) (?=[a-zA-Z0-9]\b)', '', compacted)

        leet_chars = [self.leet_map.get(ch, ch) for ch in compacted.lower()]
        return "".join(leet_chars)

    def _get_spaceless_text(self, text: str) -> str:
        normalized = unicodedata.normalize('NFKD', text)
        # First translate leetspeak on lowercased characters
        leet_chars = [self.leet_map.get(ch, ch) for ch in normalized.lower()]
        joined = "".join(leet_chars)
        # Strip all punctuation, spaces, zero-width chars, and symbols
        return re.sub(r'[^a-z0-9]', '', joined)

    def _inspect_base64_payloads(self, text: str) -> List[Dict[str, Any]]:
        findings = []
        b64_candidates = re.findall(r'[A-Za-z0-9+/=]{16,}', text)
        for cand in b64_candidates:
            try:
                decoded = base64.b64decode(cand, validate=False).decode("utf-8", errors="ignore")
                if len(decoded) > 5:
                    norm_decoded = self._normalize_text(decoded)
                    spaceless_decoded = self._get_spaceless_text(decoded)
                    for pat in self.injection_patterns:
                        m = pat.search(norm_decoded)
                        if m:
                            findings.append({
                                "rule": "OBFUSCATED_BASE64_INJECTION",
                                "matched": m.group(0),
                                "payload_snippet": decoded[:50],
                                "severity": "CRITICAL"
                            })
                            break
                    if not findings:
                        for pat in self.spaceless_patterns:
                            m = pat.search(spaceless_decoded)
                            if m:
                                findings.append({
                                    "rule": "OBFUSCATED_BASE64_INJECTION",
                                    "matched": m.group(0),
                                    "payload_snippet": decoded[:50],
                                    "severity": "CRITICAL"
                                })
                                break
            except Exception:
                continue
        return findings

    def inspect_prompt(self, text: str) -> Dict[str, Any]:
        start = time.perf_counter()
        violations = []

        # 0. Size guard to prevent ReDoS
        if len(text) > self.max_input_len:
            violations.append({
                "rule": "PAYLOAD_TOO_LARGE",
                "matched": f"Length {len(text)} exceeds limit {self.max_input_len}",
                "severity": "HIGH"
            })
            text = text[:self.max_input_len]

        # Check raw text and URL-decoded text
        unquoted = urllib.parse.unquote(text)
        texts_to_check = [text]
        if unquoted != text:
            texts_to_check.append(unquoted)

        for current_text in texts_to_check:
            # 1. Inspect text against standard patterns
            for pat in self.injection_patterns:
                m = pat.search(current_text)
                if m and not any(v.get("matched") == m.group(0) for v in violations):
                    violations.append({
                        "rule": "PROMPT_INJECTION_DETECTED",
                        "matched": m.group(0),
                        "severity": "CRITICAL"
                    })

            # 2. Inspect normalized text (catches spacing, leetspeak, zero-width)
            normalized = self._normalize_text(current_text)
            for pat in self.injection_patterns:
                m = pat.search(normalized)
                if m and not any(v.get("matched") == m.group(0) for v in violations):
                    violations.append({
                        "rule": "OBFUSCATED_PROMPT_INJECTION",
                        "matched": m.group(0),
                        "severity": "CRITICAL"
                    })

            # 3. Inspect spaceless invariant text (catches punctuation, concatenation, and symbol interleaving)
            spaceless = self._get_spaceless_text(current_text)
            for pat in self.spaceless_patterns:
                m = pat.search(spaceless)
                if m and not any(v.get("matched") == m.group(0) for v in violations):
                    violations.append({
                        "rule": "SPACELESS_OBFUSCATED_INJECTION",
                        "matched": m.group(0),
                        "severity": "CRITICAL"
                    })

            # 4. Inspect embedded Base64 payloads
            b64_violations = self._inspect_base64_payloads(current_text)
            for bv in b64_violations:
                if not any(v.get("matched") == bv["matched"] for v in violations):
                    violations.append(bv)

        duration_ms = (time.perf_counter() - start) * 1000.0
        allowed = (len(violations) == 0)

        return {
            "allowed": allowed,
            "latency_ms": round(duration_ms, 3),
            "threat_count": len(violations),
            "violations": violations,
            "action": "ALLOW" if allowed else "BLOCK"
        }
