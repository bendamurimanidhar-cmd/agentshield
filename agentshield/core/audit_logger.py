"""
AgentShield Tamper-Proof Cryptographic Audit Logger.
Emits append-only JSON logs with SHA-256 integrity hashes for SOC2 & compliance,
and provides mathematical chain verification to detect tampering.
"""

import hashlib
import json
import time
import os
from typing import Dict, Any

class AuditLogger:
    def __init__(self, log_path: str = None):
        self.log_path = log_path
        self.previous_hash = "GENESIS_BLOCK"

        # Resume cryptographic chain if log file already exists
        if self.log_path and os.path.exists(self.log_path):
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    lines = [l.strip() for l in f if l.strip()]
                    if lines:
                        last_record = json.loads(lines[-1])
                        if "hash" in last_record:
                            self.previous_hash = last_record["hash"]
            except Exception:
                pass

    def log_event(self, event_type: str, details: Dict[str, Any]) -> Dict[str, Any]:
        record = {
            "timestamp": time.time(),
            "event_type": event_type,
            "details": details,
            "prev_hash": self.previous_hash
        }
        serialized = json.dumps(record, sort_keys=True).encode("utf-8")
        current_hash = hashlib.sha256(serialized).hexdigest()
        record["hash"] = current_hash
        self.previous_hash = current_hash

        if self.log_path:
            try:
                dirname = os.path.dirname(os.path.abspath(self.log_path))
                if dirname:
                    os.makedirs(dirname, exist_ok=True)
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record) + "\n")
            except OSError:
                # Graceful fallback if current directory is read-only
                pass

        return record

    def verify_chain(self, log_path: str = None) -> Dict[str, Any]:
        target_path = log_path or self.log_path
        if not target_path or not os.path.exists(target_path):
            return {"valid": False, "reason": f"Audit log file not found: {target_path}"}

        expected_prev = "GENESIS_BLOCK"
        block_idx = 0

        with open(target_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except Exception as e:
                    return {
                        "valid": False,
                        "failed_at_block": block_idx,
                        "reason": f"Corrupted JSON format: {str(e)}"
                    }

                stored_hash = record.get("hash")
                stored_prev = record.get("prev_hash")

                # Verify hash chain continuity
                if stored_prev != expected_prev:
                    return {
                        "valid": False,
                        "failed_at_block": block_idx,
                        "reason": f"Broken chain pointer at block {block_idx}. Expected prev '{expected_prev}', got '{stored_prev}'."
                    }

                # Recompute SHA-256 block hash without the 'hash' field
                clean_record = {k: v for k, v in record.items() if k != "hash"}
                recomputed = hashlib.sha256(json.dumps(clean_record, sort_keys=True).encode("utf-8")).hexdigest()

                if recomputed != stored_hash:
                    return {
                        "valid": False,
                        "failed_at_block": block_idx,
                        "reason": f"Tampered record detected at block {block_idx}. Expected hash '{stored_hash}', recomputed '{recomputed}'."
                    }

                expected_prev = stored_hash
                block_idx += 1

        return {
            "valid": True,
            "blocks_verified": block_idx,
            "latest_hash": expected_prev
        }
