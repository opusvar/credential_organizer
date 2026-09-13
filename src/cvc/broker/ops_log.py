"""Ops log — operational JSONL distinct from the security audit chain.

Not integrity-chained; safe to rotate and truncate. Records operational
events (request counts, vault latency, ACL reloads) without secret material.
Used for dashboards and alerting, not security evidence.
"""
from __future__ import annotations

import fcntl
import json
import os
from datetime import datetime, timezone
from pathlib import Path


class OpsLog:
    def __init__(self, path: str):
        self.path = Path(path)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass  # best-effort; write attempts will also fail and be swallowed

    def record(self, event: str, **fields) -> None:
        """Append one ops event line. Never raises — ops log failure is non-fatal."""
        try:
            entry = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": event,
                **fields,
            }
            with self.path.open("a", encoding="utf-8") as fh:
                fcntl.flock(fh, fcntl.LOCK_EX)
                try:
                    fh.write(json.dumps(entry) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                finally:
                    fcntl.flock(fh, fcntl.LOCK_UN)
        except Exception:
            pass  # ops log is best-effort; never propagate to the request path
