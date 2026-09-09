"""Append-only access audit log (JSONL). One line per credential request, written BEFORE the
secret is returned so an access can never be served without a record.

Never records the secret value — only who/what/why/when/outcome. For tamper-evidence each line
carries a hash chained from the previous line's hash (a broken chain reveals deletion/edits).
Ship the log off-box for durability (out of scope here).
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


@dataclass
class AuditEvent:
    agent: str
    credential: str
    purpose: str
    outcome: str          # "allow" | "deny:<reason>"
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AuditLog:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        last = json.loads(line).get("hash", last)
                    except json.JSONDecodeError:
                        # A corrupt line breaks the chain intentionally; keep going.
                        continue
        return last

    def record(self, ev: AuditEvent) -> str:
        """Append one chained, fsync'd record. Returns the new chain hash."""
        with self.path.open("a", encoding="utf-8") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                prev = self._last_hash()
                body = {"ts": ev.ts, "agent": ev.agent, "credential": ev.credential,
                        "purpose": ev.purpose, "outcome": ev.outcome, "prev": prev}
                digest = hashlib.sha256((prev + json.dumps(body, sort_keys=True)).encode()).hexdigest()
                body["hash"] = digest
                fh.write(json.dumps(body) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)
        return digest

    def verify(self) -> bool:
        """Recompute the chain; return False if any link is broken (tamper-evident).

        Also returns False — never raises — if any line is malformed, truncated,
        or not a dict. emptyDir volumes silently destroy the log; verify() returning
        True on an absent file is intentional (no log = no tampering to detect),
        but the log must be on durable storage (PVC, not emptyDir).
        """
        prev = GENESIS
        if not self.path.exists():
            return True
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    if not isinstance(rec, dict):
                        return False
                    expect = rec.get("hash")
                    check = {k: rec[k] for k in ("ts", "agent", "credential", "purpose", "outcome", "prev")}
                    digest = hashlib.sha256((prev + json.dumps(check, sort_keys=True)).encode()).hexdigest()
                    if rec.get("prev") != prev or digest != expect:
                        return False
                    prev = expect
                except (json.JSONDecodeError, KeyError, TypeError, AttributeError):
                    return False
        return True
