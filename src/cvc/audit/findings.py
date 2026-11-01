"""Finding schema `cvc.audit.v1` and the persisted first_seen / resolve state."""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path

SCHEMA = "cvc.audit.v1"
SEVERITIES = ("info", "warn", "error")
DEFAULT_STATE = "~/.local/state/cvc/audit/findings.json"


def finding_id(check: str, subject: str) -> str:
    """Stable id: hash of check + subject (never of the wording, which may change)."""
    return hashlib.sha256(f"{check}\0{subject}".encode()).hexdigest()[:16]


@dataclass
class Finding:
    check: str
    subject: str            # what the finding is about (stable key, e.g. "people.alice")
    severity: str           # info | warn | error
    title: str
    detail: str = ""
    suggested_fix: str = ""
    first_seen: str = ""
    last_seen: str = ""
    status: str = "open"    # open | resolved

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity {self.severity!r}")

    @property
    def id(self) -> str:
        return finding_id(self.check, self.subject)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("subject")
        return {"schema": SCHEMA, "id": self.id, **d}


def merge(previous: dict[str, dict], current: list[Finding], now: str) -> dict[str, dict]:
    """Carry first_seen forward, stamp last_seen, mark absent open findings resolved."""
    out: dict[str, dict] = {}
    for f in current:
        prev = previous.get(f.id)
        f.first_seen = prev["first_seen"] if prev and prev.get("status") == "open" else now
        f.last_seen = now
        f.status = "open"
        out[f.id] = f.to_dict()
    for fid, prev in previous.items():
        if fid in out:
            continue
        if prev.get("status") == "open":
            out[fid] = {**prev, "status": "resolved", "last_seen": now}
        else:
            out[fid] = prev
    return out


def summary(findings: dict[str, dict], now: str) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings.values():
        if f.get("status") == "open":
            counts[f["severity"]] += 1
    return {"schema": SCHEMA, "open": counts, "open_total": sum(counts.values()),
            "last_run": now}


class StateFile:
    def __init__(self, path: str | os.PathLike | None = None):
        self.path = Path(path or os.environ.get("CVC_AUDIT_STATE") or DEFAULT_STATE).expanduser()

    def load(self) -> dict[str, dict]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return raw.get("findings", {}) if isinstance(raw, dict) else {}

    def save(self, findings: dict[str, dict], now: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"schema": SCHEMA, "updated": now, "findings": findings},
                                  indent=2, sort_keys=True), encoding="utf-8")
        tmp.chmod(0o600)
        tmp.replace(self.path)


# Defence in depth: refuse to publish anything that looks like a secret.
_SECRET_KEYS = re.compile(r"password|secret|token|session|apikey|private", re.IGNORECASE)
_SECRET_VALUES = re.compile(r"-----BEGIN|\b[0-9a-f]{40,}\b|eyJ[A-Za-z0-9_-]{10,}\.", re.IGNORECASE)


def assert_no_secrets(payload: dict) -> None:
    def walk(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                if _SECRET_KEYS.search(str(k)):
                    raise ValueError(f"secret-like key in payload: {path}.{k}")
                walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        elif isinstance(node, str) and _SECRET_VALUES.search(node):
            raise ValueError(f"secret-like value in payload at {path}")
    walk(payload, "$")
