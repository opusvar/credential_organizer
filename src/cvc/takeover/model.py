"""Owner takeover records, timeline state machine and the persistent store (D15).

Timeline, counted from initiation:
  day 0-15   ``requested``    target sees a banner; nothing is readable yet
  day 15-90  ``viewer``       initiator may use read-only Vaultwarden View access (reversible)
  day 90+    ``completable``  ``cvc takeover complete`` may run
For path ``recovery-password`` (no target YubiKey; target's sealed recovery password instead)
and path ``estate-kit`` (the household's printed estate recovery code) ``completable`` starts at
day 180 instead of 90.
Terminal states: ``cancelled`` (by the target, with their own YubiKey), ``vetoed`` (by another
owner; Vaultwarden View access persists until the target rejects the grants) and ``completed``.

The store keeps the current records in ``takeovers.json`` and an append-only, hash-chained
``history.jsonl`` (same chaining scheme as the broker audit log). No secret is ever stored.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import secrets
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field, fields
from datetime import UTC, datetime
from pathlib import Path

VIEW_WAIT_DAYS = 15
TAKEOVER_WAIT_DAYS = 90             # path "key": target's (primary or backup) YubiKey presented
RECOVERY_TAKEOVER_WAIT_DAYS = 180   # path "recovery-password": no target key, sealed password
NOTIFY_DAYS = (0, 7, 14, 85)
RECOVERY_NOTIFY_DAYS = (0, 7, 14, 85, 170)
PATHS = ("key", "recovery-password", "estate-kit")
LONG_PATHS = frozenset({"recovery-password", "estate-kit"})


def takeover_wait_days(path: str) -> int:
    return RECOVERY_TAKEOVER_WAIT_DAYS if path in LONG_PATHS else TAKEOVER_WAIT_DAYS


def notify_days(path: str) -> tuple[int, ...]:
    return RECOVERY_NOTIFY_DAYS if path in LONG_PATHS else NOTIFY_DAYS

GENESIS = "0" * 64
DEFAULT_STATE_DIR = "~/.local/state/cvc/takeover"

Clock = Callable[[], datetime]


def utcnow() -> datetime:
    return datetime.now(UTC)


class TakeoverError(Exception):
    """A takeover step was refused. The message says why."""


def new_id(now: datetime) -> str:
    return f"to-{now:%Y%m%d}-{secrets.token_hex(3)}"


@dataclass
class TakeoverRecord:
    id: str
    initiator: str
    target: str
    initiated_at: str                    # ISO-8601 UTC
    initiator_cert_fingerprint: str
    initiator_key: str
    target_key: str | None               # None on the recovery-password / estate-kit paths
    elevation_method: str                # "passkey" | "vaultwarden-password" (method only)
    vw_view_grant: str
    vw_takeover_grant: str
    path: str = "key"                    # PATHS
    status: str = "pending"              # pending | cancelled | vetoed | completed
    notified: list[int] = field(default_factory=list)
    cancelled_at: str | None = None
    target_key_role: str | None = None   # "primary" | "backup" (hwkey role or heuristic)
    vetoed_by: str | None = None
    vetoed_at: str | None = None
    completed_at: str | None = None

    @property
    def started(self) -> datetime:
        return datetime.fromisoformat(self.initiated_at)

    def day(self, now: datetime) -> int:
        """Whole days elapsed since initiation."""
        return (now - self.started).days

    @property
    def wait_days(self) -> int:
        return takeover_wait_days(self.path)

    def phase(self, now: datetime) -> str:
        if self.status != "pending":
            return self.status
        d = self.day(now)
        if d < VIEW_WAIT_DAYS:
            return "requested"
        if d < self.wait_days:
            return "viewer"
        return "completable"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> TakeoverRecord:
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in raw.items() if k in names})


class TakeoverStore:
    """JSON record file + hash-chained append-only history, under one directory.
    Subclasses (e.g. the delegation store) override the class attributes below."""
    record_cls: type = TakeoverRecord
    key = "takeovers"           # top-level key in the records file, also its basename
    ref = "takeover"            # history field naming the record id
    error: type[Exception] = TakeoverError

    def __init__(self, state_dir: str | os.PathLike):
        self.dir = Path(state_dir).expanduser()
        self.records_path = self.dir / f"{self.key}.json"
        self.history_path = self.dir / "history.jsonl"

    @contextlib.contextmanager
    def _lock(self) -> Iterator[None]:
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (self.dir / ".lock").open("a") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)

    def _read(self) -> dict:
        if not self.records_path.exists():
            return {}
        raw = json.loads(self.records_path.read_text(encoding="utf-8"))
        return {k: self.record_cls.from_dict(v) for k, v in raw.get(self.key, {}).items()}

    def all(self) -> dict[str, TakeoverRecord]:
        return self._read()

    def get(self, tid: str) -> TakeoverRecord:
        rec = self._read().get(tid)
        if rec is None:
            raise self.error(f"unknown {self.ref} {tid!r}")
        return rec

    def open_for(self, person: str) -> list[TakeoverRecord]:
        """Pending takeovers where ``person`` is initiator or target."""
        return [r for r in self._read().values()
                if r.status == "pending" and person in self._parties(r)]

    def _parties(self, r) -> tuple[str, ...]:
        return (r.initiator, r.target)

    def _last_hash(self) -> str:
        last = GENESIS
        if self.history_path.exists():
            for line in self.history_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    last = json.loads(line).get("hash", last)
        return last

    def save(self, rec, event: str, actor: str, now: datetime,
             detail: dict | None = None) -> str:
        """Write the record and append one chained history line. Returns the chain hash."""
        with self._lock():
            recs = self._read()
            recs[rec.id] = rec
            tmp = self.records_path.with_suffix(".tmp")
            tmp.write_text(json.dumps({self.key: {k: v.to_dict() for k, v in recs.items()}},
                                      indent=2, sort_keys=True), encoding="utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.records_path)
            body = {"ts": now.isoformat(), self.ref: rec.id, "event": event, "actor": actor,
                    "detail": detail or {}, "prev": self._last_hash()}
            body["hash"] = _chain(body)
            with self.history_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(body, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            return body["hash"]

    def history(self, tid: str | None = None) -> list[dict]:
        if not self.history_path.exists():
            return []
        rows = [json.loads(x) for x in self.history_path.read_text(encoding="utf-8").splitlines()
                if x.strip()]
        return [r for r in rows if tid is None or r.get(self.ref) == tid]

    def verify_history(self) -> bool:
        prev = GENESIS
        for row in self.history():
            body = {k: v for k, v in row.items() if k != "hash"}
            if row.get("prev") != prev or _chain(body) != row.get("hash"):
                return False
            prev = row["hash"]
        return True


def _chain(body: dict) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
