"""ETag visibility for approvals: per-approval version history, rejection log, diagnostics.

Read-only with respect to approvals: nothing here changes an approval. `attach(svc)` wraps
an `ApprovalService` instance (its publisher and its legacy `record_external` path) so every
version the service publishes is appended to an append-only history:

  {version, etag, at, event, actor, status, mqtt_published_at, mqtt_cleared_at}

event is one of created | decided | cancelled | expired | legacy-approve | republished.
actor is the deciding person/agent, or "system" (expiry, sweeps).

The history lives in a sidecar of the approvals state file (`<state>.inspect.json`, mode
0600) so the broker and the owner CLI share it without touching the approvals record schema;
without a state path it is kept in memory. It also holds a bounded ring buffer of 412/428
If-Match rejections and per-approval nonce *counts and timestamps* — nonce values are never
stored or returned.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import logging
import os
import tempfile
import threading
from pathlib import Path
from typing import Any

from .model import iso
from .publisher import TOPIC_PREFIX, request_topic

EVENTS = ("created", "decided", "cancelled", "expired", "legacy-approve", "republished")
REJECTIONS_MAX = 200
SYSTEM = "system"
_log = logging.getLogger(__name__)
_EMPTY: dict[str, Any] = {"history": {}, "rejections": [], "nonces": {}}


def etag_for(approval_id: str, version: int) -> str:
    return f'"{approval_id}.v{version}"'


def parse_etag(tag: str) -> tuple[str, int] | None:
    t = (tag or "").strip().removeprefix("W/").strip('"')
    ident, _, ver = t.rpartition(".v")
    if not ident or not ver.isdigit():
        return None
    return ident, int(ver)


class Inspector:
    """History/rejection store. Every mutation is load-modify-save under a file lock."""

    def __init__(self, svc, path: Path | None):
        self.svc, self.path = svc, path
        self._mem: dict[str, Any] = json.loads(json.dumps(_EMPTY))
        self._lock = threading.RLock()
        self._local = threading.local()

    # -- storage ----------------------------------------------------------------------
    @contextlib.contextmanager
    def _txn(self, write: bool = True):
        with self._lock:
            if self.path is None:
                yield self._mem
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            lock_path = self.path.with_name(self.path.name + ".lock")
            with open(lock_path, "a") as lf:
                fcntl.flock(lf, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
                data = self._read()
                yield data
                if write:
                    fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".inspect.")
                    with os.fdopen(fd, "w", encoding="utf-8") as fh:
                        json.dump(data, fh, indent=1)
                    os.chmod(tmp, 0o600)
                    os.replace(tmp, self.path)

    def _read(self) -> dict[str, Any]:
        data = json.loads(json.dumps(_EMPTY))
        if self.path and self.path.exists():
            raw = json.loads(self.path.read_text(encoding="utf-8") or "{}")
            for k in data:
                if isinstance(raw.get(k), type(data[k])):
                    data[k] = raw[k]
        return data

    def snapshot(self) -> dict[str, Any]:
        with self._txn(write=False) as d:
            return json.loads(json.dumps(d))

    def _now(self) -> str:
        return iso(self.svc.clock())

    # -- recording (called from hooks) ------------------------------------------------
    def on_publish(self, topic: str, payload: str) -> None:
        prefix = TOPIC_PREFIX + "/"
        if not topic.startswith(prefix) or "/" in topic[len(prefix):]:
            return
        aid = topic[len(prefix):]
        if aid == "summary":
            return
        now = self._now()
        with self._txn() as d:
            hist = d["history"].setdefault(aid, [])
            if not payload:
                if hist:
                    hist[-1]["mqtt_cleared_at"] = now
                return
            try:
                rec = json.loads(payload)
            except ValueError:
                return
            version, status = int(rec.get("version", 1)), rec.get("status")
            last = hist[-1] if hist else None
            if last and last["version"] == version and last["status"] == status:
                event, actor = "republished", SYSTEM
            elif status == "pending":
                event, actor = ("created" if not hist else "republished",
                                rec.get("requester", {}).get("agent") or SYSTEM)
            elif status == "expired":
                event, actor = "expired", SYSTEM
            elif status == "cancelled":
                event, actor = "cancelled", rec.get("decided_by") or SYSTEM
            elif getattr(self._local, "legacy", False):
                event, actor = "legacy-approve", rec.get("decided_by") or SYSTEM
            else:
                event, actor = "decided", rec.get("decided_by") or SYSTEM
            hist.append({"version": version, "etag": etag_for(aid, version), "at": now,
                         "event": event, "actor": actor, "status": status,
                         "mqtt_published_at": now, "mqtt_cleared_at": None})

    def record_rejection(self, approval_id: str, code: int, presented: str | None,
                         person: str | None, reason: str = "") -> None:
        cur = self.svc.get(approval_id) if approval_id else None
        entry = {"id": approval_id, "code": int(code), "presented_etag": presented or None,
                 "current_etag": cur.etag if cur else None, "person": person,
                 "reason": reason[:200], "at": self._now()}
        with self._txn() as d:
            d["rejections"].append(entry)
            del d["rejections"][:-REJECTIONS_MAX]

    def record_nonce(self, approval_id: str | None, outcome: str) -> None:
        """outcome: issued | consumed | rejected | expired. Counts + timestamps only."""
        key = approval_id or "_global"
        now = self._now()
        with self._txn() as d:
            n = d["nonces"].setdefault(key, {})
            n[f"{outcome}_count"] = n.get(f"{outcome}_count", 0) + 1
            n[f"last_{outcome}_at"] = now

    # -- queries (read-only) ----------------------------------------------------------
    def history(self, approval_id: str) -> list[dict[str, Any]]:
        return self.snapshot()["history"].get(approval_id, [])

    def etag_info(self, approval_id: str) -> dict[str, Any] | None:
        r = self.svc.get(approval_id)
        if r is None:
            return None
        snap = self.snapshot()
        hist = snap["history"].get(approval_id, [])
        return {"id": r.id, "etag": r.etag, "version": r.version, "status": r.status,
                "last_event": hist[-1] if hist else None,
                "nonces": snap["nonces"].get(approval_id, {})}

    def check_etag(self, approval_id: str, etag: str) -> dict[str, Any]:
        r = self.svc.get(approval_id)
        parsed = parse_etag(etag)
        out: dict[str, Any] = {"id": approval_id, "presented": etag,
                               "current_etag": r.etag if r else None}
        if r is None or parsed is None or parsed[0] != approval_id or parsed[1] > r.version:
            out["result"] = "unknown"
            return out
        if parsed[1] == r.version:
            out["result"] = "current"
            return out
        hist = self.history(approval_id)
        out["result"] = "stale"
        out["presented_version"] = parsed[1]
        out["was"] = next((h for h in hist if h["version"] == parsed[1]), None)
        out["changes_since"] = [h for h in hist if h["version"] > parsed[1]]
        return out

    def diag(self, mqtt_snapshot: dict[str, str] | None = None, recent: int = 20
             ) -> dict[str, Any]:
        items = self.svc.list(None)
        counts: dict[str, int] = {}
        for r in items:
            counts[r.status] = counts.get(r.status, 0) + 1
        snap = self.snapshot()
        out: dict[str, Any] = {"counts": counts, "total": len(items),
                               "recent_rejections": snap["rejections"][-recent:],
                               "nonces_global": snap["nonces"].get("_global", {})}
        if mqtt_snapshot is not None:
            out["mqtt_mismatches"] = mqtt_mismatches(
                items, set(getattr(self.svc, "_cleared", set())), mqtt_snapshot)
        return out


def mqtt_mismatches(items, cleared: set[str], retained: dict[str, str]) -> list[dict]:
    """Compare retained `cvc/approvals/<id>` payloads (topic -> payload) with state."""
    out: list[dict] = []
    known = {r.id: r for r in items}
    for r in items:
        payload = retained.get(request_topic(r.id), "")
        if r.id in cleared:
            if payload:
                out.append({"id": r.id, "kind": "should-be-cleared"})
            continue
        if not payload:
            out.append({"id": r.id, "kind": "missing-retained", "state_version": r.version})
            continue
        try:
            got = json.loads(payload)
        except ValueError:
            out.append({"id": r.id, "kind": "unparseable-retained"})
            continue
        if got.get("version") != r.version or got.get("status") != r.status:
            out.append({"id": r.id, "kind": "stale-retained",
                        "state": {"version": r.version, "status": r.status},
                        "retained": {"version": got.get("version"),
                                     "status": got.get("status")}})
    prefix = TOPIC_PREFIX + "/"
    for topic, payload in retained.items():
        aid = topic[len(prefix):] if topic.startswith(prefix) else None
        if aid and aid != "summary" and "/" not in aid and aid not in known and payload:
            out.append({"id": aid, "kind": "orphan-retained"})
    return out


class _RecordingPublisher:
    def __init__(self, inner, insp: Inspector):
        self.inner, self.insp = inner, insp

    def publish(self, topic: str, payload: str, retain: bool) -> None:
        self.inner.publish(topic, payload, retain)
        try:
            self.insp.on_publish(topic, payload)
        except Exception:  # noqa: BLE001 - visibility must never break approvals
            _log.warning("approvals_inspect_record_failed", exc_info=True)

    def __getattr__(self, name):
        return getattr(self.inner, name)


def attach(svc) -> Inspector:
    """Idempotently hook an ApprovalService instance; returns its Inspector."""
    insp = getattr(svc, "_inspector", None)
    if insp is not None:
        return insp
    path = None
    if getattr(svc, "state_path", None):
        sp = Path(svc.state_path)
        path = sp.with_name(sp.name + ".inspect.json")
    insp = Inspector(svc, path)
    svc.publisher = _RecordingPublisher(svc.publisher, insp)
    orig = svc.record_external

    def record_external(*a, **kw):
        insp._local.legacy = True
        try:
            return orig(*a, **kw)
        finally:
            insp._local.legacy = False

    svc.record_external = record_external
    svc._inspector = insp
    return insp
