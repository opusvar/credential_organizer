"""Notification policy: D18 routing, priority, quiet hours, escalation, digest.

Every public entry point swallows its own errors: a notification failure never changes an
approval outcome. Logs carry counts only (no topics, tokens, intents or people).
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import asdict
from datetime import datetime, time
from pathlib import Path

from cvc.approvals.model import PERSON_RANK, now_utc, parse_ts

from .config import NotifyConfig
from .message import Message, approval_message, audit_message, digest_message
from .ntfy import NtfySender

log = logging.getLogger("cvc.notify")


def _local(now: datetime, tz: str | None) -> datetime:
    if tz:
        from zoneinfo import ZoneInfo
        return now.astimezone(ZoneInfo(tz))
    return now.astimezone()


def in_quiet(t: time, quiet: tuple[time, time] | None) -> bool:
    if not quiet:
        return False
    a, b = quiet
    return (a <= t < b) if a <= b else (t >= a or t < b)


class Notifier:
    def __init__(self, config: NotifyConfig, sender: NtfySender | None = None,
                 clock: Callable[[], datetime] = now_utc):
        self.cfg = config
        self.sender = sender or NtfySender(config.backends, attempts=config.attempts)
        self.clock = clock
        self.state: dict = {"deferred": [], "escalated": [], "notified": [],
                            "last_digest": None, "audit_open": {}}
        self._load()

    # -- state ------------------------------------------------------------------------
    def _path(self) -> Path | None:
        return Path(self.cfg.state_path).expanduser() if self.cfg.state_path else None

    def _load(self) -> None:
        p = self._path()
        try:
            if p and p.exists():
                self.state.update(json.loads(p.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass

    def _save(self) -> None:
        p = self._path()
        if not p:
            return
        try:
            p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".notify.")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.state, fh)
            os.chmod(tmp, 0o600)
            os.replace(tmp, p)
        except OSError:
            log.warning("notify: state not saved")

    # -- routing (D18) ----------------------------------------------------------------
    def _active(self) -> dict[str, dict]:
        return {pid: p for pid, p in self.cfg.people.items()
                if isinstance(p, dict) and p.get("status", "active") == "active"
                and p.get("tier") in PERSON_RANK}

    def owners(self) -> list[str]:
        own = sorted(pid for pid, p in self._active().items() if p.get("tier") == "owner")
        return own or list(self.cfg.owner_ids)

    def approvers(self, req) -> list[str]:
        """Ordered recipients: assistant requests -> on_behalf_of person, then owners;
        otherwise eligible non-owners (tier >= approver_min_tier, highest first), then
        owners (owner fallback). Only people with a topic are returned."""
        people = self._active()
        obo = req.requester.on_behalf_of
        if req.requester.tier == "assistant" and obo:
            order = [obo]
        else:
            need = PERSON_RANK.get(req.approver_min_tier, 0)
            order = sorted((pid for pid, p in people.items() if p["tier"] != "owner"
                            and PERSON_RANK[p["tier"]] >= need),
                           key=lambda pid: (-PERSON_RANK[people[pid]["tier"]], pid))
        order += [o for o in self.owners() if o not in order]
        return [pid for pid in order if self.cfg.topic_for(pid)]

    # -- sending ----------------------------------------------------------------------
    def _quiet_now(self, now: datetime) -> bool:
        return in_quiet(_local(now, self.cfg.tz).time().replace(tzinfo=None), self.cfg.quiet)

    def _push(self, person: str, msg: Message, now: datetime, defer_key: dict) -> None:
        topic = self.cfg.topic_for(person)
        if not topic:
            return
        if msg.priority < 5 and self._quiet_now(now):
            self.state["deferred"].append({**defer_key, "person": person,
                                           "msg": asdict(msg)})
            return
        self.sender.send(topic, msg)

    def _approval_push(self, req, person: str, now: datetime, escalated: bool) -> None:
        msg = approval_message(req, now, self.cfg.card_url(req.id), escalated=escalated)
        if msg is not None:
            self._push(person, msg, now, {"kind": "approval", "id": req.id,
                                          "escalated": escalated})

    def on_submitted(self, req) -> None:
        try:
            now = self.clock()
            if req.status != "pending" or req.id in self.state["notified"]:
                return
            self.state["notified"].append(req.id)
            first = self.approvers(req)[:1]
            for person in first:
                self._approval_push(req, person, now, escalated=False)
            self._save()
        except Exception:                                   # noqa: BLE001
            log.warning("notify: submit notification failed")
        self._log()

    def on_audit(self, findings: dict[str, dict], summary: dict) -> None:
        """Push counts of NEW open warn/error findings to owners; remember open counts
        for the digest."""
        try:
            now = self.clock()
            new: dict[str, int] = {}
            for f in findings.values():
                if f.get("status") == "open" and f.get("first_seen") \
                        and f.get("first_seen") == f.get("last_seen"):
                    new[f.get("severity", "")] = new.get(f.get("severity", ""), 0) + 1
            self.state["audit_open"] = {k: int(v) for k, v in
                                        (summary.get("open") or {}).items()}
            msg = audit_message(new, self.cfg.dashboard_url)
            if msg is not None:
                for o in self.owners():
                    self._push(o, msg, now, {"kind": "audit"})
            self._save()
        except Exception:                                   # noqa: BLE001
            log.warning("notify: audit notification failed")
        self._log()

    def tick(self, approvals: Iterable, now: datetime | None = None) -> None:
        """Run periodically (e.g. every minute): flush deferred pushes after quiet hours,
        escalate at 50% of the deadline, send the daily digest."""
        try:
            now = now or self.clock()
            reqs = list(approvals)
            by_id = {r.id: r for r in reqs}
            pending = [r for r in reqs if r.status == "pending"]
            for r in pending:                   # catch requests submitted without the hook
                if r.id not in self.state["notified"]:
                    self.on_submitted(r)
            if not self._quiet_now(now):
                self._flush(by_id, now)
            for r in pending:
                if r.id in self.state["escalated"]:
                    continue
                start, end = parse_ts(r.created_at), parse_ts(r.deadline)
                if now >= start + (end - start) / 2:
                    self.state["escalated"].append(r.id)
                    nxt = self.approvers(r)[1:2]
                    for person in nxt:
                        self._approval_push(r, person, now, escalated=True)
            self._digest(pending, now)
            live = set(by_id)
            for k in ("notified", "escalated"):
                self.state[k] = [i for i in self.state[k] if i in live]
            self._save()
        except Exception:                                   # noqa: BLE001
            log.warning("notify: tick failed")
        self._log()

    def _flush(self, by_id: dict, now: datetime) -> None:
        queue, self.state["deferred"] = self.state["deferred"], []
        for item in queue:
            topic = self.cfg.topic_for(item.get("person", ""))
            if not topic:
                continue
            if item.get("kind") == "approval":
                req = by_id.get(item.get("id"))
                if req is None or req.status != "pending":
                    continue                      # decided/expired meanwhile: drop
                msg = approval_message(req, now, self.cfg.card_url(req.id),
                                       escalated=bool(item.get("escalated")))
                if msg is None:
                    continue
            else:
                msg = Message(**item["msg"])
            self.sender.send(topic, msg)

    def _digest(self, pending: list, now: datetime) -> None:
        local = _local(now, self.cfg.tz)
        today = local.date().isoformat()
        if self.state.get("last_digest") == today or \
                local.time().replace(tzinfo=None) < self.cfg.digest_at:
            return
        self.state["last_digest"] = today
        a = self.state.get("audit_open") or {}
        msg = digest_message(len(pending), sum(1 for r in pending if r.urgency == "low"),
                             int(a.get("warn", 0)), int(a.get("error", 0)),
                             self.cfg.dashboard_url)
        for o in self.owners():
            topic = self.cfg.topic_for(o)
            if topic:
                self.sender.send(topic, msg)

    def _log(self) -> None:
        log.info("notify: sent=%d failed=%d deferred=%d", self.sender.sent,
                 self.sender.failed, len(self.state["deferred"]))

