"""Process-wide notifier hook used by ApprovalService.submit and audit publishing.

Disabled (no-op) unless CVC_NTFY_SERVERS is set or a notifier is installed with
`set_notifier`. Every call is wrapped: a notification problem can never raise into the
caller, so approval/audit outcomes are unaffected.
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger("cvc.notify")
_UNSET = object()
_notifier: object = _UNSET


def _site_has_ntfy() -> bool:
    try:
        from cvc import site as _site
        return bool(_site.load().ntfy_servers)
    except Exception:                                   # noqa: BLE001
        return False


def set_notifier(n) -> None:
    """Install a notifier (or None to disable). Tests and long-running services use this."""
    global _notifier
    _notifier = n


def get_notifier():
    global _notifier
    if _notifier is _UNSET:
        _notifier = None
        if os.environ.get("CVC_NTFY_SERVERS") or _site_has_ntfy():
            try:
                from .__main__ import build_notifier
                _notifier = build_notifier()
            except Exception:                           # noqa: BLE001
                log.warning("notify: configuration failed; notifications disabled")
    return _notifier


def emit(event: str, *args) -> None:
    """event: 'approval_submitted' (req) | 'audit_published' (findings, summary)."""
    try:
        n = get_notifier()
        if n is None:
            return
        if event == "approval_submitted":
            n.on_submitted(*args)
        elif event == "audit_published":
            n.on_audit(*args)
    except Exception:                                   # noqa: BLE001
        log.warning("notify: hook %s failed", event)
