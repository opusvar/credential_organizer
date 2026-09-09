"""Unit tests for the reminder policy (stale / reuse / weak)."""
from datetime import datetime, timedelta, timezone

from cvc.reminders.policy import CredRecord, evaluate


def _old(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


def test_flags_stale_reused_and_weak():
    records = [
        CredRecord("1", "Bank", "u1", "correct-horse-battery-staple", last_rotated=_old(400)),
        CredRecord("2", "MailA", "u2", "SharedP@ssword123", last_rotated=_old(1)),
        CredRecord("3", "MailB", "u3", "SharedP@ssword123", last_rotated=_old(1)),
        CredRecord("4", "Weak", "u4", "abcdef", last_rotated=_old(1)),
    ]
    findings = {f.item_id: f.reasons for f in evaluate(records, max_age_days=180)}

    assert any("stale" in r for r in findings["1"])          # 400d > 180d
    assert any("reused" in r for r in findings["2"])         # shared password
    assert any("reused" in r for r in findings["3"])
    assert any("weak" in r for r in findings["4"])           # short + single class


def test_strong_unique_recent_password_not_flagged():
    records = [
        CredRecord("ok", "Fine", "u", "Zx9$kQ2!vLmP7wRt", last_rotated=_old(10)),
    ]
    assert evaluate(records, max_age_days=180) == []


def test_missing_rotation_date_is_not_flagged_stale():
    records = [CredRecord("n", "NoDate", "u", "Zx9$kQ2!vLmP7wRt", last_rotated=None)]
    assert evaluate(records, max_age_days=180) == []
