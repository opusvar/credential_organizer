"""Additional policy tests — reuse-only and edge cases not in test_policy.py."""
from cvc.reminders.policy import CredRecord, evaluate


def _rec(item_id, name, password, age_days=None):
    from datetime import datetime, timedelta, timezone
    last = None
    if age_days is not None:
        last = datetime.now(timezone.utc) - timedelta(days=age_days)
    return CredRecord(item_id=item_id, name=name, username="u", password=password,
                      last_rotated=last)


def test_reuse_only_flags_both_items():
    records = [
        _rec("1", "Site A", "SharedPassword1!", age_days=10),
        _rec("2", "Site B", "SharedPassword1!", age_days=10),
    ]
    findings = evaluate(records, max_age_days=180)
    assert len(findings) == 2
    assert all(any("reused" in r for r in f.reasons) for f in findings)


def test_three_way_reuse_flags_all():
    records = [_rec(str(i), f"Site {i}", "SamePass99!", age_days=5) for i in range(3)]
    findings = evaluate(records, max_age_days=180)
    assert len(findings) == 3


def test_unique_strong_recent_is_clean():
    records = [
        _rec("1", "A", "UniquePw$123", age_days=10),
        _rec("2", "B", "DifferentPw$456", age_days=10),
    ]
    assert evaluate(records, max_age_days=180) == []


def test_passwordless_records_are_not_flagged():
    """URI-only / passkey-only logins have no password to rotate, reuse, or judge weak.

    Before this guard, two such items counted "" as a shared password and both were
    reported as reused *and* weak — pure noise in the Home Assistant sensor.
    """
    records = [_rec("1", "Bookmark A", "", age_days=900),
               _rec("2", "Bookmark B", "", age_days=900)]
    assert evaluate(records, max_age_days=180) == []


def test_passwordless_record_does_not_mask_real_findings():
    records = [
        _rec("1", "Bookmark", "", age_days=900),
        _rec("2", "Weak One", "abcdef", age_days=1),
    ]
    findings = evaluate(records, max_age_days=180)
    assert [f.item_id for f in findings] == ["2"]


def test_no_rotation_date_not_flagged_stale():
    rec = CredRecord(item_id="x", name="X", username="u", password="Str0ng!Unique", last_rotated=None)
    findings = evaluate([rec], max_age_days=180)
    assert not any("stale" in r for f in findings for r in f.reasons)
