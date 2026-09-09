"""Unit tests for the import normalize/dedup layer (pure, no I/O)."""
from cvc.importers.normalize import Item, _norm_host, dedup


def test_norm_host_strips_scheme_www_path_port():
    assert _norm_host("https://www.example.test/login?x=1") == "example.test"
    assert _norm_host("http://example.test:8080/") == "example.test"
    assert _norm_host("example.test") == "example.test"


def test_dedup_key_groups_by_host_and_username():
    a = Item(name="A", username="U@x.test", password="p", uri="https://www.x.test/login")
    b = Item(name="B", username="u@x.test", password="q", uri="http://x.test/")
    assert a.dedup_key == b.dedup_key  # same host+username, case-insensitive


def test_dedup_first_wins_and_is_order_preserving():
    items = [
        Item("first", "u@x.test", "p1", uri="https://x.test"),
        Item("dup", "u@x.test", "p2", uri="https://www.x.test/login"),
        Item("other", "a@y.test", "p3", uri="https://y.test"),
    ]
    res = dedup(items)
    assert [i.name for i in res.unique] == ["first", "other"]
    assert [i.name for i in res.duplicates] == ["dup"]


def test_dedup_falls_back_to_name_when_no_uri():
    items = [
        Item("SharedName", "u@x.test", "p1"),
        Item("SharedName", "u@x.test", "p2"),  # dup by name+username
    ]
    res = dedup(items)
    assert len(res.unique) == 1 and len(res.duplicates) == 1
