"""Fixture-based test for the Chrome CSV importer (Phase 1 vertical slice)."""
from cvc.importers.chrome import ChromeImporter
from cvc.importers.normalize import dedup


def test_chrome_parses_rows(chrome_csv):
    items = ChromeImporter().parse(chrome_csv)
    assert len(items) == 4
    assert all(it.source == "chrome" for it in items)
    first = items[0]
    assert first.username == "user@example.test"
    assert first.uri == "https://example.test/login"


def test_chrome_then_dedup(chrome_csv):
    items = ChromeImporter().parse(chrome_csv)
    res = dedup(items)
    # 4 rows collapse to 2 unique (two host+username pairs), 2 duplicates.
    assert len(res.unique) == 2
    assert len(res.duplicates) == 2
