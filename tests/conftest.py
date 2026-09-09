"""Shared test fixtures. All data here is SYNTHETIC — no real credentials."""
import pytest

# Obviously-fake Chrome password export (columns: name,url,username,password,note).
# Includes a duplicate (same host+username via www/non-www) to exercise dedup.
_CHROME_CSV = """\
name,url,username,password,note
Example,https://example.test/login,user@example.test,not-a-real-pw-1,
Example WWW,https://www.example.test/,user@example.test,not-a-real-pw-1,dup of above
Other,https://other.test,someone@other.test,not-a-real-pw-2,
NoScheme,other.test,someone@other.test,not-a-real-pw-2,dup by host+user
"""


@pytest.fixture
def chrome_csv(tmp_path):
    """Write a synthetic Chrome export and return its path."""
    p = tmp_path / "chrome_passwords.csv"
    p.write_text(_CHROME_CSV, encoding="utf-8")
    return str(p)
