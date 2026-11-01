"""`person add` / `agent add` helpers + CLI, the `name` field, apply_edit, tiergate host flags."""
from __future__ import annotations

import datetime as dt
import shutil
from pathlib import Path

import pytest
import yaml

from cvc.access import parse_registry
from cvc.access.cli import main
from cvc.access.edit import EditError, agent_add, apply_edit, person_add
from cvc.access.graph import build_graph
from cvc.takeover.flow import display_name

EXAMPLE = Path(__file__).resolve().parent.parent / "access" / "registry.example.yaml"
TODAY = dt.date(2026, 11, 1)


@pytest.fixture
def reg(tmp_path):
    p = tmp_path / "registry.yaml"
    shutil.copy(EXAMPLE, p)
    return p


def data(p):
    return yaml.safe_load(p.read_text())


# ── name field ──────────────────────────────────────────────────────────────

def test_person_name_parsed_and_consistent_with_takeover(reg):
    d = data(reg)
    d["people"]["sam"]["name"] = "Sam S"
    r = parse_registry(d)
    assert r.people["sam"].name == "Sam S" and r.people["sam"].display_name == "Sam S"
    assert r.people["nathan"].name is None and r.people["nathan"].display_name == "nathan"
    assert display_name(d, "sam") == r.people["sam"].display_name
    assert display_name(d, "nathan") == r.people["nathan"].display_name


def test_person_name_must_be_nonempty_string(reg):
    d = data(reg)
    d["people"]["sam"]["name"] = 5
    with pytest.raises(Exception, match="people.sam.name"):
        parse_registry(d)


def test_graph_shows_name(reg):
    d = data(reg)
    d["people"]["sam"]["name"] = "Sam S"
    out = build_graph(parse_registry(d), TODAY)
    assert "Sam S<br/>(sam)" in out
    assert '["nathan<br/>tier: owner"]' in out


# ── person_add ──────────────────────────────────────────────────────────────

def test_person_add_helper(reg):
    d = data(reg)
    out, msg = person_add(d, "alice", tier="medium", granted_by="nathan", name="Alice A",
                          email="a@x", today=TODAY)
    assert out is d and "added person alice (Alice A)" in msg
    p = parse_registry(d).people["alice"]
    assert (p.name, p.tier, p.tailnet, p.granted_by) == ("Alice A", "medium", "family", "nathan")
    assert p.history[0] == {"date": TODAY, "event": "added"}


def test_person_add_owner_defaults_owner_tailnet(reg):
    d = data(reg)
    person_add(d, "o2", tier="owner", granted_by="nathan", today=TODAY)
    assert d["people"]["o2"]["tailnet"] == "owner"


@pytest.mark.parametrize("kw,err", [
    ({"tier": "guest-short", "granted_by": "nathan"}, "use `guest add`"),
    ({"tier": "medium", "granted_by": "nathan", "name": " "}, "name must not be empty"),
    ({"tier": "medium", "granted_by": "nathan", "tailnet": "bogus"}, "tailnet"),
    ({"tier": "medium", "granted_by": "ghost"}, "unknown person"),
    ({"tier": "admin", "granted_by": "sam"}, "refused by tier rules"),
])
def test_person_add_refusals_leave_data_untouched(reg, kw, err):
    d = data(reg)
    before = yaml.safe_dump(d)
    with pytest.raises(EditError, match=err):
        person_add(d, "alice", today=TODAY, **kw)
    assert yaml.safe_dump(d) == before


def test_person_add_duplicate(reg):
    with pytest.raises(EditError, match="already exists"):
        person_add(data(reg), "sam", tier="medium", granted_by="nathan")


# ── agent_add ───────────────────────────────────────────────────────────────

def test_agent_add_helper(reg):
    d = data(reg)
    out, msg = agent_add(d, "bot", tier="high", sponsor="nathan", roles=["sensor-publish"])
    assert out is d and "added agent bot" in msg
    a = parse_registry(d).agents["bot"]
    assert (a.tier, a.sponsor, a.granted_by, a.roles) == ("high", "nathan", "nathan",
                                                          ("sensor-publish",))


@pytest.mark.parametrize("kw,err", [
    ({"tier": "nope", "sponsor": "nathan"}, "not an agent tier"),
    ({"tier": "low", "sponsor": "nathan", "roles": ["ghost"]}, "unknown role"),
    ({"tier": "low", "sponsor": "ghost"}, "unknown person"),
])
def test_agent_add_refusals(reg, kw, err):
    d = data(reg)
    before = yaml.safe_dump(d)
    with pytest.raises(EditError, match=err):
        agent_add(d, "bot", **kw)
    assert yaml.safe_dump(d) == before


def test_agent_add_duplicate_principal(reg):
    with pytest.raises(EditError, match="already exists"):
        agent_add(data(reg), "nathan-mac", tier="low", sponsor="nathan")


# ── CLI ─────────────────────────────────────────────────────────────────────

def test_cli_person_add(reg, capsys):
    rc = main(["person", "add", "alice", "--tier", "medium", "--name", "Alice A",
               "--registry", str(reg)])
    assert rc == 0, capsys.readouterr().err
    assert data(reg)["people"]["alice"]["name"] == "Alice A"
    assert "added person alice" in capsys.readouterr().out


def test_cli_person_add_dry_run(reg, capsys):
    before = reg.read_text()
    rc = main(["person", "add", "alice", "--tier", "medium", "--registry", str(reg),
               "--dry-run"])
    out = capsys.readouterr().out
    assert rc == 0 and reg.read_text() == before
    assert "+  alice:" in out and "dry run: registry not written" in out


def test_cli_person_add_refused(reg, capsys):
    before = reg.read_text()
    rc = main(["person", "add", "alice", "--tier", "admin", "--granted-by", "sam",
               "--registry", str(reg)])
    assert rc == 1 and "refused" in capsys.readouterr().err and reg.read_text() == before


def test_cli_agent_add(reg, capsys):
    rc = main(["agent", "add", "bot", "--tier", "high", "--sponsor", "nathan",
               "--roles", "sensor-publish", "--expires", "2027-01-01", "--registry", str(reg)])
    assert rc == 0, capsys.readouterr().err
    a = data(reg)["agents"]["bot"]
    assert a["roles"] == ["sensor-publish"] and a["expires"] == dt.date(2027, 1, 1)


def test_cli_agent_add_dry_run(reg, capsys):
    before = reg.read_text()
    rc = main(["agent", "add", "bot", "--tier", "high", "--sponsor", "nathan",
               "--registry", str(reg), "--dry-run"])
    assert rc == 0 and reg.read_text() == before
    assert "dry run" in capsys.readouterr().out


# ── apply_edit (argparse-free core) ─────────────────────────────────────────

def test_apply_edit_confirm_and_abort(reg):
    lines: list[str] = []
    before = reg.read_text()
    with pytest.raises(EditError, match="aborted"):
        apply_edit(reg, lambda d: person_add(d, "alice", tier="low", granted_by="nathan")[1],
                   out=lines.append, confirm=lambda: False)
    assert reg.read_text() == before and any("+  alice:" in x for x in lines)
    msg = apply_edit(reg, lambda d: person_add(d, "alice", tier="low", granted_by="nathan")[1],
                     out=lines.append, confirm=lambda: True)
    assert "alice" in msg and "alice" in data(reg)["people"]


def test_apply_edit_no_aliases(reg):
    apply_edit(reg, lambda d: person_add(d, "alice", tier="low", granted_by="nathan",
                                         today=TODAY)[1])
    assert "&id" not in reg.read_text()


# ── build tiergate host flags ───────────────────────────────────────────────

def _tg(capsys, *extra):
    rc = main(["build", "tiergate", "--registry", str(EXAMPLE), *extra])
    return rc, capsys.readouterr()


def test_tiergate_base_domain(capsys):
    rc, c = _tg(capsys, "--base-domain", "home.test")
    assert rc == 0 and "books.home.test: guest-long" in c.out


def test_tiergate_host_override(capsys):
    rc, c = _tg(capsys, "--base-domain", "home.test", "--host", "books=lib.example.org")
    assert rc == 0 and "lib.example.org: guest-long" in c.out
    assert "books.home.test" not in c.out


def test_tiergate_registry_hosts(capsys):
    rc, c = _tg(capsys, "--registry-hosts")
    assert rc == 0 and "dash.example.home: high" in c.out


def test_tiergate_bad_host_arg(capsys):
    rc, c = _tg(capsys, "--host", "books")
    assert rc == 2 and "RES=FQDN" in c.err


def test_tiergate_unknown_override(capsys):
    rc, c = _tg(capsys, "--host", "ghost=x.y")
    assert rc == 1 and "unknown resource" in c.err


def test_host_flags_rejected_for_other_targets(capsys):
    rc = main(["build", "graph", "--registry", str(EXAMPLE), "--registry-hosts"])
    assert rc == 2 and "only supported for the tiergate" in capsys.readouterr().err
