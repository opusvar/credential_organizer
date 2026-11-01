"""Tests for the `graph` access builder (Mermaid auth diagram)."""
from __future__ import annotations

import copy
import datetime as dt
import re
from pathlib import Path

import yaml

import cvc.access.graph  # noqa: F401  (registers builder)
from cvc.access import BUILDERS, parse_registry
from cvc.access.graph import build_graph, mermaid_id, mermaid_label

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "access" / "registry.example.yaml"
TODAY = dt.date(2026, 10, 31)


def _data():
    return yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))


def _build(data, today=TODAY):
    return build_graph(parse_registry(data), today)


def _mermaid(out):
    return re.search(r"```mermaid\n(.*?)```", out, re.DOTALL).group(1)


def test_registered():
    assert BUILDERS["graph"] is build_graph


def test_snapshot_matches_docs_example():
    out = _build(_data())
    assert out == (ROOT / "docs" / "access-graph.example.md").read_text(encoding="utf-8")


def test_deterministic():
    d = _data()
    rev = copy.deepcopy(d)
    rev["agents"] = dict(reversed(list(d["agents"].items())))
    assert _build(d) == _build(rev)


def test_structure_and_no_secrets():
    out = _build(_data())
    m = _mermaid(out)
    assert m.startswith("flowchart LR")
    for title in ("AI agents", "Machines / sensors", "Roles", "Systems"):
        assert f'"{title}"' in m
    assert "(not enforced)" in m
    assert "11111111-2222" not in out
    assert "0000000000" not in out and "1111111111111111" not in out
    assert "backup" in m
    assert "2027-01-31" in out and "2026-10-31" in out


def test_expired_and_soon_and_orphans():
    d = _data()
    d["agents"]["personal-dashboard"]["expires"] = "2026-10-01"
    d["agents"]["playwright-billing"]["expires"] = "2026-11-15"
    d["agents"]["norole"] = {}
    d["roles"]["unused"] = {"description": "x", "grants": []}
    m = _mermaid(_build(d))
    assert "(expired)" in m
    assert "expiring 2026-11-15" in m
    assert "(no roles)" in m
    assert "unused" in m and "unused by anyone" in m


def test_label_escaping_and_injection():
    assert mermaid_label('a"b[c]<d>') == "a#quot;b#91;c#93;#lt;d#gt;"
    d = _data()
    evil = 'x"]\n end\n A-->B["pwn <script>'
    d["roles"][evil] = {"description": evil, "grants": []}
    d["agents"]["ev il-1"] = {"roles": [evil]}
    m = _mermaid(_build(d))
    assert "<script>" not in m
    assert "pwn" in m
    assert "A-->B" not in m


def test_id_sanitizing_stable_and_unique():
    assert re.fullmatch(r"[A-Za-z0-9_]+", mermaid_id("we!rd id/é"))
    d = _data()
    d["agents"]["a-b"] = {}
    d["agents"]["a_b"] = {}
    out = _build(d)
    assert out == _build(d)
    ids = re.findall(r"^\s*(\w+)\[", _mermaid(out), re.MULTILINE)
    assert len(ids) == len(set(ids))
    assert "p_a_b" in ids and "p_a_b_2" in ids


def test_topics_truncated():
    d = _data()
    d["roles"]["sensor-publish"]["grants"][0]["topics"] = [f"t/{i}" for i in range(5)]
    assert "5 topics" in _build(d)
