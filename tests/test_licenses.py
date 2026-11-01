"""License policy gate. See docs/LICENSING.md and scripts/license_inventory.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("license_inventory",
                                               ROOT / "scripts" / "license_inventory.py")
li = importlib.util.module_from_spec(_spec)
sys.modules["license_inventory"] = li
_spec.loader.exec_module(li)

REGEN = "regenerate: python scripts/license_inventory.py"


@pytest.fixture(scope="module")
def pkgs():
    return li.inventory()


@pytest.mark.parametrize("expr,verdict", [
    ("MIT", li.ALLOW), ("BSD-3-Clause", li.ALLOW), ("Apache-2.0", li.ALLOW),
    ("ISC", li.ALLOW), ("PSF-2.0", li.ALLOW), ("MPL-2.0", li.ALLOW),
    ("LGPL-3.0-or-later", li.REVIEW), ("EPL-2.0", li.REVIEW),
    ("GPL-3.0-only", li.DENY), ("AGPL-3.0-only", li.DENY), ("SSPL-1.0", li.DENY),
    ("UNKNOWN", li.DENY), ("", li.DENY), ("WTFPL-ish custom", li.DENY),
    ("EPL-2.0 OR BSD-3-Clause", li.ALLOW), ("MIT AND GPL-2.0", li.DENY),
    ("GNU Lesser General Public License v3 (LGPLv3)", li.REVIEW),
    ("GNU Affero General Public License v3", li.DENY),
])
def test_classify(expr, verdict):
    assert li.classify(expr) == verdict


def test_no_denied_runtime_deps(pkgs):
    bad = [f"{p.name} {p.version} ({p.license})" for p in li.problems(pkgs)]
    assert not bad, f"denied/unknown runtime dependency licenses: {bad}"


def test_all_declared_runtime_deps_installed(pkgs):
    missing = [p.name for p in pkgs if p.scope == "runtime" and p.version == "not installed"]
    assert not missing, f"runtime deps not installed, cannot verify license: {missing}"


def _key(rows):
    # Version-independent: CI and dev boxes resolve different patch versions and
    # platform-specific transitive deps, so staleness = direct deps' identity+license.
    return sorted((r["name"], r["license"], r["scope"]) for r in rows if r["direct"])


def test_inventory_not_stale(pkgs):
    committed = json.loads((ROOT / "licenses.json").read_text())
    current = [vars(p) for p in pkgs if p.version != "not installed"]
    have = {r["name"] for r in current}
    expected = [r for r in committed["packages"] if r["name"] in have]
    assert _key(current) == _key(expected), f"licenses.json is stale; {REGEN}"
    assert committed["services"] == li.services() or all(
        a["name"] == b["name"] and a["license"] == b["license"]
        for a, b in zip(committed["services"], li.services(), strict=True)
    ), f"services section is stale; {REGEN}"


def test_markdown_matches_json():
    text = (ROOT / "THIRD_PARTY_LICENSES.md").read_text()
    committed = json.loads((ROOT / "licenses.json").read_text())
    for r in committed["packages"]:
        assert f"| {r['name']} | {r['version']} | {r['license']} |" in text, (
            f"THIRD_PARTY_LICENSES.md out of sync with licenses.json ({r['name']}); {REGEN}")
    for s in committed["services"]:
        assert f"| {s['name']} | {s['license']} |" in text
