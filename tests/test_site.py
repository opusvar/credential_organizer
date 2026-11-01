"""cvc.site: lookup order, templating, render-deploy, and the no-private-site-values check."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
import yaml

from cvc import site as S

REPO = Path(__file__).resolve().parent.parent


def test_env_site_is_test_fixture():
    s = S.load()
    assert s.node_ip == "100.64.0.10" and s.default_owner_ids == ("alex",)
    assert s.ca_url == "https://100.64.0.10:9000"
    assert s.vault_url == "https://cvc.example.ts.net:8443/vault"


def test_lookup_order(tmp_path, monkeypatch):
    monkeypatch.delenv("CVC_SITE")
    assert S.load() is S.GENERIC                     # nothing configured -> generic
    assert S.GENERIC.default_owner_ids == ()
    xdg = S.default_path()
    xdg.parent.mkdir(parents=True)
    xdg.write_text("node_ip: 100.64.0.20\n")
    assert S.load().node_ip == "100.64.0.20"         # XDG file
    env = tmp_path / "env.yaml"
    env.write_text("node_ip: 100.64.0.30\n")
    monkeypatch.setenv("CVC_SITE", str(env))
    assert S.load().node_ip == "100.64.0.30"         # env beats XDG
    flag = tmp_path / "flag.yaml"
    flag.write_text("node_ip: 100.64.0.40\nca_url: https://ca.example:1\n")
    s = S.load(flag)
    assert s.node_ip == "100.64.0.40" and s.ca_url == "https://ca.example:1"  # flag beats env


def test_errors(tmp_path):
    with pytest.raises(S.SiteError):
        S.load(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("nodeip: x\n")
    with pytest.raises(S.SiteError, match="unknown keys"):
        S.load(bad)
    with pytest.raises(S.SiteError):
        S.owners_or_default(None, S.GENERIC)
    assert S.owners_or_default(["sam"], S.GENERIC) == ["sam"]


def test_example_file_loads():
    s = S.load(REPO / "site.example.yaml")
    assert s.base_domain == "cvc.example.ts.net" and s.default_owner_ids == ("alex",)


def test_render_leaves_shell_vars():
    s = S.load()
    out = S.render('a=${SITE_NODE_IP} b="${CA_URL:-${SITE_CA_URL}}" c=$HOME', s)
    assert out == 'a=100.64.0.10 b="${CA_URL:-https://100.64.0.10:9000}" c=$HOME'
    with pytest.raises(S.SiteError):
        S.render("${SITE_NOPE}", s)


def test_render_deploy_all_placeholders_known(tmp_path):
    assert S.main(["render-deploy", "--src", str(REPO / "deploy"), "--out",
                   str(tmp_path / "out")]) == 0
    out = tmp_path / "out"
    for f in out.rglob("*"):
        if f.is_file():
            assert "${SITE_" not in f.read_text(errors="ignore"), f
    dep = [d for d in yaml.safe_load_all((out / "step-ca" / "deployment.yaml").read_text())
           if d and d["kind"] == "Deployment"][0]
    ports = dep["spec"]["template"]["spec"]["containers"][0]["ports"]
    assert {p["hostIP"] for p in ports if "hostPort" in p} == {"100.64.0.10"}


# --- CI guard: no private site values in the product repo -------------------------------
# Patterns are assembled from pieces so this file does not match itself. Allowlist: none.
_PRIVATE = [
    r"100\.106\." + r"97\.34",
    "humpback" + "-krait",
    "orange" + "pi6",
    "nath" + "an",
    r"192\.168\." + r"1\.",
    "smuck" + "ler",
]


def test_no_private_site_values_in_repo():
    files = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], cwd=REPO,
                           capture_output=True, text=True, check=True).stdout.split()
    pat = re.compile("|".join(_PRIVATE), re.IGNORECASE)
    hits = []
    for rel in files:
        p = REPO / rel
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        hits += [f"{rel}:{i}: {ln.strip()}" for i, ln in enumerate(text.splitlines(), 1)
                 if pat.search(ln)]
    assert not hits, "private site values found (move them to site.yaml):\n" + "\n".join(hits)
