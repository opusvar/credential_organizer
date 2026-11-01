import json
from pathlib import Path

import pytest

from cvc.access.model import load_registry
from cvc.tailnet.__main__ import main
from cvc.tailnet.policy import PolicyError, build_policy, render_hujson

REG = str(Path(__file__).resolve().parent.parent / "access" / "registry.example.yaml")


def _strip(text):
    return json.loads("\n".join(ln for ln in text.splitlines() if not ln.startswith("//")))


def test_owner_full_and_shared_limited():
    policy, warnings = build_policy(load_registry(REG), ["nathan"])
    assert warnings == []
    assert policy["groups"] == {"group:owner": ["nathan@local"]}
    owner, shared = policy["acls"]
    assert owner == {"action": "accept", "src": ["group:owner"], "dst": ["*:*"]}
    assert shared["src"] == ["autogroup:shared"]
    assert shared["dst"] == ["services-node:443", "services-node:8710"]
    assert policy["hosts"]["services-node"] == "100.106.97.34"


def test_group_limit_warns():
    _, w = build_policy(load_registry(REG), ["nathan"], {"a": ["nathan"], "b": ["nathan"]})
    assert w == []
    _, w = build_policy(load_registry(REG), ["nathan"],
                        {"a": ["nathan"], "b": ["nathan"], "c": ["nathan"]})
    assert w and "free-plan" in w[0]


def test_unknown_owner_and_duplicate():
    with pytest.raises(PolicyError):
        build_policy(load_registry(REG), ["ghost"])
    with pytest.raises(PolicyError):
        build_policy(load_registry(REG), ["nathan"], {"owner": ["nathan"]})


def test_render_is_hujson():
    policy, _ = build_policy(load_registry(REG), ["nathan"])
    text = render_hujson(policy)
    assert text.startswith("//")
    assert _strip(text) == policy


def test_cli_stdout_and_out(tmp_path, capsys):
    assert main(["policy", "--registry", REG]) == 0
    assert _strip(capsys.readouterr().out)["acls"]
    out = tmp_path / "p.hujson"
    assert main(["policy", "--registry", REG, "--out", str(out),
                 "--group", "x=nathan", "--group", "y=nathan", "--group", "z=nathan"]) == 0
    assert "warning" in capsys.readouterr().err
    assert _strip(out.read_text())["groups"]["group:z"] == ["nathan@local"]


def test_cli_errors():
    assert main(["policy", "--registry", REG, "--owner", "ghost"]) == 1
    assert main(["policy", "--registry", REG, "--group", "bad"]) == 1
    assert main(["policy", "--registry", "/nonexistent.yaml"]) == 1
