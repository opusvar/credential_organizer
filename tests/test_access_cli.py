"""CLI wiring tests for `cvc-access build`."""
from __future__ import annotations

from pathlib import Path

from cvc.access.cli import main

REG = str(Path(__file__).resolve().parent.parent / "access" / "registry.example.yaml")


def _build(capsys, *extra):
    rc = main(["build", *extra, "--registry", REG])
    return rc, capsys.readouterr()


def test_build_mosquitto(capsys):
    rc, c = _build(capsys, "mosquitto")
    assert rc == 0 and "\nuser " in c.out


def test_build_graph(capsys):
    rc, c = _build(capsys, "graph")
    assert rc == 0 and "```mermaid" in c.out


def test_build_mosquitto_system(capsys):
    rc, c = _build(capsys, "mosquitto", "--system", "ha-mqtt")
    assert rc == 0 and "user " in c.out


def test_build_mosquitto_bad_system(capsys):
    rc, c = _build(capsys, "mosquitto", "--system", "vaultwarden")
    assert rc == 1 and "not an mqtt system" in c.err


def test_system_rejected_for_other_builders(capsys):
    rc, c = _build(capsys, "graph", "--system", "ha-mqtt")
    assert rc == 2 and "--system is only supported" in c.err
