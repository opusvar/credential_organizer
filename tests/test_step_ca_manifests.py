"""Offline validation of deploy/step-ca manifests (no cluster access)."""

import json
import re
from pathlib import Path

import yaml

D = Path(__file__).resolve().parent.parent / "deploy" / "step-ca"
TS_IP = "100.106.97.34"


def _docs():
    out = []
    for f in sorted(D.glob("*.yaml")):
        out += [d for d in yaml.safe_load_all(f.read_text()) if d]
    return out


def test_manifests_parse_and_kinds():
    kinds = {d["kind"] for d in _docs()}
    assert {"Namespace", "PersistentVolume", "PersistentVolumeClaim", "Deployment"} <= kinds


def test_no_secret_objects_or_literals():
    for d in _docs():
        assert d["kind"] != "Secret"
    blob = "\n".join(f.read_text() for f in D.iterdir() if f.is_file())
    assert "BEGIN" not in blob or "PRIVATE KEY" not in blob
    assert not re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", blob)


def test_namespaced_in_pki():
    for d in _docs():
        if d["kind"] not in ("Namespace", "PersistentVolume"):
            assert d["metadata"]["namespace"] == "pki"


def test_hostport_bound_to_tailscale_ip():
    dep = next(d for d in _docs() if d["kind"] == "Deployment")
    spec = dep["spec"]
    assert spec["strategy"]["type"] == "Recreate"
    ports = [p for c in spec["template"]["spec"]["containers"] for p in c.get("ports", [])]
    hp = [p for p in ports if "hostPort" in p]
    assert hp and all(p["hostIP"] == TS_IP for p in hp)
    c = spec["template"]["spec"]["containers"][0]
    assert c["readinessProbe"]["httpGet"]["path"] == "/health"
    assert re.match(r"^smallstep/step-ca:\d+\.\d+\.\d+$", c["image"])
    env_values = [e.get("value") for e in c.get("env", [])]
    assert not any(env_values)


def test_hostpath_under_mnt_data_pki():
    pv = next(d for d in _docs() if d["kind"] == "PersistentVolume")
    assert pv["spec"]["hostPath"]["path"] == "/mnt/data/pki"
    assert pv["spec"]["persistentVolumeReclaimPolicy"] == "Retain"


def test_ca_json_template():
    cfg = json.loads((D / "ca.json.tmpl").read_text())
    provs = {p["name"]: p for p in cfg["authority"]["provisioners"]}
    oidc = provs["authentik"]
    assert oidc["clientSecret"] == "__OIDC_CLIENT_SECRET__"
    assert oidc["clientID"] == "__OIDC_CLIENT_ID__"
    assert provs["ios-scep"]["challenge"] == "__SCEP_CHALLENGE__"
    yk = provs["yubikey-attest"]
    assert yk["challenges"] == ["device-attest-01"] and yk["attestationFormats"] == ["step"]
    claims = cfg["authority"]["claims"]
    assert claims["defaultTLSCertDuration"] == "2160h"
    assert claims["disableRenewal"] is False
