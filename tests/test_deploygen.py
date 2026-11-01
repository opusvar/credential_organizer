"""cvc.deploygen: Traefik CRDs, tiergate ConfigMap, takeover API, deploy/ manifest consistency."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from cvc.access.model import RegistryError, load_registry
from cvc.deploygen import traefik as T
from cvc.deploygen.__main__ import main
from cvc.deploygen.takeover_app import create_app
from cvc.takeover.model import TakeoverStore
from cvc.tiergate.core import parse_config

ROOT = Path(__file__).resolve().parent.parent
REG = ROOT / "access" / "registry.example.yaml"
DEPLOY = ROOT / "deploy"


@pytest.fixture(scope="module")
def reg():
    return load_registry(REG)


def _docs(text: str) -> list[dict]:
    return [d for d in yaml.safe_load_all(text) if d]


def _routes(docs):
    return {d["metadata"]["name"]: d for d in docs if d["kind"] == "IngressRoute"}


def test_generated_yaml_parses_and_kinds(reg):
    docs = _docs(T.build_traefik(reg))
    kinds = [d["kind"] for d in docs]
    assert kinds.count("TLSOption") == 1
    assert {"Middleware", "IngressRoute"} <= set(kinds)
    assert all(d["apiVersion"] == "traefik.io/v1alpha1" for d in docs)
    assert len(_routes(docs)) == len(reg.resources)


def test_tls_option_requires_and_verifies_client_cert(reg):
    tls = next(d for d in _docs(T.build_traefik(reg)) if d["kind"] == "TLSOption")
    assert tls["spec"]["clientAuth"] == {"secretNames": [T.CA_SECRET],
                                         "clientAuthType": "RequireAndVerifyClientCert"}
    for r in _routes(_docs(T.build_traefik(reg))).values():
        assert r["spec"]["tls"]["options"]["name"] == T.TLS_OPTION


def test_header_strip_first_and_covers_identity_headers(reg):
    docs = _docs(T.build_traefik(reg))
    for r in _routes(docs).values():
        mws = [m["name"] for m in r["spec"]["routes"][0]["middlewares"]]
        assert mws[0] == T.STRIP and mws[1] == T.CLIENT_CERT and mws[-1] == T.TIERGATE
    strip = next(d for d in docs if d["metadata"]["name"] == T.STRIP)
    hdrs = strip["spec"]["headers"]["customRequestHeaders"]
    assert all(v == "" for v in hdrs.values())
    for needed in ("X-Forwarded-Tls-Client-Cert", "X-Forwarded-Tls-Client-Cert-Info",
                   "X-Cvc-Person", "X-Cvc-Tier", "X-Cvc-Device", "X-authentik-username"):
        assert needed in hdrs


def test_passkey_hosts_include_authentik(reg):
    routes = _routes(_docs(T.build_traefik(reg)))
    for rid, res in reg.resources.items():
        mws = [m["name"] for m in routes[f"cvc-{rid}"]["spec"]["routes"][0]["middlewares"]]
        assert (T.AUTHENTIK in mws) == res.passkey_required
        if res.passkey_required:
            assert mws.index(T.AUTHENTIK) < mws.index(T.TIERGATE)
    assert any(r.passkey_required for r in reg.resources.values())
    assert any(not r.passkey_required for r in reg.resources.values())


def test_base_domain_switch_and_overrides(reg):
    default = _routes(_docs(T.build_traefik(reg)))
    assert default["cvc-books"]["spec"]["routes"][0]["match"] == (
        "Host(`books.orangepi6.humpback-krait.ts.net`)")
    opts = T.Options(base_domain="home.example.org.", host_overrides={"ha": "hass.example.net"})
    routes = _routes(_docs(T.build_traefik(reg, opts)))
    assert routes["cvc-books"]["spec"]["routes"][0]["match"] == "Host(`books.home.example.org`)"
    assert routes["cvc-ha"]["spec"]["routes"][0]["match"] == "Host(`hass.example.net`)"
    reg_hosts = T.resource_hosts(reg, T.Options(registry_hosts=True))
    assert reg_hosts["media"] == "media.example.home"
    with pytest.raises(RegistryError):
        T.resource_hosts(reg, T.Options(host_overrides={"nope": "x.y"}))
    with pytest.raises(RegistryError):
        T.resource_hosts(reg, T.Options(host_overrides={"ha": "books.orangepi6.humpback-krait.ts.net"}))


def test_tiergate_configmap_matches_routes(reg):
    opts = T.Options(base_domain="d.test")
    cm = _docs(T.build_tiergate_configmap(reg, opts))[0]
    cfg = parse_config(yaml.safe_load(cm["data"]["config.yaml"]))
    hosts = set(T.resource_hosts(reg, opts).values())
    assert set(cfg.hosts) == hosts
    assert cfg.default_min_tier is None
    assert cfg.min_tier_for("portainer.d.test") == "admin"


def test_cli(tmp_path, capsys):
    out = tmp_path / "r.yaml"
    assert main(["traefik", "--registry", str(REG), "--base-domain", "x.test",
                 "--host", "books=lib.x.test", "-o", str(out)]) == 0
    text = out.read_text()
    assert "Host(`lib.x.test`)" in text and "Host(`ha.x.test`)" in text
    assert main(["tiergate", "--registry", str(REG)]) == 0
    assert "cvc-tiergate-config" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main(["traefik", "--registry", str(REG), "--host", "bad"])


def test_committed_examples_up_to_date(reg):
    assert (DEPLOY / "traefik" / "routes.example.yaml").read_text() == T.build_traefik(reg)
    assert (DEPLOY / "tiergate" / "configmap.generated.yaml").read_text() == (
        T.build_tiergate_configmap(reg))


# --- deploy/ manifests -------------------------------------------------------------------

def _file_docs(path: Path) -> list[dict]:
    return _docs(path.read_text())


def test_all_new_deploy_manifests_parse():
    for sub in ("traefik", "tiergate", "takeover", "step-ca"):
        for f in sorted((DEPLOY / sub).glob("*.yaml")):
            for d in _file_docs(f):
                assert "kind" in d and "apiVersion" in d, f


def test_takeover_manifests_wiring():
    docs = _file_docs(DEPLOY / "takeover" / "takeover.yaml")
    svc = next(d for d in docs if d["kind"] == "Service")
    dep = next(d for d in docs if d["kind"] == "Deployment")
    pvc = next(d for d in docs if d["kind"] == "PersistentVolumeClaim")
    assert svc["spec"]["selector"] == dep["spec"]["template"]["metadata"]["labels"]
    vols = dep["spec"]["template"]["spec"]["volumes"]
    assert vols[0]["persistentVolumeClaim"]["claimName"] == pvc["metadata"]["name"]
    routes = _routes(docs)
    shared = {d["metadata"]["name"] for d in T.shared_objects(T.Options())}
    for r in routes.values():
        route = r["spec"]["routes"][0]
        mws = [m["name"] for m in route["middlewares"]]
        assert set(mws) <= shared and mws[0] == T.STRIP and mws[-1] == T.TIERGATE
        assert route["services"][0]["name"] == svc["metadata"]["name"]
        assert r["spec"]["tls"]["options"]["name"] == T.TLS_OPTION
    admin = routes["cvc-takeover-admin"]["spec"]["routes"][0]
    assert "/v1/takeover/status" in admin["match"] and T.AUTHENTIK in str(admin["middlewares"])
    assert "status" not in routes["cvc-takeover"]["spec"]["routes"][0]["match"]


def test_step_ca_names_consistent():
    docs = [d for f in sorted((DEPLOY / "step-ca").glob("*.yaml")) for d in _file_docs(f)]
    by = {(d["kind"], d["metadata"]["name"]): d for d in docs}
    ns = by[("Namespace", "pki")]["metadata"]["name"]
    for d in docs:
        if d["kind"] not in ("Namespace", "PersistentVolume"):
            assert d["metadata"]["namespace"] == ns
    pv = by[("PersistentVolume", "pki-step-ca")]
    pvc = by[("PersistentVolumeClaim", "step-ca-data")]
    assert pvc["spec"]["volumeName"] == pv["metadata"]["name"]
    assert pv["spec"]["claimRef"]["name"] == pvc["metadata"]["name"]
    assert pv["spec"]["claimRef"]["namespace"] == ns
    pod = by[("Deployment", "step-ca")]["spec"]["template"]["spec"]
    vols = {v["name"]: v for v in pod["volumes"]}
    assert vols["data"]["persistentVolumeClaim"]["claimName"] == "step-ca-data"
    assert vols["tmpl"]["configMap"]["name"] == "step-ca-config"
    mounts = {m["name"] for c in pod["containers"] + pod["initContainers"]
              for m in c["volumeMounts"]}
    assert mounts <= set(vols)
    assert re.search(r"configmap step-ca-config", (DEPLOY / "step-ca" / "deployment.yaml")
                     .read_text())


def test_helmchartconfig_binds_tailscale_only():
    d = _file_docs(DEPLOY / "traefik" / "helmchartconfig-tailscale-only.yaml")[0]
    vals = yaml.safe_load(d["spec"]["valuesContent"])
    assert vals["service"]["type"] == "ClusterIP"
    assert {p["hostIP"] for p in vals["ports"].values()} == {"100.106.97.34"}


# --- takeover API ------------------------------------------------------------------------

def test_takeover_api_identity_and_owner_gate(tmp_path):
    c = TestClient(create_app(TakeoverStore(tmp_path)))
    assert c.get("/v1/takeover/faq").status_code == 200
    assert c.get("/v1/takeover/banner").status_code == 401
    r = c.get("/v1/takeover/banner?person=nathan", headers={"X-Cvc-Person": "alice"})
    assert r.json() == {"person": "alice", "active": False, "takeovers": []}
    assert c.get("/v1/takeover/status", headers={"X-Cvc-Person": "a",
                                                 "X-Cvc-Tier": "admin"}).status_code == 403
    ok = c.get("/v1/takeover/status", headers={"X-Cvc-Person": "n", "X-Cvc-Tier": "owner"})
    assert ok.status_code == 200 and ok.json() == {"takeovers": []}


# --- tier-gate builders agree ------------------------------------------------------------

@pytest.mark.parametrize("kw", [
    {},
    {"base_domain": "example.test"},
    {"registry_hosts": True},
    {"host_overrides": {"ha": "home.example.test"}},
])
def test_access_and_deploygen_tiergate_hosts_identical(reg, kw):
    from cvc.access.catalog import build_tiergate
    opts = T.Options(**kw)
    access_hosts = yaml.safe_load(build_tiergate(reg, **kw))["hosts"]
    cm = next(d for d in yaml.safe_load_all(T.build_tiergate_configmap(reg, opts)) if d)
    deploygen_hosts = yaml.safe_load(cm["data"]["config.yaml"])["hosts"]
    assert access_hosts == deploygen_hosts
    route_hosts = {r["match"].split("`")[1] for d in T.route_objects(reg, opts)
                   for r in d["spec"]["routes"]}
    assert set(access_hosts) == route_hosts == set(T.resource_hosts(reg, opts).values())
