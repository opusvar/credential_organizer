import base64
import datetime as dt
from urllib.parse import quote

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from cvc.tiergate.app import create_app
from cvc.tiergate.core import TIERS, extract_identity, load_cert, parse_config

_KEY = ec.generate_private_key(ec.SECP256R1())


def make_cert(uris: list[str]) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = dt.datetime.now(dt.UTC)
    b = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=1))
    )
    if uris:
        b = b.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(u) for u in uris]),
            critical=False,
        )
    return b.sign(_KEY, hashes.SHA256())


def traefik_header(cert: x509.Certificate) -> str:
    """Mimic passTLSClientCert pem:true — PEM body without delimiters, URL-escaped."""
    return quote(base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode())


def full_pem_header(cert: x509.Certificate) -> str:
    return quote(cert.public_bytes(serialization.Encoding.PEM).decode())


def ident_cert(tier: str, person: str = "alex", device: str | None = "phone1"):
    uris = [f"urn:cvc:tier:{tier}", f"urn:cvc:person:{person}"]
    if device:
        uris.append(f"urn:cvc:device:{device}")
    return make_cert(uris)


CFG = parse_config(
    {
        "hosts": {
            "media.home": "media-only",
            "wiki.home": "medium",
            "vault.home": "high",
            "admin.home": "admin",
        }
    }
)


@pytest.fixture
def client():
    return TestClient(create_app(CFG))


def call(client, host, cert=None, authentik=None, encoder=traefik_header):
    headers = {"X-Forwarded-Host": host}
    if cert is not None:
        headers["X-Forwarded-Tls-Client-Cert"] = encoder(cert)
    if authentik is not None:
        headers["X-authentik-username"] = authentik
    return client.get("/auth", headers=headers)


def test_tier_order():
    assert TIERS == (
        "guest-short", "guest-long", "media-only", "low", "medium", "high", "admin", "owner"
    )


def test_extract_identity_both_encodings():
    c = ident_cert("medium")
    for enc in (traefik_header, full_pem_header):
        ident = extract_identity(load_cert(enc(c)))
        assert (ident.tier, ident.person, ident.device) == ("medium", "alex", "phone1")


def test_chain_takes_leaf():
    leaf, other = ident_cert("low", person="leaf"), ident_cert("owner", person="ca")
    hdr = traefik_header(leaf) + "," + traefik_header(other)
    assert extract_identity(load_cert(hdr)).person == "leaf"


def test_allow_sets_headers(client):
    r = call(client, "wiki.home", ident_cert("high"))
    assert r.status_code == 200
    assert r.headers["X-Cvc-Person"] == "alex"
    assert r.headers["X-Cvc-Tier"] == "high"
    assert r.headers["X-Cvc-Device"] == "phone1"


def test_exact_min_tier_allowed(client):
    assert call(client, "media.home", ident_cert("media-only")).status_code == 200


def test_below_min_denied(client):
    assert call(client, "wiki.home", ident_cert("low")).status_code == 403
    assert call(client, "media.home", ident_cert("guest-long")).status_code == 403


def test_no_cert_denied(client):
    assert call(client, "media.home").status_code == 403


def test_garbage_cert_denied(client):
    r = client.get(
        "/auth",
        headers={"X-Forwarded-Host": "media.home", "X-Forwarded-Tls-Client-Cert": "not%20a%20cert"},
    )
    assert r.status_code == 403


def test_unknown_host_denied(client):
    assert call(client, "other.home", ident_cert("owner"), authentik="n").status_code == 403


def test_missing_tier_or_person_denied(client):
    assert call(client, "media.home", make_cert(["urn:cvc:person:x"])).status_code == 403
    assert call(client, "media.home", make_cert(["urn:cvc:tier:owner"])).status_code == 403
    assert call(client, "media.home", make_cert([])).status_code == 403
    assert call(client, "media.home", make_cert(["urn:cvc:tier:bogus", "urn:cvc:person:x"])
                ).status_code == 403


@pytest.mark.parametrize("host", ["vault.home", "admin.home"])
def test_passkey_required_for_high_hosts(client, host):
    assert call(client, host, ident_cert("owner")).status_code == 403
    assert call(client, host, ident_cert("owner"), authentik="  ").status_code == 403
    assert call(client, host, ident_cert("owner"), authentik="alex").status_code == 200


def test_passkey_not_required_for_lower_hosts(client):
    assert call(client, "wiki.home", ident_cert("owner")).status_code == 200


def test_host_header_fallback_and_port(client):
    hdr = traefik_header(ident_cert("medium"))
    r = client.get(
        "/auth", headers={"Host": "WIKI.home:443", "X-Forwarded-Tls-Client-Cert": hdr}
    )
    assert r.status_code == 200


def test_default_min_tier():
    cfg = parse_config({"hosts": {}, "default_min_tier": "low"})
    c = TestClient(create_app(cfg))
    assert call(c, "x.home", ident_cert("low")).status_code == 200
    assert call(c, "x.home", ident_cert("media-only")).status_code == 403


def test_bad_config_rejected():
    with pytest.raises(ValueError):
        parse_config({"hosts": {"a": "superuser"}})
    with pytest.raises(ValueError):
        parse_config({"hosts": {}, "default_min_tier": "nope"})


def test_healthz(client):
    assert client.get("/healthz").json() == {"ok": True}


# ── D27: temporary (bridge) device certs ────────────────────────────────────
def _future(hours=48):
    return (dt.datetime.now(dt.UTC) + dt.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def temp_cert(tier="medium", device="alex-temp-1", expires=None, flag=True):
    uris = [f"urn:cvc:tier:{tier}", "urn:cvc:person:alex", f"urn:cvc:device:{device}"]
    if flag:
        uris.append(f"urn:cvc:temp:{expires or _future()}")
    return make_cert(uris)


def test_temp_flag_parsed_and_headers(client):
    end = _future()
    ident = extract_identity(temp_cert(expires=end))
    assert ident.temp and ident.temp_expires == end and ident.tier == "medium"
    r = call(client, "wiki.home", temp_cert(expires=end))
    assert r.status_code == 200
    assert r.headers["X-Cvc-Temp"] == "1" and r.headers["X-Cvc-Temp-Expires"] == end


def test_permanent_cert_has_no_temp_headers(client):
    r = call(client, "wiki.home", ident_cert("high"))
    assert "X-Cvc-Temp" not in r.headers and not extract_identity(ident_cert("high")).temp


@pytest.mark.parametrize("tier", ["high", "admin", "owner"])
def test_temp_tier_capped_at_medium(client, tier):
    """Even a mis-issued temp cert carrying a high tier is treated as medium."""
    c = temp_cert(tier=tier)
    assert extract_identity(c).tier == "medium"
    assert call(client, "wiki.home", c).headers["X-Cvc-Tier"] == "medium"
    for host in ("vault.home", "admin.home"):
        assert call(client, host, c, authentik="alex").status_code == 403


def test_temp_device_id_without_flag_still_capped(client):
    c = temp_cert(tier="owner", flag=False)
    ident = extract_identity(c)
    assert ident.temp and ident.tier == "medium" and ident.temp_expires is None
    assert call(client, "admin.home", c, authentik="alex").status_code == 403


def test_low_temp_tier_not_raised():
    assert extract_identity(temp_cert(tier="low")).tier == "low"


@pytest.mark.parametrize("expires", ["2020-01-01T00:00:00Z", "not-a-date"])
def test_expired_or_garbled_temp_denied(client, expires):
    r = call(client, "wiki.home", temp_cert(expires=expires))
    assert r.status_code == 403
