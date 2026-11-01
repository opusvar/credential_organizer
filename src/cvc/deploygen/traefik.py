"""Traefik v3 CRDs (IngressRoute / Middleware / TLSOption) from the registry resource catalog.

Per resource the route is `<resource-id>.<base-domain>` unless overridden. Middleware order:

    cvc-strip-identity-headers   drop client-supplied identity headers (must be first)
    cvc-client-cert              passTLSClientCert -> X-Forwarded-Tls-Client-Cert
    cvc-authentik                forwardAuth to the Authentik outpost (passkey tiers only)
    cvc-tiergate                 forwardAuth to cvc-tiergate (host -> min tier)

TLS: TLSOption `cvc-mtls` requires and verifies client certs against the step-ca root
(Secret `cvc-step-ca-root`, key `tls.ca`). The server cert comes from Secret `cvc-routes-tls`
(a step-ca-issued wildcard for `*.<base-domain>`; Tailscale's `tailscale cert` cannot issue for
sub-names of a machine name).
"""
from __future__ import annotations

from dataclasses import dataclass, field

import yaml

from cvc.access.builders import GENERATED_HEADER
from cvc.access.check import check_resources
from cvc.access.model import PERSON_TIERS, Registry, RegistryError

DEFAULT_BASE_DOMAIN = "orangepi6.humpback-krait.ts.net"
DEFAULT_NAMESPACE = "cvc"
DEFAULT_ENTRYPOINT = "websecure"
AUTHENTIK_OUTPOST = ("http://ak-outpost-authentik-embedded-outpost.auth.svc.cluster.local:9000"
                     "/outpost.goauthentik.io/auth/traefik")
TIERGATE_URL = "http://cvc-tiergate.cvc.svc.cluster.local:8720/auth"

STRIP = "cvc-strip-identity-headers"
CLIENT_CERT = "cvc-client-cert"
AUTHENTIK = "cvc-authentik"
TIERGATE = "cvc-tiergate"
TLS_OPTION = "cvc-mtls"
CA_SECRET = "cvc-step-ca-root"
SERVER_TLS_SECRET = "cvc-routes-tls"

# Traefik's headers middleware cannot match prefixes, so every identity header the gate chain
# sets or trusts is enumerated; an empty value deletes the header from the request.
AUTHENTIK_HEADERS = [
    "X-authentik-username", "X-authentik-groups", "X-authentik-entitlements",
    "X-authentik-email", "X-authentik-name", "X-authentik-uid", "X-authentik-jwt",
    "X-authentik-meta-jwks", "X-authentik-meta-outpost", "X-authentik-meta-provider",
    "X-authentik-meta-app", "X-authentik-meta-version",
]
CVC_HEADERS = ["X-Cvc-Person", "X-Cvc-Tier", "X-Cvc-Device"]
STRIPPED_HEADERS = [
    "X-Forwarded-Tls-Client-Cert", "X-Forwarded-Tls-Client-Cert-Info",
    *CVC_HEADERS, *AUTHENTIK_HEADERS,
]


@dataclass(frozen=True)
class Options:
    base_domain: str = DEFAULT_BASE_DOMAIN
    namespace: str = DEFAULT_NAMESPACE
    entrypoints: tuple[str, ...] = (DEFAULT_ENTRYPOINT,)
    host_overrides: dict[str, str] = field(default_factory=dict)  # resource id -> fqdn
    registry_hosts: bool = False   # use each resource's registry `host` verbatim


def _checked(registry: Registry) -> None:
    errors = [f"{f.path}: {f.message}" for f in check_resources(registry) if f.level == "error"]
    if errors:
        raise RegistryError(errors)
    if not registry.resources:
        raise RegistryError(["resources: empty; nothing to route"])


def resource_hosts(registry: Registry, opts: Options) -> dict[str, str]:
    """resource id -> route hostname (override > registry host if requested > id.base)."""
    unknown = sorted(set(opts.host_overrides) - set(registry.resources))
    if unknown:
        raise RegistryError([f"host override for unknown resource: {r}" for r in unknown])
    base = opts.base_domain.strip().strip(".").lower()
    out = {}
    for rid in sorted(registry.resources):
        if rid in opts.host_overrides:
            out[rid] = opts.host_overrides[rid].strip().lower()
        elif opts.registry_hosts:
            out[rid] = registry.resources[rid].host
        else:
            out[rid] = f"{rid}.{base}"
    dupes = sorted({h for h in out.values() if list(out.values()).count(h) > 1})
    if dupes:
        raise RegistryError([f"duplicate route host: {h}" for h in dupes])
    return out


def chain_for(passkey_required: bool) -> list[str]:
    return [STRIP, CLIENT_CERT, *([AUTHENTIK] if passkey_required else []), TIERGATE]


def _meta(kind: str, name: str, ns: str, **labels: str) -> dict:
    md: dict = {"name": name, "namespace": ns,
                "labels": {"app.kubernetes.io/managed-by": "cvc-deploygen", **labels}}
    return {"apiVersion": "traefik.io/v1alpha1", "kind": kind, "metadata": md}


def shared_objects(opts: Options) -> list[dict]:
    ns = opts.namespace
    tls = _meta("TLSOption", TLS_OPTION, ns)
    tls["spec"] = {"minVersion": "VersionTLS12", "sniStrict": True,
                   "clientAuth": {"secretNames": [CA_SECRET],
                                  "clientAuthType": "RequireAndVerifyClientCert"}}
    strip = _meta("Middleware", STRIP, ns)
    strip["spec"] = {"headers": {"customRequestHeaders": {h: "" for h in STRIPPED_HEADERS}}}
    cert = _meta("Middleware", CLIENT_CERT, ns)
    cert["spec"] = {"passTLSClientCert": {"pem": True}}
    ak = _meta("Middleware", AUTHENTIK, ns)
    ak["spec"] = {"forwardAuth": {"address": AUTHENTIK_OUTPOST, "trustForwardHeader": True,
                                  "authResponseHeaders": AUTHENTIK_HEADERS}}
    tg = _meta("Middleware", TIERGATE, ns)
    # trustForwardHeader is safe: the strip middleware runs first and Traefik sets X-Forwarded-*
    # itself on the entrypoint (forwardedHeaders.trustedIPs is left empty).
    tg["spec"] = {"forwardAuth": {"address": TIERGATE_URL, "trustForwardHeader": True,
                                  "authResponseHeaders": CVC_HEADERS}}
    return [tls, strip, cert, ak, tg]


def route_objects(registry: Registry, opts: Options) -> list[dict]:
    hosts = resource_hosts(registry, opts)
    out = []
    for rid, host in hosts.items():
        res = registry.resources[rid]
        ir = _meta("IngressRoute", f"cvc-{rid}", opts.namespace,
                   **{"cvc.access/resource": rid, "cvc.access/min-tier": res.min_tier})
        ir["metadata"]["annotations"] = {"cvc.access/name": res.name,
                                         "cvc.access/upstream-url": res.url or ""}
        ir["spec"] = {
            "entryPoints": list(opts.entrypoints),
            "routes": [{
                "match": f"Host(`{host}`)", "kind": "Rule",
                "middlewares": [{"name": m} for m in chain_for(res.passkey_required)],
                # Upstream Service is a placeholder named after the resource; create it (or an
                # ExternalName/Endpoints pair for host services like calibre-web) per DEPLOY.md.
                "services": [{"name": f"cvc-upstream-{rid}", "port": 80}],
            }],
            "tls": {"secretName": SERVER_TLS_SECRET, "options": {"name": TLS_OPTION}},
        }
        out.append(ir)
    return out


def tiergate_hosts(registry: Registry, opts: Options) -> dict[str, str]:
    hosts = resource_hosts(registry, opts)
    return {hosts[r]: registry.resources[r].min_tier
            for r in sorted(hosts, key=lambda r: hosts[r])}


class _Dumper(yaml.SafeDumper):
    pass


def _str(dumper: yaml.SafeDumper, data: str) -> yaml.ScalarNode:
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


_Dumper.add_representer(str, _str)


def _dump(docs: list[dict]) -> str:
    return yaml.dump_all(docs, Dumper=_Dumper, sort_keys=False, explicit_start=True)


def build_traefik(registry: Registry, opts: Options | None = None) -> str:
    opts = opts or Options()
    _checked(registry)
    head = GENERATED_HEADER.format(name="traefik").replace("cvc-access build traefik",
                                                           "cvc-deploygen traefik")
    head += (f"# base domain: {opts.base_domain}; entrypoints: {', '.join(opts.entrypoints)}\n"
             "# NOT applied. Review, then `kubectl apply -f`. Chain: " + " -> ".join(
                 chain_for(True)) + " (authentik only on high/admin/owner hosts).\n")
    return head + _dump(shared_objects(opts) + route_objects(registry, opts))


def build_tiergate_configmap(registry: Registry, opts: Options | None = None) -> str:
    """ConfigMap for cvc-tiergate whose host keys match the generated routes."""
    opts = opts or Options()
    _checked(registry)
    cfg = ("# Tier order: " + " < ".join(PERSON_TIERS) + "\n# Unlisted hosts are denied.\n"
           + yaml.safe_dump({"hosts": tiergate_hosts(registry, opts)}, sort_keys=False))
    cm = {"apiVersion": "v1", "kind": "ConfigMap",
          "metadata": {"name": "cvc-tiergate-config", "namespace": opts.namespace},
          "data": {"config.yaml": cfg}}
    head = GENERATED_HEADER.format(name="tiergate").replace("cvc-access build tiergate",
                                                            "cvc-deploygen tiergate")
    return head + _dump([cm])
