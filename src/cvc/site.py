"""Site configuration: the per-installation values that are NOT part of the cvc product.

cvc the product is generic; everything that identifies one installation (node IPs, tailnet
name, route base domain, default owner ids, ...) lives in a `site.yaml` outside this repo.

Lookup order (first hit wins):
    1. explicit path (`--site FILE` on CLIs that accept it)
    2. `$CVC_SITE`
    3. `$XDG_CONFIG_HOME/cvc/site.yaml` (default `~/.config/cvc/site.yaml`)
    4. built-in GENERIC defaults (documentation-only addresses, no default owner)

See docs/SITE-CONFIG.md and site.example.yaml.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass, field, fields, replace
from pathlib import Path

import yaml


class SiteError(ValueError):
    pass


@dataclass(frozen=True)
class Site:
    node_ip: str = "100.64.0.1"             # services node, tailnet address
    lan_ip: str = "10.0.0.10"               # services node, LAN address
    base_domain: str = "cvc.example.ts.net"  # route base: <resource>.<base_domain>
    tailnet_name: str = "example"
    ca_admin_email: str = "admin@example.com"   # step-ca OIDC admin
    default_owner_ids: tuple[str, ...] = ()  # empty -> CLIs require an explicit --owner
    broker_port: int = 8710
    vault_port: int = 8443
    ca_port: int = 9000
    ca_url: str = ""                        # default https://<node_ip>:<ca_port>
    vault_url: str = ""                     # default https://<base_domain>:<vault_port>/vault
    namespaces: dict[str, str] = field(default_factory=lambda: {
        "cvc": "cvc", "pki": "pki", "auth": "auth"})
    # MQTT broker for cvc/approvals + cvc/audits (env MQTT_HOST/MQTT_PORT/MQTT_USERNAME win).
    # Only the username is configured here; MQTT_PASSWORD stays env-only.
    mqtt_host: str = ""                     # "" -> no MQTT publishing unless env opts in
    mqtt_port: int = 1883
    mqtt_username: str = ""                 # the broker's MQTT user (sole writer of cvc/#)
    # ntfy push (env CVC_NTFY_SERVERS / CVC_NTFY_TOPICS / CVC_APPROVAL_CARD_URL win).
    # Tokens are env-only (CVC_NTFY_TOKEN_<n>), never in site.yaml.
    ntfy_servers: tuple[str, ...] = ()      # failover order
    ntfy_topics: dict[str, str] = field(default_factory=dict)   # person id -> topic
    approval_card_url: str = ""             # "" -> "{dashboard}/agents/approvals/{id}"
    source: str = "<generic defaults>"

    def __post_init__(self) -> None:
        if not self.ca_url:
            object.__setattr__(self, "ca_url", f"https://{self.node_ip}:{self.ca_port}")
        if not self.vault_url:
            object.__setattr__(self, "vault_url",
                               f"https://{self.base_domain}:{self.vault_port}/vault")

    @property
    def broker_url(self) -> str:
        return f"http://{self.node_ip}:{self.broker_port}"

    def template_vars(self) -> dict[str, str]:
        """`${SITE_*}` variables available to deploy templates."""
        return {
            "SITE_NODE_IP": self.node_ip,
            "SITE_LAN_IP": self.lan_ip,
            "SITE_BASE_DOMAIN": self.base_domain,
            "SITE_TAILNET": self.tailnet_name,
            "SITE_CA_ADMIN_EMAIL": self.ca_admin_email,
            "SITE_BROKER_PORT": str(self.broker_port),
            "SITE_BROKER_URL": self.broker_url,
            "SITE_CA_URL": self.ca_url,
            "SITE_VAULT_URL": self.vault_url,
            "SITE_NS_CVC": self.namespaces.get("cvc", "cvc"),
            "SITE_NS_PKI": self.namespaces.get("pki", "pki"),
            "SITE_NS_AUTH": self.namespaces.get("auth", "auth"),
            "SITE_NTFY_HOST": f"ntfy.{self.base_domain}",
            "SITE_MQTT_USER": self.mqtt_username,
        }


GENERIC = Site()
_FIELDS = {f.name for f in fields(Site)} - {"source"}


def default_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "cvc" / "site.yaml"


def from_mapping(data: dict, source: str = "<mapping>") -> Site:
    if not isinstance(data, dict):
        raise SiteError(f"{source}: top level must be a mapping")
    unknown = sorted(set(data) - _FIELDS - {"tailnet"})
    if unknown:
        raise SiteError(f"{source}: unknown keys: {', '.join(unknown)}")
    kw = dict(data)
    if "tailnet" in kw:
        kw["tailnet_name"] = kw.pop("tailnet")
    owners = kw.get("default_owner_ids")
    if isinstance(owners, str):
        owners = [owners]
    if owners is not None:
        kw["default_owner_ids"] = tuple(str(o) for o in owners)
    if "namespaces" in kw:
        kw["namespaces"] = {**GENERIC.namespaces, **(kw["namespaces"] or {})}
    servers = kw.get("ntfy_servers")
    if isinstance(servers, str):
        servers = [u for u in servers.split(",")]
    if servers is not None:
        kw["ntfy_servers"] = tuple(str(u).strip() for u in servers if str(u).strip())
    if "ntfy_topics" in kw:
        topics = kw["ntfy_topics"] or {}
        if not isinstance(topics, dict):
            raise SiteError(f"{source}: ntfy_topics must be a mapping of person id -> topic")
        kw["ntfy_topics"] = {str(k): str(v) for k, v in topics.items()}
    for k in ("mqtt_host", "mqtt_username", "approval_card_url"):
        if k in kw:
            kw[k] = "" if kw[k] is None else str(kw[k])
    if "mqtt_port" in kw:
        kw["mqtt_port"] = int(kw["mqtt_port"])
    kw.setdefault("ca_url", "")
    kw.setdefault("vault_url", "")
    return replace(GENERIC, **kw, source=source)


def load(path: str | os.PathLike | None = None) -> Site:
    """Resolve the site config (see module docstring for lookup order)."""
    explicit = path or os.environ.get("CVC_SITE")
    p = Path(explicit) if explicit else default_path()
    if not p.is_file():
        if explicit:
            raise SiteError(f"site config not found: {p}")
        return GENERIC
    return from_mapping(yaml.safe_load(p.read_text(encoding="utf-8")) or {}, str(p))


def add_site_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--site", help="site.yaml (default: $CVC_SITE, then "
                                       "$XDG_CONFIG_HOME/cvc/site.yaml, then generic)")


def owners_or_default(explicit: list[str] | None, site: Site) -> list[str]:
    """Explicit ids, else the site's default owners; raises if neither is set."""
    if explicit:
        return list(explicit)
    if site.default_owner_ids:
        return list(site.default_owner_ids)
    raise SiteError("no owner given and the site config sets no default_owner_ids "
                    "(pass --owner/--granted-by or set default_owner_ids in site.yaml)")


_VAR = re.compile(r"\$\{(SITE_[A-Z_]+)\}")


def render(text: str, site: Site) -> str:
    """Replace `${SITE_*}` placeholders; any other `${...}` (shell vars) is left alone."""
    tv = site.template_vars()

    def sub(m: re.Match) -> str:
        if m.group(1) not in tv:
            raise SiteError(f"unknown template variable: {m.group(0)}")
        return tv[m.group(1)]
    return _VAR.sub(sub, text)


def render_tree(src: Path, out: Path, site: Site) -> list[Path]:
    """Copy `src` to `out`, rendering `${SITE_*}` in every text file. Returns written paths."""
    written = []
    for f in sorted(src.rglob("*")):
        if not f.is_file():
            continue
        dest = out / f.relative_to(src)
        dest.parent.mkdir(parents=True, exist_ok=True)
        data = f.read_bytes()
        try:
            dest.write_text(render(data.decode("utf-8"), site), encoding="utf-8")
        except UnicodeDecodeError:
            dest.write_bytes(data)
        dest.chmod(f.stat().st_mode & 0o777)
        written.append(dest)
    return written


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cvc-site", description="site config tools")
    add_site_arg(ap)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("show", help="print the resolved site config")
    r = sub.add_parser("render-deploy", help="render deploy/ templates with site values")
    r.add_argument("--src", default="deploy", help="template dir (default: %(default)s)")
    r.add_argument("--out", required=True, help="output dir (keep it outside the repo)")
    a = ap.parse_args(argv)
    try:
        site = load(a.site)
        if a.cmd == "show":
            print(f"# source: {site.source}")
            for k, v in site.template_vars().items():
                print(f"{k}={v}")
            print(f"DEFAULT_OWNER_IDS={','.join(site.default_owner_ids)}")
            return 0
        n = render_tree(Path(a.src), Path(a.out), site)
    except (SiteError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"rendered {len(n)} files from {a.src} to {a.out} (site: {site.source})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
