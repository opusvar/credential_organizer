#!/usr/bin/env python3
"""Inventory third-party licenses for cvc (offline, via importlib.metadata).

Walks the dependency closure of everything declared in pyproject.toml
(runtime deps, optional extras such as [estate], and the [dev] extra),
classifies each license against the policy below, and writes:

  THIRD_PARTY_LICENSES.md   human-readable table + hand-maintained services section
  licenses.json             machine-readable inventory

Usage:
  python scripts/license_inventory.py            # regenerate both files
  python scripts/license_inventory.py --check    # exit 1 on denied/unknown runtime deps

No network access. Packages that are declared but not installed are listed
as "not installed" so the gap is visible rather than silently dropped.
See docs/LICENSING.md for the policy rationale.
"""

from __future__ import annotations

import argparse
import importlib.metadata as md
import json
import re
import sys
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
MD_OUT = ROOT / "THIRD_PARTY_LICENSES.md"
JSON_OUT = ROOT / "licenses.json"

# --------------------------------------------------------------------------- policy

ALLOW = "allow"
REVIEW = "review"
DENY = "deny"
_RANK = {ALLOW: 0, REVIEW: 1, DENY: 2}

# Order matters: first match wins, so specific patterns come before generic ones.
_POLICY_PATTERNS: list[tuple[str, str]] = [
    (r"\bAGPL|Affero", DENY),
    (r"\bSSPL|Server Side Public", DENY),
    (r"\bLGPL|Lesser General Public|Library General Public", REVIEW),
    (r"\bGPL|General Public License", DENY),
    (r"\bEPL|Eclipse Public", REVIEW),
    (r"\bEDL|Eclipse Distribution", ALLOW),  # EDL-1.0 is BSD-3-Clause text
    (r"\bMPL|Mozilla Public", ALLOW),  # file-level copyleft; OK unmodified
    (r"\bMIT\b|MIT License|\bMIT-", ALLOW),
    (r"\bBSD|0BSD", ALLOW),
    (r"\bApache|Apache Software License", ALLOW),
    (r"\bISC\b", ALLOW),
    (r"\bPSF|Python Software Foundation", ALLOW),
    (r"\bUnlicense|CC0|Public Domain", ALLOW),
]


def classify_single(lic: str) -> str:
    for pat, verdict in _POLICY_PATTERNS:
        if re.search(pat, lic, re.IGNORECASE):
            return verdict
    return DENY  # unknown == deny until a human looks


def classify(lic: str) -> str:
    """Classify an SPDX-ish expression. OR -> best option, AND -> worst."""
    lic = (lic or "").strip()
    if not lic or lic.upper() in {"UNKNOWN", "NONE"}:
        return DENY
    lic = lic.strip("()")
    if re.search(r"\sOR\s", lic):
        return min((classify(p) for p in re.split(r"\s+OR\s+", lic)), key=_RANK.get)
    if re.search(r"\sAND\s", lic):
        return max((classify(p) for p in re.split(r"\s+AND\s+", lic)), key=_RANK.get)
    return classify_single(lic)


# --------------------------------------------------------------------------- metadata


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _req_name(req: str) -> str | None:
    m = _REQ_NAME.match(req)
    return norm(m.group(1)) if m else None


def _marker_ok(req: str) -> bool:
    """True if the requirement applies here (skip extras; evaluate env markers)."""
    if ";" not in req:
        return True
    marker = req.split(";", 1)[1]
    if "extra" in marker:
        return False
    try:
        from packaging.markers import Marker

        return Marker(marker).evaluate()
    except (ImportError, ValueError, SyntaxError):  # packaging absent or odd marker: include conservatively
        return True


def _license_of(dist: md.Distribution) -> tuple[str, str]:
    meta = dist.metadata
    classifiers = [
        c.split("::")[-1].strip()
        for c in (meta.get_all("Classifier") or [])
        if c.startswith("License ::") and c.strip() != "License :: OSI Approved"
    ]
    lic = (meta.get("License-Expression") or "").strip()
    if not lic:
        raw = (meta.get("License") or "").strip()
        # Some packages paste the whole license text into License:; ignore that.
        if raw and "\n" not in raw and len(raw) < 80:
            lic = raw
    if not lic and classifiers:
        lic = " OR ".join(classifiers)
    return lic or "UNKNOWN", "; ".join(classifiers)


def _homepage(dist: md.Distribution) -> str:
    meta = dist.metadata
    if meta.get("Home-page"):
        return meta["Home-page"]
    urls = meta.get_all("Project-URL") or []
    for pref in ("homepage", "home", "source", "repository", "documentation"):
        for u in urls:
            label, _, url = u.partition(",")
            if label.strip().lower() == pref:
                return url.strip()
    return urls[0].partition(",")[2].strip() if urls else ""


@dataclass
class Pkg:
    name: str
    version: str
    license: str
    classifier: str
    homepage: str
    scope: str  # runtime | optional:<extra> | dev
    direct: bool
    verdict: str


def _declared() -> dict[str, list[str]]:
    proj = tomllib.loads(PYPROJECT.read_text())["project"]
    groups = {"runtime": list(proj.get("dependencies", []))}
    for extra, reqs in proj.get("optional-dependencies", {}).items():
        groups["dev" if extra == "dev" else f"optional:{extra}"] = list(reqs)
    return groups


def inventory() -> list[Pkg]:
    groups = _declared()
    seen: dict[str, Pkg] = {}
    # runtime first so a package shared with dev keeps the stricter scope
    order = ["runtime"] + sorted(g for g in groups if g.startswith("optional:")) + ["dev"]
    for scope in order:
        queue = [(n, True) for r in groups.get(scope, []) if (n := _req_name(r))]
        while queue:
            name, direct = queue.pop(0)
            if name in seen or name == "cvc":
                if name in seen and direct and seen[name].scope == scope:
                    seen[name].direct = True
                continue
            try:
                dist = md.distribution(name)
            except md.PackageNotFoundError:
                seen[name] = Pkg(name, "not installed", "UNKNOWN", "", "", scope, direct, DENY)
                continue
            lic, cls = _license_of(dist)
            seen[name] = Pkg(
                norm(dist.metadata["Name"]),
                dist.version,
                lic,
                cls,
                _homepage(dist),
                scope,
                direct,
                classify(lic),
            )
            for req in dist.requires or []:
                if _marker_ok(req) and (n := _req_name(req)):
                    queue.append((n, False))
    return sorted(seen.values(), key=lambda p: (order.index(p.scope), p.name))


# ------------------------------------------------------------ hand-maintained services
# Deployed alongside / used by cvc but NOT linked into it. Python-installed ones are
# re-verified from metadata at generation time; the rest are verified=False.

SERVICES = [
    # (name, license, how cvc uses it, pypi dist to verify from or None)
    ("Vaultwarden", "AGPL-3.0-only", "credential store; cvc talks to it over HTTP", None),
    ("Authentik", "MIT (core); enterprise/ dir under proprietary Authentik EE license",
     "SSO in front of the auth stack", None),
    ("step-ca (smallstep)", "Apache-2.0", "internal CA for tiergate client certs", None),
    ("Traefik", "MIT", "k3s ingress", None),
    ("k3s", "Apache-2.0", "container orchestration", None),
    ("Tailscale client", "BSD-3-Clause (client); control plane proprietary SaaS",
     "tailnet transport / identity", None),
    ("Home Assistant", "Apache-2.0", "reminder notifications via MQTT discovery", None),
    ("Eclipse Mosquitto", "EPL-2.0 OR EDL-1.0", "MQTT broker", None),
    ("yubikey-manager (ykman)", "BSD-2-Clause", "hardware-key enrollment tooling",
     "yubikey-manager"),
    ("segno", "BSD-3-Clause", "estate-kit QR codes (also a Python dep, [estate])", "segno"),
]


def services() -> list[dict]:
    out = []
    for name, lic, use, dist_name in SERVICES:
        verified = False
        note = "unverified: from upstream docs, not checked from installed metadata"
        if dist_name:
            try:
                dist = md.distribution(dist_name)
                meta_lic, _ = _license_of(dist)
                verified = True
                note = f"verified from installed metadata ({dist.version}: {meta_lic})"
            except md.PackageNotFoundError:
                note = "unverified: not installed here"
        out.append({"name": name, "license": lic, "use": use, "verified": verified,
                    "note": note, "verdict_if_linked": classify(lic.split(";")[0])})
    return out


# --------------------------------------------------------------------------- output


def render_md(pkgs: list[Pkg], svcs: list[dict]) -> str:
    lines = [
        "# Third-party licenses",
        "",
        "<!-- GENERATED by scripts/license_inventory.py; do not edit by hand. -->",
        "<!-- Regenerate: PYTHONPATH=src python scripts/license_inventory.py -->",
        "",
        ("Policy and rationale: [docs/LICENSING.md](docs/LICENSING.md). Verdicts: "
        "`allow` / `review` / `deny` (deny = must not be linked into a paid product; "
        "unknown counts as deny)."),
        "",
        ("Versions reflect the environment the file was generated in; transitive "
        "dependencies can vary by platform."),
        "",
        "## Python dependencies",
        "",
        "| Package | Version | License | Classifier | Homepage | Scope | Direct | Verdict |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for p in pkgs:
        lines.append(
            f"| {p.name} | {p.version} | {p.license} | {p.classifier or '-'} | "
            f"{p.homepage or '-'} | {p.scope} | {'yes' if p.direct else 'no'} | {p.verdict} |"
        )
    lines += [
        "",
        "## Deployed services and tools (not linked)",
        "",
        ("Hand-maintained in `SERVICES` in scripts/license_inventory.py. These run as "
        "separate processes/containers; cvc talks to them over the network or CLI. "
        "See docs/LICENSING.md for why that matters (esp. Vaultwarden / AGPL)."),
        "",
        "| Component | License | Used for | Verified |",
        "|---|---|---|---|",
    ]
    for s in svcs:
        lines.append(f"| {s['name']} | {s['license']} | {s['use']} | "
                     f"{'yes' if s['verified'] else 'NO'}: {s['note']} |")
    return "\n".join(lines) + "\n"


def problems(pkgs: list[Pkg]) -> list[Pkg]:
    """Runtime packages that are denied/unknown (optional/dev are reported, not failed)."""
    return [p for p in pkgs if p.scope == "runtime" and p.verdict == DENY]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail on denied runtime deps")
    args = ap.parse_args(argv)
    pkgs, svcs = inventory(), services()
    if args.check:
        bad = problems(pkgs)
        for p in bad:
            print(f"DENIED runtime dep: {p.name} {p.version} ({p.license})", file=sys.stderr)
        for p in pkgs:
            if p.verdict == REVIEW:
                print(f"review: {p.name} ({p.license}) [{p.scope}]", file=sys.stderr)
        return 1 if bad else 0
    MD_OUT.write_text(render_md(pkgs, svcs))
    JSON_OUT.write_text(json.dumps(
        {"packages": [asdict(p) for p in pkgs], "services": svcs}, indent=2) + "\n")
    print(f"wrote {MD_OUT.name} and {JSON_OUT.name} ({len(pkgs)} packages)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
