"""Mermaid auth graph: principal -> role -> system, as a Markdown document."""
from __future__ import annotations

import datetime as dt
import re

from cvc.access.builders import register_builder
from cvc.access.catalog import can_reach
from cvc.access.classify import effective, grant_labels
from cvc.access.model import Registry

SOON_DAYS = 30
MAX_LIST = 2

_ESC = {"#": "#35;", '"': "#quot;", "[": "#91;", "]": "#93;", "<": "#lt;", ">": "#gt;",
        "{": "#123;", "}": "#125;", "(": "#40;", ")": "#41;", "|": "#124;", "`": "#96;",
        ";": "#59;", "&": "#38;"}
_ESC_RE = re.compile("|".join(re.escape(c) for c in _ESC))

_CLASSDEFS = """\
    classDef enforced fill:#dbeafe,stroke:#1d4ed8,color:#0f172a,stroke-width:2px
    classDef unenforced fill:#f1f5f9,stroke:#64748b,color:#0f172a,stroke-dasharray:5 4
    classDef role fill:#ede9fe,stroke:#6d28d9,color:#0f172a
    classDef orphan fill:#fef9c3,stroke:#a16207,color:#0f172a,stroke-dasharray:2 3
    classDef principal fill:#dcfce7,stroke:#15803d,color:#0f172a
    classDef expired fill:#e5e7eb,stroke:#9ca3af,color:#6b7280,stroke-dasharray:3 3
    classDef person fill:#fce7f3,stroke:#be185d,color:#0f172a
    classDef hwkey fill:#fef3c7,stroke:#b45309,color:#0f172a
    classDef soon fill:#fed7aa,stroke:#c2410c,color:#0f172a,stroke-width:2px"""


def mermaid_label(text: object) -> str:
    """Escape registry text for use inside a quoted Mermaid label."""
    s = " ".join(str(text).split())
    return _ESC_RE.sub(lambda m: _ESC[m.group()], s)


def mermaid_id(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", text) or "_"


class _Ids:
    """Stable, unique, sanitized ids (assignment order = caller's sorted order)."""

    def __init__(self) -> None:
        self.map: dict[tuple[str, str], str] = {}
        self.used: set[str] = set()

    def get(self, prefix: str, key: str) -> str:
        k = (prefix, key)
        if k not in self.map:
            base = f"{prefix}_{mermaid_id(key)}"
            cand, n = base, 2
            while cand in self.used:
                cand, n = f"{base}_{n}", n + 1
            self.used.add(cand)
            self.map[k] = cand
        return self.map[k]


def _fmt_list(items: list[str], noun: str) -> str:
    items = sorted(set(items))
    return ", ".join(items) if len(items) <= MAX_LIST else f"{len(items)} {noun}"


def _edge_label(grants, kind: str) -> str:
    if kind == "credential-store":
        creds = {g.credential.lower() for g in grants}
        sentinels = sorted(c for c in creds if "-" not in c)
        purposes = [p for g in grants for p in g.purposes]
        head = f"{len(creds)} credential{'s' if len(creds) != 1 else ''}"
        if sentinels:
            head += f" ({', '.join(sentinels)})"
        return f"{head}: {_fmt_list(purposes, 'purposes')}"
    if kind == "mqtt":
        access = "/".join(sorted({g.access or "?" for g in grants}))
        return f"{access}: {_fmt_list([t for g in grants for t in g.topics], 'topics')}"
    return "documented only"


def _labels(data: str | None, action: str | None) -> str:
    return f"{data or '?'}/{action or '?'}" if (data or action) else ""


def _grant_labels(registry: Registry, grants) -> str:
    seen = sorted({_labels(*grant_labels(registry, g)) for g in grants} - {""})
    via = sorted({g.via for g in grants if g.via})
    return ", ".join(seen) + (f" via {', '.join(via)}" if via else "")


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")


@register_builder("graph")
def build_graph(registry: Registry, today: dt.date | None = None) -> str:
    today = today or dt.datetime.now().astimezone().date()
    ids = _Ids()
    soon_limit = today + dt.timedelta(days=SOON_DAYS)

    def status(p) -> str:
        if not p.active(today):
            return "expired"
        if p.expires and p.expires <= soon_limit:
            return "expiring soon"
        return "active"

    used_roles = {r for p in registry.principals() for r in p.roles}
    lines = ["flowchart LR"]
    classes: dict[str, list[str]] = {}

    def cls(name: str, nid: str) -> None:
        classes.setdefault(name, []).append(nid)

    def principal_nodes(title: str, sub: str, group: dict) -> None:
        lines.append(f'    subgraph {sub}["{title}"]')
        for pid in sorted(group):
            p = group[pid]
            nid = ids.get("p", pid)
            st = status(p)
            label = mermaid_label(pid)
            if st == "expired":
                label += "<br/>(expired)"
                cls("expired", nid)
            elif st == "expiring soon":
                label += f"<br/>expiring {p.expires.isoformat()}"
                cls("soon", nid)
            else:
                cls("principal", nid)
            if getattr(p, "tier", None):
                label += f"<br/>tier: {mermaid_label(p.tier)}"
                if group is registry.agents:
                    eff = effective(registry, p).row
                    if eff and eff != p.tier:
                        label += f" (effective {mermaid_label(eff)})"
            if not p.roles:
                label += "<br/>(no roles)"
            lines.append(f'        {nid}["{label}"]')
        lines.append("    end")

    principal_nodes("AI agents", "agents", registry.agents)
    principal_nodes("Machines / sensors", "machines", registry.machines)

    if registry.people:
        lines.append('    subgraph people["People"]')
        for uid in sorted(registry.people):
            nid = ids.get("u", uid)
            cls("person", nid)
            u = registry.people[uid]
            label = mermaid_label(uid)
            if u.name and u.name != uid:
                label = f"{mermaid_label(u.name)}<br/>({mermaid_label(uid)})"
            if u.tier:
                label += f"<br/>tier: {mermaid_label(u.tier)}"
            lines.append(f'        {nid}["{label}"]')
        lines.append("    end")
    if registry.hardware_keys:
        lines.append('    subgraph hwkeys["Hardware keys"]')
        for kid in sorted(registry.hardware_keys):
            k = registry.hardware_keys[kid]
            nid = ids.get("k", kid)
            label = f"{mermaid_label(kid)}<br/>{mermaid_label(k.location)}"
            if k.usable:
                cls("hwkey", nid)
            else:
                label += f"<br/>({mermaid_label(k.status)})"
                cls("expired", nid)
            lines.append(f'        {nid}["{label}"]')
        lines.append("    end")
    if registry.devices:
        lines.append('    subgraph devices["Devices"]')
        for did in sorted(registry.devices):
            d = registry.devices[did]
            nid = ids.get("p", did)
            c = d.cert
            label = f"{mermaid_label(did)}<br/>{mermaid_label(d.kind)}"
            label += (f"<br/>cert: {mermaid_label(c.status)} ({mermaid_label(c.storage)})"
                      if c else "<br/>(no cert)")
            soon = (c is not None and c.status == "active" and c.not_after is not None
                    and c.not_after <= soon_limit)
            if (c is not None and c.status in ("revoked", "expired")) or not d.active(today):
                cls("expired", nid)
            elif soon:
                cls("soon", nid)
                label += f"<br/>cert expiring {c.not_after.isoformat()}"
            else:
                cls("principal", nid)
            if not d.roles:
                label += "<br/>(no roles)"
            lines.append(f'        {nid}["{label}"]')
        lines.append("    end")

    lines.append('    subgraph roles["Roles"]')
    for rid in sorted(registry.roles):
        nid = ids.get("r", rid)
        label = mermaid_label(rid)
        if rid not in used_roles:
            label += "<br/>(unused by anyone)"
            cls("orphan", nid)
        else:
            cls("role", nid)
        lines.append(f'        {nid}["{label}"]')
    lines.append("    end")

    lines.append('    subgraph systems["Systems"]')
    for sid in sorted(registry.systems):
        s = registry.systems[sid]
        nid = ids.get("s", sid)
        label = f"{mermaid_label(sid)}<br/>{mermaid_label(s.kind)}"
        if s.data or s.action:
            label += f"<br/>{mermaid_label(_labels(s.data, s.action))}"
        if s.enforced:
            cls("enforced", nid)
            lines.append(f'        {nid}["{label}"]')
        else:
            cls("unenforced", nid)
            lines.append(f'        {nid}["{label}<br/>(not enforced)"]')
    lines.append("    end")

    for did in sorted(registry.devices):
        d = registry.devices[did]
        if d.owner in registry.people:
            lines.append(f"    {ids.get('u', d.owner)} --> {ids.get('p', did)}")
        if d.cert and d.cert.storage == "yubikey-piv" and d.cert.hardware_key:
            arrow = "-->" if d.cert.status in ("pending", "active") else "-.->"
            lines.append(f"    {ids.get('p', did)} {arrow} {ids.get('k', d.cert.hardware_key)}")
    for aid in sorted(registry.agents):
        sp = registry.agents[aid].sponsor_id
        if sp in registry.people:
            lines.append(f'    {ids.get("u", sp)} -.->|"sponsors"| {ids.get("p", aid)}')
    for group in (registry.agents, registry.machines, registry.devices):
        for pid in sorted(group):
            for rid in sorted(group[pid].roles):
                lines.append(f"    {ids.get('p', pid)} --> {ids.get('r', rid)}")
    for rid in sorted(registry.roles):
        by_sys: dict[str, list] = {}
        for g in registry.roles[rid].grants:
            by_sys.setdefault(g.system, []).append(g)
        for sid in sorted(by_sys):
            s = registry.systems[sid]
            text = _edge_label(by_sys[sid], s.kind)
            if lab := _grant_labels(registry, by_sys[sid]):
                text += f" [{lab}]"
            label = mermaid_label(text)
            arrow = "-->" if s.enforced else "-.->"
            lines.append(f'    {ids.get("r", rid)} {arrow}|"{label}"| {ids.get("s", sid)}')

    lines.append(_CLASSDEFS)
    for name in sorted(classes):
        lines.append(f"    class {','.join(classes[name])} {name}")

    out = ["# Access graph", "",
           f"Generated {today.isoformat()} by `cvc-access build graph` from the access registry.",
           "", "```mermaid", *lines, "```", "",
           ("Solid blue = enforced; dashed = documented only (not enforced); grey = expired; "
            "data/action labels (D16) are shown on systems and in brackets on grant edges; "
            "dotted 'sponsors' edges link a person to the agents they sponsor; "
           f"orange = expires within {SOON_DAYS} days; yellow dashed = unused role. "
           "Revoked certs and lost/revoked/retired hardware keys are grey. Cert serials and "
           "fingerprints are never shown."), "",
           "## Principals", "",
           "| id | type | tier | sponsor | roles | expires | status |",
           "|---|---|---|---|---|---|---|"]
    for sect, group in (("agent", registry.agents), ("machine", registry.machines),
                        ("device", registry.devices)):
        for pid in sorted(group):
            p = group[pid]
            tier = getattr(p, "tier", None) or "-"
            sponsor = "-"
            if sect == "agent":
                sponsor = p.sponsor_id or "-"
                eff = effective(registry, p).row
                if eff and eff != p.tier:
                    tier += f" (effective {eff})"
            out.append(f"| {_cell(pid)} | {sect} | {_cell(tier)} | {_cell(sponsor)} | "
                       f"{_cell(', '.join(sorted(p.roles)) or '-')} | "
                       f"{p.expires.isoformat() if p.expires else '-'} | {status(p)} |")
    if registry.people:
        out += ["", "## People", "", "| id | tier | tailnet | ha | expires | granted by |",
                "|---|---|---|---|---|---|"]
        for uid in sorted(registry.people):
            u = registry.people[uid]
            out.append(f"| {_cell(uid)} | {_cell(u.tier or '-')} | {_cell(u.tailnet or '-')} | "
                       f"{_cell(u.ha)} | {u.expires.isoformat() if u.expires else '-'} | "
                       f"{_cell(u.granted_by or '-')} |")
    if registry.devices:
        out += ["", "## Devices", "", ("| id | owner | kind | cert storage | cert status | "
                 "cert not after | history entries |"), "|---|---|---|---|---|---|---|"]
        for did in sorted(registry.devices):
            d = registry.devices[did]
            c = d.cert
            out.append(f"| {_cell(did)} | {_cell(d.owner)} | {_cell(d.kind)} | "
                       f"{_cell(c.storage) if c else '-'} | "
                       f"{_cell(c.status) if c else 'no cert'} | "
                       f"{c.not_after.isoformat() if c and c.not_after else '-'} | "
                       f"{len(d.history)} |")
    if registry.hardware_keys:
        on_key: dict[str, int] = {}
        for d in registry.devices.values():
            if d.cert and d.cert.hardware_key and d.cert.status in ("pending", "active"):
                on_key[d.cert.hardware_key] = on_key.get(d.cert.hardware_key, 0) + 1
        out += ["", "## Hardware keys", "", ("| id | owner | model | uses | location | status | "
                 "device certs |"), "|---|---|---|---|---|---|---|"]
        for kid in sorted(registry.hardware_keys):
            k = registry.hardware_keys[kid]
            out.append(f"| {_cell(kid)} | {_cell(k.owner)} | {_cell(k.model)} | "
                       f"{_cell(', '.join(k.uses))} | {_cell(k.location)} | {_cell(k.status)} | "
                       f"{on_key.get(kid, 0)} |")
    if registry.resources:
        out += ["", "## Resources", "",
                "| id | name | host | kind | min tier | ha level | passkey |",
                "|---|---|---|---|---|---|---|"]
        for rid in sorted(registry.resources):
            r = registry.resources[rid]
            out.append(f"| {_cell(rid)} | {_cell(r.name)} | {_cell(r.host)} | {_cell(r.kind)} | "
                       f"{_cell(r.min_tier)} | {_cell(r.ha_level or '-')} | "
                       f"{'yes' if r.passkey_required else 'no'} |")
        if registry.people:
            rids = sorted(registry.resources)
            out += ["", "## What each person can reach", "",
                    ("Same rule as the tier gate: active person, tier >= resource min tier. "
                     "`yes*` = passkey (Authentik) also required."), "",
                    "| person | tier | " + " | ".join(_cell(r) for r in rids) + " |",
                    "|---|---|" + "---|" * len(rids)]
            for uid in sorted(registry.people):
                u = registry.people[uid]
                cells = []
                for rid in rids:
                    r = registry.resources[rid]
                    ok = can_reach(u, r, today)
                    cells.append(("yes*" if r.passkey_required else "yes") if ok else "-")
                tier = u.tier or "-"
                if u.expires is not None and today > u.expires:
                    tier += " (expired)"
                out.append(f"| {_cell(uid)} | {_cell(tier)} | " + " | ".join(cells) + " |")
    out += ["", "## Systems", "", "| id | kind | data | action | enforced |",
            "|---|---|---|---|---|"]
    for sid in sorted(registry.systems):
        s = registry.systems[sid]
        out.append(f"| {_cell(sid)} | {_cell(s.kind)} | {_cell(s.data or '-')} | "
                   f"{_cell(s.action or '-')} | {'yes' if s.enforced else 'no'} |")
    return "\n".join(out) + "\n"
