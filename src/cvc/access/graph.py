"""Mermaid auth graph: principal -> role -> system, as a Markdown document."""
from __future__ import annotations

import datetime as dt
import re

from cvc.access.builders import register_builder
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


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")


@register_builder("graph")
def build_graph(registry: Registry, today: dt.date | None = None) -> str:
    today = today or dt.date.today()
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
            if not p.roles:
                label += "<br/>(no roles)"
            lines.append(f'        {nid}["{label}"]')
        lines.append("    end")

    principal_nodes("AI agents", "agents", registry.agents)
    principal_nodes("Machines / sensors", "machines", registry.machines)

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
        if s.enforced:
            cls("enforced", nid)
            lines.append(f'        {nid}["{label}"]')
        else:
            cls("unenforced", nid)
            lines.append(f'        {nid}["{label}<br/>(not enforced)"]')
    lines.append("    end")

    for group in (registry.agents, registry.machines):
        for pid in sorted(group):
            for rid in sorted(group[pid].roles):
                lines.append(f"    {ids.get('p', pid)} --> {ids.get('r', rid)}")
    for rid in sorted(registry.roles):
        by_sys: dict[str, list] = {}
        for g in registry.roles[rid].grants:
            by_sys.setdefault(g.system, []).append(g)
        for sid in sorted(by_sys):
            s = registry.systems[sid]
            label = mermaid_label(_edge_label(by_sys[sid], s.kind))
            arrow = "-->" if s.enforced else "-.->"
            lines.append(f'    {ids.get("r", rid)} {arrow}|"{label}"| {ids.get("s", sid)}')

    lines.append(_CLASSDEFS)
    for name in sorted(classes):
        lines.append(f"    class {','.join(classes[name])} {name}")

    out = ["# Access graph", "",
           f"Generated {today.isoformat()} by `cvc-access build graph` from the access registry.",
           "", "```mermaid", *lines, "```", "",
           "Solid blue = enforced; dashed = documented only (not enforced); grey = expired; "
           f"orange = expires within {SOON_DAYS} days; yellow dashed = unused role.", "",
           "## Principals", "",
           "| id | type | roles | expires | status |", "|---|---|---|---|---|"]
    for sect, group in (("agent", registry.agents), ("machine", registry.machines)):
        for pid in sorted(group):
            p = group[pid]
            out.append(f"| {_cell(pid)} | {sect} | {_cell(', '.join(sorted(p.roles)) or '-')} | "
                       f"{p.expires.isoformat() if p.expires else '-'} | {status(p)} |")
    out += ["", "## Systems", "", "| id | kind | enforced |", "|---|---|---|"]
    for sid in sorted(registry.systems):
        s = registry.systems[sid]
        out.append(f"| {_cell(sid)} | {_cell(s.kind)} | {'yes' if s.enforced else 'no'} |")
    return "\n".join(out) + "\n"
