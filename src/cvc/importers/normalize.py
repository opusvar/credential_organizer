"""Canonical credential item model + dedup. Pure/testable — no I/O, no secrets logged."""
from __future__ import annotations

from dataclasses import dataclass, field


def _norm_host(uri: str) -> str:
    """Best-effort host key for grouping: strip scheme, path, port, leading www."""
    s = uri.strip().lower()
    for scheme in ("https://", "http://"):
        if s.startswith(scheme):
            s = s[len(scheme):]
            break
    s = s.split("/", 1)[0].split("?", 1)[0]
    s = s.split(":", 1)[0]
    if s.startswith("www."):
        s = s[4:]
    return s


@dataclass(frozen=True)
class Item:
    """A normalized login credential from any source."""
    name: str
    username: str
    password: str
    uri: str = ""
    note: str = ""
    source: str = ""

    @property
    def dedup_key(self) -> tuple[str, str]:
        """Two items collide when they share the same host and username."""
        return (_norm_host(self.uri) if self.uri else self.name.strip().lower(),
                self.username.strip().lower())


@dataclass
class DedupResult:
    unique: list[Item] = field(default_factory=list)
    duplicates: list[Item] = field(default_factory=list)


def dedup(items: list[Item]) -> DedupResult:
    """Keep the first item per (host, username); collect the rest as duplicates.

    Order-preserving so the first occurrence (typically the primary source) wins.
    """
    seen: dict[tuple[str, str], Item] = {}
    res = DedupResult()
    for it in items:
        key = it.dedup_key
        if key in seen:
            res.duplicates.append(it)
        else:
            seen[key] = it
            res.unique.append(it)
    return res
