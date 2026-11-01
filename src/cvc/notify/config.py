"""Notifier configuration from env (+ site defaults + registry people).

Env (tokens are env-only and never logged or stored in config objects):
  CVC_NTFY_SERVERS     comma list, in failover order, e.g.
                       "https://ntfy.example.com,https://ntfy.sh"  (option D primary, C fallback)
  CVC_NTFY_TOKEN_<n>   write-only access token for server n (1-based), read at send time
  CVC_NTFY_TOPICS      fallback per-person topic map "alex=cvc-alex-k3j9,sam=cvc-sam-p2x8"
                       (registry people.<id>.notify.ntfy_topic wins when present)
  CVC_DASHBOARD_URL    dashboard base (default https://dashboard.<site.base_domain>)
  CVC_APPROVAL_CARD_URL  card link template, default "{dashboard}/agents/approvals/{id}"
  CVC_NOTIFY_QUIET     quiet hours "HH:MM-HH:MM" local (default 22:00-07:00; "" = off)
  CVC_NOTIFY_TZ        IANA zone for quiet hours/digest (default: system local)
  CVC_NOTIFY_DIGEST_AT digest time "HH:MM" local (default 08:00)
  CVC_NOTIFY_STATE     state file (deferred queue, escalations, digest date)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import time

DEFAULT_QUIET = "22:00-07:00"
DEFAULT_STATE = "~/.local/state/cvc/notify.json"


@dataclass(frozen=True)
class Backend:
    url: str                 # ntfy server base URL
    token_env: str | None    # NAME of the env var holding the token (never the token)

    @property
    def name(self) -> str:   # log-safe label
        return self.token_env or "anon"

    def token(self) -> str | None:
        return os.environ.get(self.token_env) if self.token_env else None


def _hhmm(s: str) -> time:
    h, m = s.strip().split(":")
    return time(int(h), int(m))


def parse_quiet(spec: str | None) -> tuple[time, time] | None:
    if not spec or not spec.strip():
        return None
    a, b = spec.split("-")
    return _hhmm(a), _hhmm(b)


@dataclass
class NotifyConfig:
    backends: list[Backend]
    dashboard_url: str
    card_template: str = "{dashboard}/agents/approvals/{id}"
    topics: dict[str, str] = field(default_factory=dict)       # person id -> topic
    people: dict[str, dict] = field(default_factory=dict)      # registry people (raw)
    quiet: tuple[time, time] | None = field(default_factory=lambda: parse_quiet(DEFAULT_QUIET))
    tz: str | None = None
    digest_at: time = time(8, 0)
    state_path: str | None = None
    owner_ids: tuple[str, ...] = ()
    attempts: int = 2                                          # per backend

    def card_url(self, approval_id: str) -> str:
        return self.card_template.format(dashboard=self.dashboard_url.rstrip("/"),
                                         id=approval_id)

    def topic_for(self, person: str) -> str | None:
        p = self.people.get(person) or {}
        n = p.get("notify") if isinstance(p, dict) else None
        if isinstance(n, dict) and n.get("ntfy_topic"):
            return str(n["ntfy_topic"])
        return self.topics.get(person)

    @classmethod
    def from_env(cls, site=None, people: dict | None = None,
                 env: dict | None = None) -> NotifyConfig | None:
        """None when no ntfy server is configured (notifications disabled)."""
        env = os.environ if env is None else env
        urls = [u.strip() for u in env.get("CVC_NTFY_SERVERS", "").split(",") if u.strip()]
        if not urls:
            return None
        backends = [Backend(u, f"CVC_NTFY_TOKEN_{i}") for i, u in enumerate(urls, 1)]
        topics = dict(kv.split("=", 1) for kv in env.get("CVC_NTFY_TOPICS", "").split(",")
                      if "=" in kv)
        base = getattr(site, "base_domain", "cvc.example.ts.net")
        return cls(
            backends=backends,
            dashboard_url=env.get("CVC_DASHBOARD_URL") or f"https://dashboard.{base}",
            card_template=env.get("CVC_APPROVAL_CARD_URL") or cls.card_template,
            topics={k.strip(): v.strip() for k, v in topics.items()},
            people=dict(people or {}),
            quiet=parse_quiet(env.get("CVC_NOTIFY_QUIET", DEFAULT_QUIET)),
            tz=env.get("CVC_NOTIFY_TZ") or None,
            digest_at=_hhmm(env.get("CVC_NOTIFY_DIGEST_AT", "08:00")),
            state_path=env.get("CVC_NOTIFY_STATE") or DEFAULT_STATE,
            owner_ids=tuple(getattr(site, "default_owner_ids", ()) or ()),
        )
