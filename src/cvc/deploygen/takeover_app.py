"""Takeover banner / status / FAQ API, served behind Traefik + cvc-tiergate (deploy/takeover).

Identity comes only from X-Cvc-Person, which cvc-tiergate sets via authResponseHeaders after
the strip middleware has removed any client-supplied copy. The banner shows only the caller's
own takeovers (unlike cvc.takeover.api's `?person=` banner, which trusts the query string).
Tier enforcement is per host at the gate: `takeover.<d>` (any tier) serves banner + FAQ,
`takeover-admin.<d>` (min tier owner, passkey) serves status.
"""
from __future__ import annotations

import os

from fastapi import FastAPI, Header, HTTPException

from cvc.takeover.api import STATES
from cvc.takeover.flow import banner_message
from cvc.takeover.model import Clock, TakeoverStore, utcnow

FAQ = [
    {"q": "What is a takeover?",
     "a": "A time-delayed request by a trusted person to gain access to your vault. You are "
          "notified daily and can cancel at any point before it completes."},
    {"q": "How do I cancel?", "a": "Run `cvc takeover cancel <id>` or contact the owner."},
    {"q": "Why can I see this banner?",
     "a": "Only the person a takeover targets sees its banner; status is owner-only."},
]


def create_app(store: TakeoverStore, clock: Clock = utcnow) -> FastAPI:
    app = FastAPI(title="cvc-takeover-api", docs_url=None, redoc_url=None, openapi_url=None)

    def _who(x_cvc_person: str | None) -> str:
        if not x_cvc_person:
            raise HTTPException(status_code=401, detail="no gate identity")
        return x_cvc_person

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    @app.get("/v1/takeover/faq")
    def faq() -> dict:
        return {"faq": FAQ}

    @app.get("/v1/takeover/banner")
    def banner(x_cvc_person: str | None = Header(default=None)) -> dict:
        person = _who(x_cvc_person)
        now = clock()
        items = [{"id": r.id, "initiator": r.initiator, "day": r.day(now),
                  "completes_on_day": r.wait_days, "state": STATES[r.phase(now)],
                  "message": banner_message(r, now)}
                 for r in store.all().values() if r.status == "pending" and r.target == person]
        return {"person": person, "active": bool(items), "takeovers": items}

    @app.get("/v1/takeover/status")
    def status(x_cvc_person: str | None = Header(default=None),
               x_cvc_tier: str | None = Header(default=None)) -> dict:
        _who(x_cvc_person)
        if x_cvc_tier != "owner":   # defence in depth; the gate host already requires owner
            raise HTTPException(status_code=403, detail="owner only")
        now = clock()
        return {"takeovers": [
            {"id": r.id, "initiator": r.initiator, "target": r.target, "path": r.path,
             "status": r.status, "initiated_at": r.initiated_at,
             "phase": r.phase(now) if r.status == "pending" else None}
            for r in store.all().values()]}

    return app


def main() -> None:
    import uvicorn

    store = TakeoverStore(os.environ.get("CVC_TAKEOVER_STATE", "/var/lib/cvc/takeover"))
    uvicorn.run(create_app(store), host=os.environ.get("CVC_TAKEOVER_HOST", "0.0.0.0"),
                port=int(os.environ.get("CVC_TAKEOVER_PORT", "8730")))
