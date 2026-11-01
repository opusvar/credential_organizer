"""Takeover banner (target), status indicator (initiator) and FAQ endpoints (D15).

Not wired into the broker app and UNAUTHENTICATED: mount the router only behind the tier gate.
"""
from __future__ import annotations

from importlib.resources import files

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from cvc.takeover.flow import banner_message, status_items
from cvc.takeover.model import Clock, TakeoverStore, utcnow

STATES = {"requested": "takeover request in progress", "viewer": "viewer access granted",
          "completable": "takeover can be completed"}


def faq_text() -> str:
    return files("cvc.takeover").joinpath("faq.md").read_text(encoding="utf-8")


def make_router(store: TakeoverStore, clock: Clock = utcnow) -> APIRouter:
    router = APIRouter()

    @router.get("/v1/takeover/banner")
    def banner(person: str) -> dict:
        now = clock()
        items = [{"id": r.id, "initiator": r.initiator, "path": r.path, "factor": r.factor,
                  "day": r.day(now), "completes_on_day": r.wait_days,
                  "completes_on": r.deadline.date().isoformat(), "phase": r.phase(now),
                  "state": STATES[r.phase(now)], "message": banner_message(r, now)}
                 for r in store.all().values() if r.status == "pending" and r.target == person]
        return {"person": person, "active": bool(items), "takeovers": items}

    @router.get("/v1/takeover/status")
    def status(initiator: str) -> dict:
        items = status_items(store, initiator, clock())
        return {"initiator": initiator, "active": bool(items), "items": items}

    @router.get("/v1/takeover/faq", response_class=PlainTextResponse)
    def faq() -> str:
        return faq_text()

    return router
