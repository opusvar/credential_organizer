"""Banner endpoint for pending takeovers (D15). Not wired into the broker app; mount the router
behind the tier gate wherever the banner should show."""
from __future__ import annotations

from fastapi import APIRouter

from cvc.takeover.flow import banner_message
from cvc.takeover.model import Clock, TakeoverStore, utcnow

STATES = {"requested": "takeover request in progress", "viewer": "viewer access granted",
          "completable": "takeover can be completed"}


def make_router(store: TakeoverStore, clock: Clock = utcnow) -> APIRouter:
    router = APIRouter()

    @router.get("/v1/takeover/banner")
    def banner(person: str) -> dict:
        now = clock()
        items = [{"id": r.id, "initiator": r.initiator, "path": r.path, "day": r.day(now),
                  "completes_on_day": r.wait_days, "phase": r.phase(now),
                  "state": STATES[r.phase(now)], "message": banner_message(r, now)}
                 for r in store.all().values() if r.status == "pending" and r.target == person]
        return {"person": person, "active": bool(items), "takeovers": items}

    return router
