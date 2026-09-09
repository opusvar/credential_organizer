"""Phase 4 credential broker — FastAPI.

Least-privilege access for Playwright agents. Every request is:
  1. authenticated (agent id + bearer token, checked against the ACL),
  2. authorized (default-deny, per-credential, purpose-bound),
  3. AUDITED (append-only, chained) BEFORE any secret would be returned.

SCAFFOLD: the ACL + audit path is real; actual secret retrieval is stubbed (returns 501) until
the Phase-4 decisions in docs/DECISIONS.md (esp. D5 isolation) are settled and an Opus security
review is done. Do NOT wire real secret delivery before that review.

OpenAPI is served automatically at /openapi.json (Swagger UI /docs, ReDoc /redoc); export a
static copy with `make openapi` (writes docs/openapi.yaml).
"""
from __future__ import annotations

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .. import config
from .acl import Acl
from .audit import AuditEvent, AuditLog

app = FastAPI(
    title="cvc credential broker",
    version="0.0.0",
    description=(
        "Brokers least-privilege, purpose-bound, audited access to specific Vaultwarden "
        "credentials for automation agents. Default-deny. Every access is recorded before a "
        "secret is returned. SCAFFOLD: secret retrieval is not yet implemented."
    ),
    openapi_tags=[
        {"name": "credentials", "description": "Request a specific credential for a stated purpose."},
        {"name": "audit", "description": "Audit-log integrity."},
        {"name": "meta", "description": "Health and readiness."},
    ],
)


def _cfg() -> config.Config:
    return config.load()


def _acl() -> Acl:
    try:
        return Acl.load(_cfg().broker_acl)
    except FileNotFoundError:
        # No ACL file => nothing is permitted (fail closed).
        return Acl({})


def _audit() -> AuditLog:
    return AuditLog(_cfg().audit_log)


# ── models ───────────────────────────────────────────────────────────────────
class FetchRequest(BaseModel):
    credential: str = Field(..., description="Vault item name or id the agent needs.")
    purpose: str = Field(..., description="Why the agent needs it (bound + logged).")


class FetchResponse(BaseModel):
    credential: str
    granted: bool
    # NOTE: the secret is intentionally NOT in this schema yet. Delivery mechanism
    # (one-time token vs inline, TTL) is a Phase-4 decision pending security review.
    detail: str


# ── endpoints ────────────────────────────────────────────────────────────────
@app.get("/healthz", tags=["meta"], summary="Liveness probe")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/v1/audit/verify", tags=["audit"], summary="Verify audit-log integrity")
def audit_verify() -> dict:
    """Recompute the audit hash chain; `intact: false` means the log was altered/truncated."""
    return {"intact": _audit().verify()}


@app.post("/v1/credentials/fetch", response_model=FetchResponse, tags=["credentials"],
          summary="Fetch a credential (default-deny, audited)")
def fetch_credential(
    req: FetchRequest,
    x_agent_id: str = Header(..., description="Calling agent's id."),
    authorization: str = Header(..., description="Bearer <agent service token>."),
    acl: Acl = Depends(_acl),
    audit: AuditLog = Depends(_audit),
) -> FetchResponse:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=400, detail="Authorization header must use Bearer scheme")
    token = authorization.removeprefix("Bearer ").strip()

    # 1. Authenticate.
    if not acl.authenticate(x_agent_id, token):
        audit.record(AuditEvent(agent=x_agent_id, credential=req.credential,
                                purpose=req.purpose, outcome="deny:auth"))
        raise HTTPException(status_code=401, detail="authentication failed")

    # 2. Authorize (default-deny).
    decision = acl.authorize(x_agent_id, req.credential, req.purpose)
    if not decision.allowed:
        audit.record(AuditEvent(agent=x_agent_id, credential=req.credential,
                                purpose=req.purpose, outcome=f"deny:{decision.reason}"))
        raise HTTPException(status_code=403, detail=decision.reason)

    # 3. Audit the grant BEFORE any secret leaves the system.
    audit.record(AuditEvent(agent=x_agent_id, credential=req.credential,
                            purpose=req.purpose, outcome="allow"))

    # 4. Retrieve — stubbed until D5 + security review.
    raise HTTPException(
        status_code=501,
        detail="secret retrieval not implemented (pending D5 isolation + Opus security review)",
    )


def main() -> None:
    """`cvc-broker` entrypoint — run the broker with uvicorn."""
    import uvicorn

    cfg = config.load()
    uvicorn.run(app, host=cfg.broker_bind, port=cfg.broker_port)


if __name__ == "__main__":
    main()
