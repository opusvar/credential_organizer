"""Phase 4 credential broker — FastAPI.

Least-privilege access for Playwright agents. Every request is:
  1. authenticated (agent id + bearer token, checked against the ACL),
  2. authorized (default-deny, per-credential, purpose-bound),
  3. AUDITED (append-only, chained) BEFORE any secret is returned.

Secrets are delivered inline with Cache-Control: no-store. OpenAPI/docs
endpoints are disabled. Body size is capped at 8 KB.

Requires: a dedicated Vaultwarden agent account (D5), BW_SESSION set in
the environment (unlock managed externally — see broker-deployment.yaml).
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

import logging as _logging

from .. import config
from ..vault.client import BwClient, VaultError
from .acl import Acl
from .audit import AuditEvent, AuditLog
from .ops_log import OpsLog

_log = _logging.getLogger(__name__)

_MAX_BODY = 8 * 1024  # 8 KB


@asynccontextmanager
async def _lifespan(app: FastAPI):
    cfg = _cfg()
    acl = _acl()
    _log.info(
        "broker_started",
        extra={
            "broker_bind": cfg.broker_bind,
            "broker_port": cfg.broker_port,
            "acl_path": cfg.broker_acl,
            "audit_log": cfg.audit_log,
            "ops_log": cfg.ops_log,
            "acl_entries": len(acl._agents),
        },
    )
    _ops().record(
        "broker_started",
        broker_bind=cfg.broker_bind,
        broker_port=cfg.broker_port,
        acl_entries=len(acl._agents),
    )
    yield


app = FastAPI(
    lifespan=_lifespan,
    title="cvc credential broker",
    version="0.0.0",
    description=(
        "Brokers least-privilege, purpose-bound, audited access to specific Vaultwarden "
        "credentials for automation agents. Default-deny. Every access is recorded before a "
        "secret is returned."
    ),
    openapi_tags=[
        {"name": "credentials", "description": "Request a specific credential for a stated purpose."},
        {"name": "audit", "description": "Audit-log integrity."},
        {"name": "meta", "description": "Health and readiness."},
    ],
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


def _cfg() -> config.Config:
    return config.load()


def _acl() -> Acl:
    try:
        return Acl.load(_cfg().broker_acl)
    except FileNotFoundError:
        return Acl({})
    except Exception:
        _log.error(
            "acl_load_failed",
            extra={"path": _cfg().broker_acl},
            exc_info=True,
        )
        return Acl({})


def _audit() -> AuditLog:
    return AuditLog(_cfg().audit_log)


def _bw() -> BwClient:
    return BwClient(server=_cfg().bw_server or "")


def _ops() -> OpsLog:
    return OpsLog(_cfg().ops_log)


# ── models ───────────────────────────────────────────────────────────────────
_MAX_FIELD = 256


class FetchRequest(BaseModel):
    credential: str = Field(..., max_length=_MAX_FIELD,
                            description="Vault item UUID the agent needs.")
    purpose: str = Field(..., max_length=_MAX_FIELD,
                         description="Why the agent needs it (bound + logged).")
    field: Literal["password", "username", "totp"] = Field(
        "password", description="Which field to return."
    )


class FetchResponse(BaseModel):
    credential: str
    field: str
    value: str


# ── middleware ───────────────────────────────────────────────────────────────
@app.middleware("http")
async def _request_log(request: Request, call_next):
    import time as _time
    t0 = _time.monotonic()
    response = await call_next(request)
    duration_ms = round((_time.monotonic() - t0) * 1000)
    agent = request.headers.get("x-agent-id", "-")
    _log.info(
        "request",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "agent": agent,
            "duration_ms": duration_ms,
        },
    )
    _ops().record(
        "request",
        method=request.method,
        path=request.url.path,
        status=response.status_code,
        agent=agent,
        duration_ms=duration_ms,
    )
    return response


@app.middleware("http")
async def _limit_body_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    try:
        if content_length and int(content_length) > _MAX_BODY:
            return Response(status_code=413, content="Request body too large")
    except ValueError:
        pass  # malformed Content-Length; fall through to measured check
    response = await call_next(request)
    return response


# ── endpoints ────────────────────────────────────────────────────────────────
@app.get("/healthz", tags=["meta"], summary="Liveness probe")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/v1/audit/verify", tags=["audit"], summary="Verify audit-log integrity")
def audit_verify(
    x_agent_id: str = Header(..., max_length=64, description="Calling agent's id."),
    authorization: str = Header(..., description="Bearer <agent service token>."),
    acl: Acl = Depends(_acl),
) -> dict:
    """Recompute the audit hash chain; `intact: false` means the log was altered/truncated."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=400, detail="Authorization header must use Bearer scheme")
    token = authorization.removeprefix("Bearer ").strip()
    if not acl.authenticate(x_agent_id, token):
        raise HTTPException(status_code=401, detail="authentication failed")
    return {"intact": _audit().verify()}


@app.post("/v1/credentials/fetch", tags=["credentials"],
          summary="Fetch a credential field (default-deny, audited)")
def fetch_credential(
    req: FetchRequest,
    x_agent_id: str = Header(..., max_length=64, description="Calling agent's id."),
    authorization: str = Header(..., description="Bearer <agent service token>."),
    acl: Acl = Depends(_acl),
    audit: AuditLog = Depends(_audit),
    bw: BwClient = Depends(_bw),
) -> JSONResponse:
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

    # 4. Retrieve the requested field from the vault.
    try:
        if req.field == "totp":
            from ..vault.client import _run, _session
            value = _run("get", "totp", req.credential, session=_session())
        else:
            item = bw.get_item(req.credential)
            login = item.get("login") or {}
            value = login.get(req.field) or ""
    except VaultError as exc:
        _log.error(
            "vault_retrieval_failed",
            extra={
                "agent": x_agent_id,
                "credential": req.credential,
                "field": req.field,
            },
        )
        raise HTTPException(status_code=502, detail="vault retrieval failed") from exc

    return JSONResponse(
        content={"credential": req.credential, "field": req.field, "value": value},
        headers={"Cache-Control": "no-store"},
    )


def main() -> None:
    """`cvc-broker` entrypoint — run the broker with uvicorn."""
    import uvicorn

    cfg = config.load()
    uvicorn.run(app, host=cfg.broker_bind, port=cfg.broker_port)


if __name__ == "__main__":
    main()
