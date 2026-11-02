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

import hashlib
import hmac
import json
import logging as _logging
import os
import re
import subprocess
import sys
import threading
import time
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from .. import config
from ..approvals import inspect as approvals_inspect
from ..approvals import model as approvals_model
from ..approvals.publisher import from_env as _approvals_publisher
from ..approvals.service import ApprovalService, DecideError
from ..escalation import EscalationError, EscalationRefused, EscalationStore
from ..escalation import evaluate as escalation_evaluate
from ..vault.client import BwClient, VaultError, _run, _session
from .acl import Acl
from .audit import AuditEvent, AuditLog
from .ops_log import OpsLog
from .tiers import ApprovalStore, SessionStore, SessionToken

_log = _logging.getLogger(__name__)

_MAX_BODY = 8 * 1024  # 8 KB

# Paths hit by kubelet probes — excluded from ops-log noise (see _request_log).
_PROBE_PATHS = frozenset({"/healthz", "/readyz"})

# /readyz TTL cache: readiness shells out to `bw status`, which forks a Node
# process and costs on the order of a second on this host. Caching keeps the
# probe cheap under the 200m CPU limit (see broker-deployment.yaml comment).
_READYZ_TTL = 25.0  # seconds; must stay below the probe periodSeconds so each probe is fresh-ish
_readyz_lock = threading.Lock()
_readyz_cache: tuple[float, bool, str] | None = None  # (monotonic_ts, ready, detail)
_readyz_last_reported: bool | None = None  # last (ready) value recorded to the ops log


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
    stop = threading.Event()
    t = threading.Thread(target=_sweep_loop, args=(stop,), daemon=True, name="approvals-sweep")
    t.start()
    yield
    stop.set()


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
        {"name": "backup", "description": "On-demand encrypted vault backup."},
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
    except Exception:  # noqa: BLE001 - any load failure is logged and treated as fail-closed
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


_SESSIONS = SessionStore()
_APPROVALS = ApprovalStore()


def _sessions() -> SessionStore:
    return _SESSIONS


def _approvals() -> ApprovalStore:
    return _APPROVALS


_APPROVAL_SVC: ApprovalService | None = None
_SWEEP_INTERVAL = 30.0


def _approval_service() -> ApprovalService:
    """D18 approvals: publishes to MQTT; state mirrored to CVC_APPROVALS_STATE if set."""
    global _APPROVAL_SVC
    if _APPROVAL_SVC is None:
        _APPROVAL_SVC = ApprovalService(publisher=_approvals_publisher(),
                                        state_path=os.environ.get("CVC_APPROVALS_STATE"))
        approvals_inspect.attach(_APPROVAL_SVC)
    return _APPROVAL_SVC


_ESCALATIONS: EscalationStore | None = None


def _escalations() -> EscalationStore:
    """D27 escalation store, sharing the approvals service. State: CVC_ESCALATIONS_STATE."""
    global _ESCALATIONS
    if _ESCALATIONS is None:
        _ESCALATIONS = EscalationStore(
            os.environ.get("CVC_ESCALATIONS_STATE", "/var/lib/cvc/escalations.json"),
            _approval_service())
    return _ESCALATIONS


def _inspector() -> approvals_inspect.Inspector:
    """ETag history/rejection log for the approval service (read-only debugging)."""
    return approvals_inspect.attach(_approval_service())


def _sweep_loop(stop: threading.Event) -> None:
    while not stop.wait(_SWEEP_INTERVAL):
        try:
            _approval_service().sweep()
        except Exception:  # noqa: BLE001 - the sweeper must never die
            _log.warning("approvals_sweep_failed", exc_info=True)


def _sync_approval(store: ApprovalStore, svc: ApprovalService, approval_id: str | None) -> None:
    """Pull a D18 decision (made via /decide, the CLI, or expiry) into the broker record."""
    if not approval_id:
        return
    r = svc.get(approval_id)
    if r is None:
        return
    if r.status == "approved":
        store.approve(approval_id, r.decided_by or "?")
    elif r.status in ("denied", "expired", "cancelled"):
        store.deny(approval_id, r.decided_by)


# Tier-gate identity headers are trusted only when the broker is deployed behind tier-gate
# (Traefik forwardAuth strips/overwrites them). Unset -> /decide, /whoami, /nonce refuse.
_TRUST_TIERGATE_ENV = "CVC_TRUST_TIERGATE"
# Browser origin of the personal dashboard allowed to call the human-facing endpoints.
_DASHBOARD_ORIGIN_ENV = "CVC_DASHBOARD_ORIGIN"
_HUMAN_PATHS = re.compile(
    r"^/v1/(whoami|approvals/nonce|approvals/diag|"
    r"approvals/[^/]+/(decide|request|etag|history))$")
# Networks /v1/whoami may be reached from (client IP via tier-gate/Traefik headers).
_TAILNET_CIDRS_ENV = "CVC_TAILNET_CIDRS"
_DEFAULT_TAILNET_CIDRS = "100.64.0.0/10"
_NONCE_TTL = 300.0


class _NonceStore:
    """Single-use, person-bound, short-lived nonces (one per decision; anti-CSRF/replay)."""

    def __init__(self, clock=time.monotonic):
        self._clock, self._lock = clock, threading.Lock()
        self._items: dict[str, tuple[str, float]] = {}

    def issue(self, person: str) -> str:
        import secrets
        n = secrets.token_urlsafe(24)
        with self._lock:
            now = self._clock()
            for k in [k for k, (_, exp) in self._items.items() if exp <= now]:
                del self._items[k]
            self._items[n] = (person, now + _NONCE_TTL)
        return n

    def consume(self, nonce: str | None, person: str) -> bool:
        if not nonce:
            return False
        with self._lock:
            rec = self._items.pop(nonce, None)
        return rec is not None and rec[0] == person and rec[1] > self._clock()


_NONCES = _NonceStore()


def _nonces() -> _NonceStore:
    return _NONCES


def _tiergate_trusted() -> bool:
    return os.environ.get(_TRUST_TIERGATE_ENV, "").strip().lower() in ("1", "true", "yes")


def _require_tailnet_client(x_real_ip: str | None, x_forwarded_for: str | None) -> str:
    """Client IP (X-Real-Ip, else first X-Forwarded-For hop — set by Traefik and trusted only
    behind tier-gate) must fall inside CVC_TAILNET_CIDRS (default 100.64.0.0/10)."""
    import ipaddress
    if not _tiergate_trusted():
        raise HTTPException(status_code=403,
                            detail="tier-gate identity not trusted on this deployment")
    raw = (x_real_ip or (x_forwarded_for or "").split(",")[0]).strip()
    try:
        ip = ipaddress.ip_address(raw)
        nets = [ipaddress.ip_network(c.strip(), strict=False) for c in
                os.environ.get(_TAILNET_CIDRS_ENV, _DEFAULT_TAILNET_CIDRS).split(",")
                if c.strip()]
    except ValueError:
        raise HTTPException(status_code=403, detail="client address unknown") from None
    if not any(ip in n for n in nets):
        raise HTTPException(status_code=403, detail="only reachable on the tailnet")
    return raw


def _parse_if_match(if_match: str | None, approval_id: str) -> int:
    """If-Match: "<id>.v<version>" -> version. Missing -> 428, foreign/garbled -> 412."""
    if not if_match:
        raise HTTPException(status_code=428, detail="If-Match (approval ETag) required")
    tag = if_match.strip().removeprefix("W/").strip('"')
    ident, _, ver = tag.rpartition(".v")
    if ident != approval_id or not ver.isdigit():
        raise HTTPException(status_code=412, detail="If-Match does not match this approval")
    return int(ver)


def _tiergate_identity(person: str | None, tier: str | None) -> tuple[str, str]:
    if not _tiergate_trusted():
        raise HTTPException(status_code=403,
                            detail="tier-gate identity not trusted on this deployment")
    if not person or not tier:
        raise HTTPException(status_code=401, detail="tier-gate identity headers missing")
    return person, tier


# sha256 of the human approver's token. Unset -> approvals cannot be granted (fail-closed).
_APPROVER_ENV = "CVC_APPROVER_TOKEN_SHA256"


def _bearer(authorization: str) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=400, detail="Authorization header must use Bearer scheme")
    return authorization.removeprefix("Bearer ").strip()


def _authn(acl: Acl, sessions: SessionStore, agent: str, token: str,
           enforce_session: bool = False) -> tuple[bool, SessionToken | None]:
    """Accept either the long-lived service token or an unexpired session token.

    With ``enforce_session`` and the agent opted in (acl.requires_session_token), the
    service token is rejected — it may then only be used to mint session tokens."""
    if acl.authenticate(agent, token):
        if enforce_session and acl.requires_session_token(agent):
            return False, None
        return True, None
    rec = sessions.resolve(agent, token)
    return (rec is not None), rec


def _obo(acl: Acl, agent: str) -> str | None:
    """Dual-attribution value for audit records (assistant tier only)."""
    return acl.on_behalf_of(agent) if acl.tier(agent) == "assistant" else None


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


class IssueRequest(BaseModel):
    credentials: list[str] = Field(..., max_length=32,
                                   description="Credentials the session token is scoped to.")
    ttl: int | None = Field(None, ge=1, description="Requested TTL (capped by tier).")


class ApprovalRequest(BaseModel):
    credential: str = Field(..., max_length=_MAX_FIELD)
    purpose: str = Field(..., max_length=_MAX_FIELD)


class ApprovalCreate(BaseModel):
    """D18 approval request body. Only credential/purpose are required (legacy clients)."""
    credential: str = Field(..., max_length=_MAX_FIELD)
    purpose: str = Field(..., max_length=_MAX_FIELD)
    intent: str | None = Field(None, max_length=512)
    summary: str | None = Field(None, max_length=512)
    if_approved: str | None = Field(None, max_length=512)
    if_denied: str | None = Field(None, max_length=512)
    urgency: Literal["low", "normal", "urgent"] = "normal"
    deadline_s: int = Field(15 * 60, ge=1, le=24 * 3600,
                            description="Seconds until timeout (deny). Default 15 min, max 24h.")
    details_url: str | None = Field(None, max_length=512)
    data: Literal["public", "internal", "private", "secret"] | None = None
    action: Literal["read", "relay", "write", "act", "delegate"] | None = None


class DecideBody(BaseModel):
    decision: Literal["approve", "deny"]
    nonce: str = Field(..., min_length=8, max_length=128,
                       description="Single-use nonce from GET /v1/approvals/nonce.")


class ApproveRequest(BaseModel):
    approver: str = Field(..., min_length=1, max_length=64,
                          description="Human approver name (recorded).")


class TriggerRequest(BaseModel):
    purpose: str = Field(..., max_length=_MAX_FIELD,
                         description="Why the backup is being triggered (bound + logged).")


# The ACL credential sentinel gating /v1/backup/trigger. Not a vault UUID — see
# acl._SENTINEL_CREDENTIALS. Kept as a named constant so the endpoint, the audit record
# and deploy/broker-acl.yaml cannot drift apart.
_BACKUP_CAPABILITY = "backup"

# `cvc-backup` shells out to `bw login`/`unlock`/`export`; Phase 4 measured a single
# credential fetch at ~15s on this host, so a whole-vault export runs in minutes. The cap
# is a guard against a wedged `bw`, not an expected duration.
_BACKUP_TIMEOUT = 600
# Single-flight guard: one backup at a time (each holds a worker for minutes).
_backup_lock = threading.Lock()
_STDERR_TAIL = 500
_SECRET_LINE = re.compile(r"password|passwd|session|token|secret|key|bearer|authorization",
                          re.IGNORECASE)


def _redacted_stderr_tail(stderr: str | None) -> str:
    """Bounded tail of child stderr with any secret-looking line dropped."""
    if not stderr:
        return ""
    lines = [ln for ln in stderr.splitlines()[-20:] if not _SECRET_LINE.search(ln)]
    return "\n".join(lines)[-_STDERR_TAIL:]


# ── middleware ───────────────────────────────────────────────────────────────
@app.middleware("http")
async def _dashboard_cors(request: Request, call_next):
    """CORS + Origin check for the human-facing endpoints only (dashboard, D18).

    A request carrying an Origin must match CVC_DASHBOARD_ORIGIN exactly (unset -> any
    browser origin is refused). /decide must be application/json (no simple-request CSRF).
    """
    path = request.url.path
    if not _HUMAN_PATHS.match(path):
        return await call_next(request)
    allowed = os.environ.get(_DASHBOARD_ORIGIN_ENV, "").strip().rstrip("/")
    origin = request.headers.get("origin")
    if origin is not None and (not allowed or origin.rstrip("/") != allowed):
        return JSONResponse(status_code=403, content={"detail": "origin not allowed"})
    cors = {"Access-Control-Allow-Origin": allowed, "Vary": "Origin",
            "Access-Control-Allow-Credentials": "true"} if origin else {}
    if request.method == "OPTIONS":
        return Response(status_code=204, headers={
            **cors, "Access-Control-Allow-Methods": "GET, POST",
            "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Max-Age": "600"})
    if request.method == "POST":
        ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype != "application/json":
            return JSONResponse(status_code=415, content={"detail": "JSON only"})
    response = await call_next(request)
    for k, v in cors.items():
        response.headers[k] = v
    return response


@app.middleware("http")
async def _request_log(request: Request, call_next):
    import time as _time
    t0 = _time.monotonic()
    response = await call_next(request)
    duration_ms = round((_time.monotonic() - t0) * 1000)
    agent = request.headers.get("x-agent-id", "-")
    path = request.url.path
    # Liveness (/healthz) and readiness (/readyz) are polled continuously by
    # kubelet — logging every probe at info level / recording it to ops.jsonl
    # would drown out real traffic and grow the ops log forever. Downgrade to
    # debug and skip the ops record for those two paths only.
    log_fn = _log.debug if path in _PROBE_PATHS else _log.info
    log_fn(
        "request",
        extra={
            "method": request.method,
            "path": path,
            "status": response.status_code,
            "agent": agent,
            "duration_ms": duration_ms,
        },
    )
    if path not in _PROBE_PATHS:
        _ops().record(
            "request",
            method=request.method,
            path=path,
            status=response.status_code,
            agent=agent,
            duration_ms=duration_ms,
        )
    return response


@app.middleware("http")
async def _limit_body_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    measured = content_length is None
    if content_length is not None:
        try:
            if int(content_length) > _MAX_BODY:
                return Response(status_code=413, content="Request body too large")
        except ValueError:
            measured = True  # malformed Content-Length: don't trust it, measure instead
    if measured:
        # No usable Content-Length (e.g. chunked): read incrementally, abort past the
        # limit (never buffering more than _MAX_BODY + one chunk), then replay the body.
        chunks: list[bytes] = []
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > _MAX_BODY:
                return Response(status_code=413, content="Request body too large")
            chunks.append(chunk)
        # Starlette's cached request replays `_body` to the downstream app.
        request._body = b"".join(chunks)
    response = await call_next(request)
    return response


def _vault_ready() -> tuple[bool, str]:
    """Return (ready, detail). Calls `bw status` at most once per _READYZ_TTL seconds."""
    global _readyz_cache
    now = time.monotonic()
    with _readyz_lock:
        cached = _readyz_cache
        if cached is not None and now - cached[0] < _READYZ_TTL:
            return cached[1], cached[2]

    # Cache miss (or expired) — probe outside the lock so a slow `bw` invocation
    # doesn't block other requests from reading the cache. Two concurrent
    # misses may both probe; that's acceptable.
    try:
        try:
            session = _session()
        except VaultError:
            ready, detail = False, "session-missing"
        else:
            raw = _run("status", session=session)
            status = json.loads(raw).get("status")
            if status == "unlocked":
                ready, detail = True, "unlocked"
            elif status in ("locked", "unauthenticated"):
                ready, detail = False, status
            else:
                ready, detail = False, "status-unparseable"
    except VaultError:
        ready, detail = False, "vault-unreachable"
    except (json.JSONDecodeError, TypeError, AttributeError):
        ready, detail = False, "status-unparseable"
    except Exception:  # noqa: BLE001 - probe must never 500
        # A readiness probe must never return a 500 — map anything unexpected
        # (never the session key, server URL, or vault contents) to a fixed token.
        ready, detail = False, "probe-failed"

    with _readyz_lock:
        _readyz_cache = (time.monotonic(), ready, detail)
    return ready, detail


# ── endpoints ────────────────────────────────────────────────────────────────
@app.get("/healthz", tags=["meta"], summary="Liveness probe")
def healthz() -> dict:
    # Deliberately does not touch the vault: a dead vault session must not
    # trigger a container restart loop via the liveness probe — that is the
    # readiness probe's job (see /readyz below).
    return {"status": "ok"}


@app.get("/readyz", tags=["meta"], summary="Readiness probe — verifies the vault session is live")
def readyz() -> JSONResponse:
    """No authentication — the kubelet cannot present credentials.

    200 `{"status": "ready", "vault": "unlocked"}` when the vault session is unlocked;
    503 `{"status": "not ready", "vault": "<detail>"}` otherwise. Result is cached for
    up to `_READYZ_TTL` seconds so repeated probing does not shell out to `bw` every
    request.
    """
    global _readyz_last_reported
    ready, detail = _vault_ready()

    with _readyz_lock:
        changed = _readyz_last_reported != ready
        _readyz_last_reported = ready
    if changed:
        _ops().record("readiness_changed", ready=ready, vault=detail)

    if ready:
        return JSONResponse(
            content={"status": "ready", "vault": detail},
            headers={"Cache-Control": "no-store"},
        )
    return JSONResponse(
        status_code=503,
        content={"status": "not ready", "vault": detail},
        headers={"Cache-Control": "no-store"},
    )


@app.get("/v1/audit/verify", tags=["audit"], summary="Verify audit-log integrity")
def audit_verify(
    x_agent_id: str = Header(..., max_length=64, description="Calling agent's id."),
    authorization: str = Header(..., description="Bearer <agent service token>."),
    acl: Acl = Depends(_acl),  # noqa: B008 - FastAPI dependency-injection idiom
    sessions: SessionStore = Depends(_sessions),  # noqa: B008
) -> dict:
    """Recompute the audit hash chain; `intact: false` means the log was altered/truncated."""
    token = _bearer(authorization)
    if not _authn(acl, sessions, x_agent_id, token)[0]:
        raise HTTPException(status_code=401, detail="authentication failed")
    return {"intact": _audit().verify()}


@app.post("/v1/credentials/fetch", tags=["credentials"],
          summary="Fetch a credential field (default-deny, audited)")
def fetch_credential(
    req: FetchRequest,
    x_agent_id: str = Header(..., max_length=64, description="Calling agent's id."),
    authorization: str = Header(..., description="Bearer <agent service token>."),
    acl: Acl = Depends(_acl),  # noqa: B008 - FastAPI dependency-injection idiom
    audit: AuditLog = Depends(_audit),  # noqa: B008 - FastAPI dependency-injection idiom
    bw: BwClient = Depends(_bw),  # noqa: B008 - FastAPI dependency-injection idiom
    sessions: SessionStore = Depends(_sessions),  # noqa: B008
    approvals: ApprovalStore = Depends(_approvals),  # noqa: B008
    x_approval_id: str | None = Header(None, max_length=64,
                                       description="Approved approval id (tier high, physical)."),
    x_escalation_id: str | None = Header(None, max_length=64,
                                         description="D27 approved escalation id."),
    x_escalation_nonce: str | None = Header(None, max_length=128,
                                            description="Nonce returned with the escalation."),
    escalations: EscalationStore = Depends(_escalations),  # noqa: B008
) -> JSONResponse:
    token = _bearer(authorization)
    obo = _obo(acl, x_agent_id)

    def _deny(status: int, reason: str, outcome: str | None = None):
        audit.record(AuditEvent(agent=x_agent_id, credential=req.credential,
                                purpose=req.purpose, outcome=outcome or f"deny:{reason}",
                                on_behalf_of=obo))
        raise HTTPException(status_code=status, detail=reason)

    # 0. D27 escalation: a single-use grant replaces the ACL/tier checks for this one
    #    fetch. It is bound to the agent's service token, the exact credential and the nonce.
    if x_escalation_id is not None:
        if not acl.authenticate(x_agent_id, token):
            _deny(401, "authentication failed", "deny:auth")
        try:
            esc = escalations.consume(x_escalation_id, agent=x_agent_id, token=token,
                                      resource=f"credential:{req.credential.lower()}",
                                      nonce=x_escalation_nonce, action="read")
        except EscalationError as e:
            _deny(403, e.reason, f"deny:escalation:{e.code}")
        obo = esc.on_behalf_of or obo
        audit.record(AuditEvent(agent=x_agent_id, credential=req.credential,
                                purpose=req.purpose, outcome=f"allow:escalation:{esc.id}",
                                on_behalf_of=obo))
    else:
        # 1. Authenticate (service token or short-lived session token).
        ok, session = _authn(acl, sessions, x_agent_id, token, enforce_session=True)
        if not ok:
            _deny(401, "authentication failed", "deny:auth")
        if session is not None and req.credential.lower() not in session.scope:
            _deny(403, "credential outside session token scope")

        # 2. Authorize (default-deny).
        decision = acl.authorize(x_agent_id, req.credential, req.purpose)
        if not decision.allowed:
            _deny(403, decision.reason)
        _tier_checks(acl, approvals, x_agent_id, req, obo, x_approval_id, _deny)
        # 3. Audit the grant BEFORE any secret leaves the system.
        audit.record(AuditEvent(agent=x_agent_id, credential=req.credential,
                                purpose=req.purpose, outcome="allow", on_behalf_of=obo))
    return _deliver(req, x_agent_id, bw)


def _tier_checks(acl, approvals, x_agent_id, req, obo, x_approval_id, _deny) -> None:
    # 2b. Tier enforcement.
    tier = acl.tier(x_agent_id)
    if tier == "assistant" and not obo:
        _deny(403, "assistant tier requires on_behalf_of in ACL")
    if tier == "high" and acl.is_physical(x_agent_id, req.credential):
        _sync_approval(approvals, _approval_service(), x_approval_id)
    if (tier == "high" and acl.is_physical(x_agent_id, req.credential)
            and not approvals.consume(x_approval_id, x_agent_id, req.credential, req.purpose)):
        _deny(403, "physical action requires human approval")


def _deliver(req: FetchRequest, x_agent_id: str, bw: BwClient) -> JSONResponse:
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


@app.post("/v1/backup/trigger", tags=["backup"],
          summary="Run the encrypted backup pipeline now (BLOCKING — minutes)")
def trigger_backup(
    req: TriggerRequest,
    x_agent_id: str = Header(..., max_length=64, description="Calling agent's id."),
    authorization: str = Header(..., description="Bearer <agent service token>."),
    acl: Acl = Depends(_acl),  # noqa: B008 - FastAPI dependency-injection idiom
    audit: AuditLog = Depends(_audit),  # noqa: B008 - FastAPI dependency-injection idiom
    cfg: config.Config = Depends(_cfg),  # noqa: B008 - FastAPI dependency-injection idiom
    sessions: SessionStore = Depends(_sessions),  # noqa: B008
) -> JSONResponse:
    """On-demand equivalent of the cvc-backup CronJob (D9).

    WARNING — THIS IS A BLOCKING CALL that takes MINUTES. `cvc-backup` performs a full
    `bw export` of the vault; on this ARM64 host under a 200m CPU limit that is minutes,
    not seconds. Callers MUST set a client timeout of 600s or more. The request occupies
    one of FastAPI's threadpool workers for its whole duration, so do not poll it.

    200 means the TRIGGER succeeded, not that the backup did — check `exit_code` (0 = the
    backup itself succeeded) and `log`. 403/401 are ACL/auth refusals, 503 means the
    subprocess could not be started at all, 504 means it exceeded the internal cap.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=400, detail="Authorization header must use Bearer scheme")
    token = authorization.removeprefix("Bearer ").strip()
    obo = _obo(acl, x_agent_id)

    # 1. Authenticate.
    ok, session = _authn(acl, sessions, x_agent_id, token, enforce_session=True)
    if ok and session is not None and _BACKUP_CAPABILITY not in session.scope:
        ok = False
    if not ok:
        audit.record(AuditEvent(agent=x_agent_id, credential=_BACKUP_CAPABILITY,
                                purpose=req.purpose, outcome="deny:auth", on_behalf_of=obo))
        raise HTTPException(status_code=401, detail="authentication failed")

    # 2. Authorize (default-deny) — the "backup" capability, not a vault item.
    decision = acl.authorize(x_agent_id, _BACKUP_CAPABILITY, req.purpose)
    if not decision.allowed:
        audit.record(AuditEvent(agent=x_agent_id, credential=_BACKUP_CAPABILITY,
                                purpose=req.purpose, outcome=f"deny:{decision.reason}",
                                on_behalf_of=obo))
        raise HTTPException(status_code=403, detail=decision.reason)
    if acl.tier(x_agent_id) == "assistant" and not obo:
        audit.record(AuditEvent(agent=x_agent_id, credential=_BACKUP_CAPABILITY,
                                purpose=req.purpose, outcome="deny:no on_behalf_of"))
        raise HTTPException(status_code=403, detail="assistant tier requires on_behalf_of in ACL")

    # 2b. Single-flight: refuse (and audit) a concurrent run instead of queueing workers.
    if not _backup_lock.acquire(blocking=False):
        audit.record(AuditEvent(agent=x_agent_id, credential=_BACKUP_CAPABILITY,
                                purpose=req.purpose, outcome="deny:busy", on_behalf_of=obo))
        raise HTTPException(status_code=409, detail="a backup is already in progress")
    try:
        return _run_backup(req, x_agent_id, audit, cfg, obo)
    finally:
        _backup_lock.release()


def _run_backup(req: TriggerRequest, x_agent_id: str, audit: AuditLog,
                cfg: config.Config, obo: str | None = None) -> JSONResponse:
    # 3. Audit the grant BEFORE the vault is touched, same invariant as a credential fetch.
    audit.record(AuditEvent(agent=x_agent_id, credential=_BACKUP_CAPABILITY,
                            purpose=req.purpose, outcome="allow", on_behalf_of=obo))

    # 4. Run the pipeline out-of-process. Deliberately NOT inline: `bw export` is a
    #    multi-minute blocking syscall that would stall the event loop, and a separate
    #    process means a wedged `bw` cannot take the broker down with it.
    try:
        result = subprocess.run(  # noqa: PLW1510
            [sys.executable, "-m", "cvc.backup"],
            capture_output=True,
            text=True,
            timeout=_BACKUP_TIMEOUT,
            env={**os.environ, "BACKUP_DIR": cfg.backup_dir},
        )
    except subprocess.TimeoutExpired as exc:
        _log.error("backup_trigger_timeout", extra={"agent": x_agent_id})
        raise HTTPException(
            status_code=504,
            detail=f"backup exceeded {_BACKUP_TIMEOUT}s and was killed",
        ) from exc
    except OSError as exc:
        # The subprocess never started (no interpreter, fork failure, ENOMEM).
        _log.error("backup_trigger_spawn_failed", extra={"agent": x_agent_id}, exc_info=True)
        raise HTTPException(status_code=503, detail="could not start backup") from exc

    if result.returncode != 0:
        _log.warning(
            "backup_trigger_failed exit_code=%s stderr_tail=%r",
            result.returncode, _redacted_stderr_tail(result.stderr),
        )

    _ops().record(
        "backup_triggered",
        agent=x_agent_id,
        purpose=req.purpose,
        exit_code=result.returncode,
    )

    # stdout is truncated to the tail: it holds the export path and prune count, and an
    # unbounded child log must not become an unbounded HTTP response. stderr is NOT
    # returned — it can carry `bw` diagnostics; it goes to the broker's own log instead.
    return JSONResponse(
        content={
            "triggered": True,
            "exit_code": result.returncode,
            "log": result.stdout[-2000:],
            "note": "blocking call — completed synchronously; use a 600s+ client timeout",
        },
        headers={"Cache-Control": "no-store"},
    )


@app.post("/v1/tokens/issue", tags=["credentials"],
          summary="Exchange the service token for a short-lived, scoped session token")
def issue_token(
    req: IssueRequest,
    x_agent_id: str = Header(..., max_length=64),
    authorization: str = Header(...),
    acl: Acl = Depends(_acl),  # noqa: B008
    sessions: SessionStore = Depends(_sessions),  # noqa: B008
) -> JSONResponse:
    """Only the long-lived service token may mint; session tokens cannot re-mint.
    Scope must be a non-empty subset of the agent's ACL allow entries. TTL is capped by tier
    (never above 15 minutes). The token plaintext is returned once and never logged."""
    token = _bearer(authorization)
    if not acl.authenticate(x_agent_id, token):
        raise HTTPException(status_code=401, detail="authentication failed")
    scope = [c.lower() for c in req.credentials]
    if not scope or not set(scope) <= acl.allowed_credentials(x_agent_id):
        raise HTTPException(status_code=403, detail="requested scope exceeds ACL")
    tier = acl.tier(x_agent_id)
    session_token, rec = sessions.issue(x_agent_id, tier, scope, req.ttl)
    ttl = max(0, round(rec.expires - time.time()))
    _ops().record("session_issued", agent=x_agent_id, tier=tier, ttl=ttl, scope_size=len(scope))
    return JSONResponse(
        content={"token": session_token, "tier": tier, "expires_in": ttl,
                 "scope": sorted(rec.scope)},
        headers={"Cache-Control": "no-store"},
    )


@app.post("/v1/approvals", tags=["credentials"],
          summary="Create a pending human-approval record (tier high, physical actions)")
def create_approval(
    req: ApprovalCreate,
    x_agent_id: str = Header(..., max_length=64),
    authorization: str = Header(...),
    acl: Acl = Depends(_acl),  # noqa: B008
    audit: AuditLog = Depends(_audit),  # noqa: B008
    sessions: SessionStore = Depends(_sessions),  # noqa: B008
    approvals: ApprovalStore = Depends(_approvals),  # noqa: B008
) -> JSONResponse:
    token = _bearer(authorization)
    if not _authn(acl, sessions, x_agent_id, token)[0]:
        raise HTTPException(status_code=401, detail="authentication failed")
    if not acl.authorize(x_agent_id, req.credential, req.purpose).allowed:
        raise HTTPException(status_code=403, detail="not permitted by ACL")
    tier = acl.tier(x_agent_id)
    obo = _obo(acl, x_agent_id)
    try:
        ar = approvals_model.new_request(
            agent=x_agent_id, agent_tier=tier, on_behalf_of=obo,
            intent=req.intent or f"use a credential for: {req.purpose}",
            summary=req.summary or req.purpose,
            if_approved=req.if_approved or "the agent may fetch the credential once",
            if_denied=req.if_denied or "the request is refused; the agent gets nothing",
            urgency=req.urgency, deadline_s=req.deadline_s, details_url=req.details_url,
            data=req.data, action=req.action,
            physical=acl.is_physical(x_agent_id, req.credential))
    except approvals_model.ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors) from None
    a = approvals.create(x_agent_id, req.credential, req.purpose, ttl=req.deadline_s,
                         approval_id=ar.id)
    _approval_service().submit(ar)
    audit.record(AuditEvent(agent=x_agent_id, credential=req.credential, purpose=req.purpose,
                            outcome=f"approval:requested:{a.id}",
                            on_behalf_of=_obo(acl, x_agent_id)))
    return JSONResponse(status_code=201, content={
        "id": a.id, "status": a.status, "risk": ar.risk, "deadline": ar.deadline,
        "requires_passkey": ar.requires_passkey, "approver_min_tier": ar.approver_min_tier})


@app.get("/v1/approvals/nonce", tags=["approvals"],
         summary="Single-use nonce for one /decide call (5 min, bound to the person)")
def approval_nonce(
    x_cvc_person: str | None = Header(None, max_length=64),
    x_cvc_tier: str | None = Header(None, max_length=32),
    nonces: _NonceStore = Depends(_nonces),  # noqa: B008
) -> dict:
    person, _ = _tiergate_identity(x_cvc_person, x_cvc_tier)
    n = nonces.issue(person)
    try:  # counts/timestamps only; the nonce value is never recorded
        _inspector().record_nonce(None, "issued")
    except Exception:  # noqa: BLE001 - visibility must never break the flow
        _log.warning("approvals_inspect_failed", exc_info=True)
    return {"nonce": n, "expires_in": int(_NONCE_TTL)}


def _require_owner(person: str | None, tier: str | None, x_real_ip: str | None,
                   x_forwarded_for: str | None) -> str:
    """ETag debug endpoints: tailnet client + tier-gate identity with tier=owner."""
    _require_tailnet_client(x_real_ip, x_forwarded_for)
    who, t = _tiergate_identity(person, tier)
    if t != "owner":
        raise HTTPException(status_code=403, detail="owner tier required")
    return who


@app.get("/v1/approvals/diag", tags=["approvals"],
         summary="[owner debug] status counts and recent 412/428 rejections")
def approvals_diag(
    x_cvc_person: str | None = Header(None, max_length=64),
    x_cvc_tier: str | None = Header(None, max_length=32),
    x_real_ip: str | None = Header(None, max_length=64),
    x_forwarded_for: str | None = Header(None, max_length=512),
    insp: approvals_inspect.Inspector = Depends(_inspector),  # noqa: B008
) -> dict:
    _require_owner(x_cvc_person, x_cvc_tier, x_real_ip, x_forwarded_for)
    return insp.diag()


@app.get("/v1/approvals/{approval_id}/etag", tags=["approvals"],
         summary="[owner debug] current ETag, version, status and last event")
def approval_etag(
    approval_id: str,
    x_cvc_person: str | None = Header(None, max_length=64),
    x_cvc_tier: str | None = Header(None, max_length=32),
    x_real_ip: str | None = Header(None, max_length=64),
    x_forwarded_for: str | None = Header(None, max_length=512),
    insp: approvals_inspect.Inspector = Depends(_inspector),  # noqa: B008
) -> dict:
    _require_owner(x_cvc_person, x_cvc_tier, x_real_ip, x_forwarded_for)
    out = insp.etag_info(approval_id)
    if out is None:
        raise HTTPException(status_code=404, detail="no such approval")
    return out


@app.get("/v1/approvals/{approval_id}/history", tags=["approvals"],
         summary="[owner debug] append-only version history of one approval")
def approval_history(
    approval_id: str,
    x_cvc_person: str | None = Header(None, max_length=64),
    x_cvc_tier: str | None = Header(None, max_length=32),
    x_real_ip: str | None = Header(None, max_length=64),
    x_forwarded_for: str | None = Header(None, max_length=512),
    insp: approvals_inspect.Inspector = Depends(_inspector),  # noqa: B008
) -> dict:
    _require_owner(x_cvc_person, x_cvc_tier, x_real_ip, x_forwarded_for)
    return {"id": approval_id, "history": insp.history(approval_id)}


@app.get("/v1/approvals/{approval_id}", tags=["credentials"], summary="Approval status")
def get_approval(
    approval_id: str,
    x_agent_id: str = Header(..., max_length=64),
    authorization: str = Header(...),
    acl: Acl = Depends(_acl),  # noqa: B008
    sessions: SessionStore = Depends(_sessions),  # noqa: B008
    approvals: ApprovalStore = Depends(_approvals),  # noqa: B008
) -> JSONResponse:
    token = _bearer(authorization)
    if not _authn(acl, sessions, x_agent_id, token)[0]:
        raise HTTPException(status_code=401, detail="authentication failed")
    svc = _approval_service()
    _sync_approval(approvals, svc, approval_id)
    a = approvals.get(approval_id)
    if a is None or a.agent != x_agent_id:
        raise HTTPException(status_code=404, detail="no such approval")
    body = {"id": a.id, "status": a.status, "credential": a.credential, "purpose": a.purpose}
    r = svc.get(approval_id)
    headers = {}
    if r is not None:
        body["version"] = r.version
        headers["ETag"] = r.etag
    return JSONResponse(content=body, headers=headers)


@app.get("/v1/approvals/{approval_id}/request", tags=["approvals"],
         summary="Full cvc.approval.v1 record for a human approver (with ETag)")
def get_approval_request(
    approval_id: str,
    x_cvc_person: str | None = Header(None, max_length=64),
    x_cvc_tier: str | None = Header(None, max_length=32),
    svc: ApprovalService = Depends(_approval_service),  # noqa: B008
) -> JSONResponse:
    _tiergate_identity(x_cvc_person, x_cvc_tier)
    r = svc.get(approval_id)
    if r is None:
        raise HTTPException(status_code=404, detail="no such approval")
    return JSONResponse(content=r.to_dict(), headers={"ETag": r.etag})


@app.post("/v1/approvals/{approval_id}/approve", tags=["credentials"],
          summary="[deprecated: use /decide] Human approves via the shared approver token")
def approve(
    approval_id: str,
    req: ApproveRequest,
    x_approver_token: str = Header(..., description="Human approver token."),
    audit: AuditLog = Depends(_audit),  # noqa: B008
    approvals: ApprovalStore = Depends(_approvals),  # noqa: B008
) -> dict:
    expected = os.environ.get(_APPROVER_ENV, "").strip().lower()
    if not expected:
        raise HTTPException(status_code=503, detail="approvals not configured")
    got = hashlib.sha256(x_approver_token.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(expected, got):
        raise HTTPException(status_code=401, detail="approver authentication failed")
    a = approvals.approve(approval_id, req.approver)
    if a is None:
        raise HTTPException(status_code=409, detail="approval not pending")
    _approval_service().record_external(approval_id, "approved", req.approver)
    audit.record(AuditEvent(agent=a.agent, credential=a.credential, purpose=a.purpose,
                            outcome=f"approval:granted:{a.id}:by:{req.approver}"))
    return {"id": a.id, "status": a.status}


@app.get("/v1/whoami", tags=["approvals"], summary="Person/tier as asserted by tier-gate")
def whoami(
    x_cvc_person: str | None = Header(None, max_length=64),
    x_cvc_tier: str | None = Header(None, max_length=32),
    x_authentik_username: str | None = Header(None, max_length=128),
    x_real_ip: str | None = Header(None, max_length=64),
    x_forwarded_for: str | None = Header(None, max_length=512),
) -> dict:
    _require_tailnet_client(x_real_ip, x_forwarded_for)
    person, tier = _tiergate_identity(x_cvc_person, x_cvc_tier)
    return {"person": person, "tier": tier,
            "passkey": bool(x_authentik_username) and x_authentik_username == person}


@app.post("/v1/escalations", tags=["credentials"],
          summary="D27: agent requests a single-use exemption for one action")
def create_escalation(
    body: dict = Body(...),  # noqa: B008 - strict validation in cvc.escalation.policy
    x_agent_id: str = Header(..., max_length=64),
    authorization: str = Header(...),
    acl: Acl = Depends(_acl),  # noqa: B008
    audit: AuditLog = Depends(_audit),  # noqa: B008
    escalations: EscalationStore = Depends(_escalations),  # noqa: B008
) -> JSONResponse:
    token = _bearer(authorization)
    if not acl.authenticate(x_agent_id, token):      # service token only, never a session
        raise HTTPException(status_code=401, detail="authentication failed")
    tier = acl.tier(x_agent_id)
    target = str(body.get("resource", "-"))[:128] if isinstance(body, dict) else "-"

    def _log(outcome: str, obo: str | None) -> None:
        audit.record(AuditEvent(agent=x_agent_id, credential=target, purpose="escalation",
                                outcome=outcome, on_behalf_of=obo))

    default_obo = _obo(acl, x_agent_id)
    try:
        a = escalation_evaluate(x_agent_id, tier, body, on_behalf_of_default=default_obo)
    except EscalationRefused as e:
        _log(f"escalation:refused:{e.code}", default_obo)
        raise HTTPException(status_code=e.status,
                            detail={"code": e.code, "reason": e.reason}) from None
    if a.already_permitted:
        _log("escalation:already_permitted", a.on_behalf_of)
        return JSONResponse(content={"status": "already_permitted",
                                     "detail": "the agent's tier already allows this action"})
    escalations.mark_non_human(acl._agents)
    try:
        esc, nonce, suggestion = escalations.request(a, token)
    except EscalationError as e:
        _log(f"escalation:refused:{e.code}", a.on_behalf_of)
        raise HTTPException(status_code=e.status,
                            detail={"code": e.code, "reason": e.reason}) from None
    _log(f"escalation:requested:{esc.id}", a.on_behalf_of)
    out = {"id": esc.id, "status": esc.status, "nonce": nonce, "approval_id": esc.approval_id,
           "current_tier": esc.current_tier, "requested_tier": esc.required_tier,
           "approver_min_tier": esc.approver_min_tier, "ttl_s": esc.ttl_s}
    if suggestion:
        out["audit_suggestion"] = suggestion
    return JSONResponse(status_code=201, content=out, headers={"Cache-Control": "no-store"})


@app.get("/v1/escalations/{escalation_id}", tags=["credentials"],
         summary="D27: escalation status (the requesting agent only)")
def get_escalation(
    escalation_id: str,
    x_agent_id: str = Header(..., max_length=64),
    authorization: str = Header(...),
    acl: Acl = Depends(_acl),  # noqa: B008
    escalations: EscalationStore = Depends(_escalations),  # noqa: B008
) -> dict:
    if not acl.authenticate(x_agent_id, _bearer(authorization)):
        raise HTTPException(status_code=401, detail="authentication failed")
    escalations.mark_non_human(acl._agents)
    esc = escalations.get(escalation_id)
    if esc is None or esc.agent != x_agent_id:
        raise HTTPException(status_code=404, detail="no such escalation")
    return esc.public()


@app.post("/v1/approvals/{approval_id}/decide", tags=["approvals"],
          summary="Human approves/denies (tier-gate identity; passkey for physical)")
def decide(
    approval_id: str,
    body: DecideBody,
    x_cvc_person: str | None = Header(None, max_length=64),
    x_cvc_tier: str | None = Header(None, max_length=32),
    x_authentik_username: str | None = Header(None, max_length=128),
    audit: AuditLog = Depends(_audit),  # noqa: B008
    approvals: ApprovalStore = Depends(_approvals),  # noqa: B008
    svc: ApprovalService = Depends(_approval_service),  # noqa: B008
    nonces: _NonceStore = Depends(_nonces),  # noqa: B008
    if_match: str | None = Header(None, max_length=128),
) -> JSONResponse:
    person, tier = _tiergate_identity(x_cvc_person, x_cvc_tier)
    insp = approvals_inspect.attach(svc)
    try:
        version = _parse_if_match(if_match, approval_id)
    except HTTPException as e:
        insp.record_rejection(approval_id, e.status_code, if_match, person, str(e.detail))
        raise
    if not nonces.consume(body.nonce, person):
        insp.record_nonce(approval_id, "rejected")
        raise HTTPException(status_code=403, detail="invalid or reused nonce")
    insp.record_nonce(approval_id, "consumed")
    try:
        r = svc.decide(approval_id, body.decision, person=person, tier=tier,
                       passkey_user=x_authentik_username, expected_version=version)
    except DecideError as e:
        if e.status_code in (412, 428):
            insp.record_rejection(approval_id, e.status_code, if_match, person, e.detail)
        raise HTTPException(status_code=e.status_code, detail=e.detail) from None
    _sync_approval(approvals, svc, approval_id)
    a = approvals.get(approval_id)
    audit.record(AuditEvent(agent=r.requester.agent, credential=a.credential if a else "-",
                            purpose=a.purpose if a else "-",
                            outcome=f"approval:{r.status}:{r.id}:by:{person}",
                            on_behalf_of=r.requester.on_behalf_of))
    return JSONResponse(content={"id": r.id, "status": r.status, "decided_by": r.decided_by,
                                 "decided_at": r.decided_at, "version": r.version},
                        headers={"ETag": r.etag})


def main() -> None:
    """`cvc-broker` entrypoint — run the broker with uvicorn."""
    import uvicorn

    cfg = config.load()
    uvicorn.run(app, host=cfg.broker_bind, port=cfg.broker_port)


if __name__ == "__main__":
    main()
