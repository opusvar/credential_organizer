"""FastAPI forwardAuth endpoint for tiergate.

Traefik calls GET /auth with the original request's headers; we return 200 (with
X-Cvc-Person / X-Cvc-Tier, to be copied upstream via authResponseHeaders) or 403.
"""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI, Request, Response

from cvc.tiergate.core import Config, decide, load_config

log = logging.getLogger("cvc.tiergate")

CERT_HEADER = "x-forwarded-tls-client-cert"
AUTHENTIK_HEADER = "x-authentik-username"


def create_app(config: Config) -> FastAPI:
    app = FastAPI(title="cvc-tiergate", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    @app.api_route("/auth", methods=["GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"])
    def auth(request: Request) -> Response:
        h = request.headers
        host = h.get("x-forwarded-host") or h.get("host", "")
        d = decide(config, host, h.get(CERT_HEADER), h.get(AUTHENTIK_HEADER))
        ident = d.identity
        log.info(
            "host=%s allowed=%s reason=%s person=%s tier=%s device=%s temp=%s",
            host, d.allowed, d.reason,
            ident and ident.person, ident and ident.tier, ident and ident.device,
            ident and ident.temp,
        )
        if not d.allowed:
            return Response(status_code=403, content="forbidden\n", media_type="text/plain")
        headers = {"X-Cvc-Person": ident.person, "X-Cvc-Tier": ident.tier}
        if ident.device:
            headers["X-Cvc-Device"] = ident.device
        if ident.temp:
            headers["X-Cvc-Temp"] = "1"
            if ident.temp_expires:
                headers["X-Cvc-Temp-Expires"] = ident.temp_expires
        return Response(status_code=200, headers=headers)

    return app


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    cfg = load_config(os.environ.get("CVC_TIERGATE_CONFIG", "/etc/cvc-tiergate/config.yaml"))
    uvicorn.run(
        create_app(cfg),
        host=os.environ.get("CVC_TIERGATE_HOST", "0.0.0.0"),
        port=int(os.environ.get("CVC_TIERGATE_PORT", "8720")),
    )


if __name__ == "__main__":
    main()
