# API documentation (OpenAPI)

The credential broker (`cvc.broker.app`) is a FastAPI service, so it is **OpenAPI-native**:

| What | Where (when the broker is running) |
|---|---|
| OpenAPI JSON | `GET /openapi.json` |
| Swagger UI | `GET /docs` |
| ReDoc | `GET /redoc` |

Per the project OpenAPI documentation standard (all HTTP-API projects ship a spec), a static
copy is committed at [`openapi.yaml`](openapi.yaml) so the contract is reviewable without running
the service. Regenerate it from the live app after any endpoint change:

```bash
make openapi        # writes docs/openapi.yaml from cvc.broker.app:app.openapi()
```

## Endpoints (v0 scaffold)
- `GET /healthz` — liveness.
- `GET /v1/audit/verify` — audit hash-chain integrity (`intact: bool`).
- `POST /v1/credentials/fetch` — default-deny, purpose-bound, audited credential request.
  Auth via `X-Agent-Id` + `Authorization: Bearer <token>`. Returns 401 (auth), 403 (ACL deny),
  or 501 (retrieval not implemented — pending decision D5 + Opus security review).

The other components (importers, reminders, backup) are CLIs/jobs, not HTTP services, so they
have no OpenAPI surface; their contracts live in `ARCHITECTURE.md` and their `--help`.
