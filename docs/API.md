# API documentation (OpenAPI)

The credential broker (`cvc.broker.app`) is a FastAPI service, so it is **OpenAPI-native**:

OpenAPI docs (`/docs`, `/redoc`, `/openapi.json`) are **disabled** on the live broker
(security: a credential broker must not advertise its contract). The static spec at
[`openapi.yaml`](openapi.yaml) is the reviewable contract. Regenerate after endpoint changes:

```bash
# Run locally (not from the deployed pod) to regenerate:
python -c "import yaml, json; from cvc.broker.app import app; print(yaml.dump(json.loads(app.openapi())))" > docs/openapi.yaml
```

## Endpoints
- `GET /healthz` — liveness (no auth required).
- `GET /v1/audit/verify` — audit hash-chain integrity (`intact: bool`). Requires auth.
- `POST /v1/credentials/fetch` — default-deny, purpose-bound, audited credential fetch.
  Auth via `X-Agent-Id` + `Authorization: Bearer <token>`. Returns 401 (auth), 403 (ACL deny),
  502 (vault error), or 200 with `{"credential": "<uuid>", "field": "<field>", "value": "<val>"}`.

The other components (importers, reminders, backup) are CLIs/jobs, not HTTP services, so they
have no OpenAPI surface; their contracts live in `ARCHITECTURE.md` and their `--help`.
