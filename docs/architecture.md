# SentinelForge AI architecture

## MVP topology

```text
Browser (React + TypeScript)
  ├─ local synthetic fixture set (default demo)
  └─ src/api.ts ── optional HTTP ── FastAPI
                                    ├─ validated event request models
                                    ├─ deterministic detection rules
                                    └─ optional scikit-learn Isolation Forest
```

The browser dashboard can run with no backend. The small API currently analyzes submitted events; it is not the frontend's source of truth and does not persist data. The browser's alert status changes and notes are in-memory React state.

## Event and alert flow

1. A future connector normalizes source records to the API's validated `Event` schema.
2. Detection rules group failed authentication records by source and scan records by source/destination in a rolling UTC window.
3. Each output includes evidence signals and point contributions. Failed-login volume contributes up to 40 points, distinct ports up to 35, multiple accounts 15, and asset criticality up to 10. The aggregate is clamped to 100.
4. A future persistence layer stores events, rule versions, alert state transitions, analyst notes, and audit history.
5. A model adapter may produce a summary from a bounded evidence bundle; the analyst should see cited evidence and retain control of response actions.

## Trust and configuration boundaries

- All seeded frontend examples are synthetic and visibly labeled. Local IPs and reputation classifications are example context, not external threat feeds.
- The LLM environment variables only indicate an intended integration. The API does not make model requests.
- The threat-intelligence environment variables are reserved; no enrichment request is implemented.
- `analyst_guard` is an explicit authentication seam. Demo mode returns a demo analyst. If `AUTH_ENABLED=true`, requests are denied until a real token verifier is supplied; bearer-token presence alone is never treated as authentication.
- Secrets belong in backend environment variables or a secret manager. Browser build-time environment variables are public.

## Production evolution

1. Add SQLAlchemy models and Alembic migrations for organizations, users, sources, events, rules, alerts, incidents, notes, and audit entries. Scope every database query by tenant.
2. Validate OIDC issuer, audience, signature, expiry, and roles on every protected operation. Enforce analyst/admin authorization server-side.
3. Introduce authenticated ingestion adapters, queue/backpressure, schema versioning, deduplication, retention, and dead-letter handling.
4. Version rules and risk weights. Add replayable offline evaluations before enabling rule changes.
5. Add a provider interface for LLM and threat-intel integrations, with timeouts, rate limits, redaction, provenance, and clear degraded states.
6. Add health/metrics, structured audit logs, deployment secrets, TLS, explicit CORS, backup and recovery, and operational runbooks.
