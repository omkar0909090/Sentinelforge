# SentinelForge AI

**Intelligent SOC Monitoring & Threat Detection Platform** — a responsive security operations dashboard with explainable demo alerts, investigation workflows, event exploration, rule controls, and synthetic threat context.

> **Demo mode:** the included records are synthetic. The frontend is configured to use local demo records by default. It does not connect to real log sources, call an LLM, or query external threat intelligence.

## Local setup (Windows PowerShell)

Requirements: Node.js 20+ with npm, and Python 3.10+.

From the project root, create the backend environment and install its dependencies:

```powershell
python --version
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r backend/requirements.txt
Copy-Item .env.example .env
```

Start the API in this terminal:

```powershell
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

The health check is available at `http://127.0.0.1:8000/health` and the interactive API schema at `http://127.0.0.1:8000/docs`.

In a second PowerShell terminal, from the same project root, configure and start the frontend:

```powershell
@'
VITE_API_BASE_URL=http://127.0.0.1:8000
'@ | Set-Content .env.local
npm install
npm run build
npm run dev -- --host 127.0.0.1
```

Open the local URL printed by Vite. To use the dashboard without the backend, leave `VITE_API_BASE_URL` empty or remove `.env.local`; the seeded synthetic demo remains available. Restart Vite after changing environment variables.

If PowerShell blocks virtual environment activation, run the environment's Python directly instead:

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

If a managed shell reports `PermissionError` from `ensurepip` while creating the venv, set its temporary directory to this workspace and retry:

```powershell
New-Item -ItemType Directory -Path work\tmp -Force | Out-Null
$env:TEMP = Join-Path (Get-Location) 'work\tmp'
$env:TMP = $env:TEMP
python -m venv .venv
```

The API includes rolling-window failed-login and port-scan rules, transparent bounded risk scoring, and an optional Isolation Forest endpoint. It uses synthetic/demo mode and does not persist records. The UI currently operates from its local synthetic dataset; status and notes persist only for the current browser session. When configured, the frontend checks `/health` and the API helper converts dashboard event fields to the validated backend schema before analysis requests.

## Checks

```powershell
npm run typecheck
npm run build
.\.venv\Scripts\python.exe -m unittest discover -s backend/tests -v
```

There is no separate frontend test suite yet. In the current managed Codex workspace, the frontend build is unverified because its bundled PNPM fails during workspace discovery with `EPERM` from Node's asynchronous `fs.promises.realpath`, before dependency installation or TypeScript/Vite execution. The project directory is readable/writable and synchronous/callback `realpath` succeeds; the same async failure occurs for a scratch project under `work/`, so this is a runtime sandbox limitation rather than a project-directory ACL or package manifest error. Use the npm commands above on a normal local Node.js installation to verify the frontend build.

## Configuration and security

- Keep API credentials only in backend environment variables. Never use `VITE_*` for secrets; Vite embeds those values in browser assets.
- `AUTH_ENABLED=false` is for local demo use. Enabling it intentionally rejects requests with `501` until an OIDC/JWT verifier and server-side role checks are implemented. Do not expose protected routes without that verifier.
- `DATABASE_URL`, LLM, and threat-intelligence variables are documented integration points. PostgreSQL persistence, LLM-backed generation, and external enrichment are not implemented or implied to be connected.
- For deployment, set explicit trusted CORS origins, use TLS, add identity verification and server-side authorization, and persist audit records before ingesting production telemetry.

## Project structure

```text
src/                 React + TypeScript dashboard, synthetic fixtures, API boundary
backend/app/         FastAPI health and detection endpoints
backend/requirements.txt Python API dependencies
backend/tests/       Detection logic unit tests
docs/architecture.md Architecture, data flow, trust boundaries, roadmap
outputs/             Reserved for user-facing packaged deliverables
```

## Implemented

- Overview with event timeline, severity distribution, suspicious IP table, pipeline health, and recent detections.
- Searchable/filterable alerts, detail drawer, status transitions, evidence, risk breakdown, and analyst notes.
- Event Explorer, incident queue, evidence-first AI Investigation demo, detection rule toggles, local threat indicator examples, and analyst preferences.
- Responsive dark SOC interface with loading-safe static demo state, empty search states, and action feedback.
- FastAPI request validation, rolling-window failed-auth and port-scan detection, risk evidence, optional Isolation Forest, and configuration-status endpoints.

## Planned

- PostgreSQL models, migrations, retention and audit history.
- OIDC/JWT login and server-side analyst/administrator authorization.
- Streaming ingestion and production SIEM connectors.
- Configurable rule editor and persistent alert/incident updates.
- LLM provider adapter with redaction, prompt controls, citations to source events, and review safeguards.
- Threat-intelligence provider adapters and freshness/provenance metadata.
- Operational telemetry, deployment manifests, and production hardening.
