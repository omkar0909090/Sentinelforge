"""SentinelForge demo API. Demo records are synthetic; no external services are called."""
from __future__ import annotations

import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, IPvAnyAddress
from dotenv import load_dotenv

load_dotenv()
APP_ENV = os.getenv("APP_ENV", "development")
AUTH_ENABLED = os.getenv("AUTH_ENABLED", "false").lower() == "true"
LLM_CONFIGURED = bool(os.getenv("LLM_PROVIDER") and os.getenv("LLM_API_KEY") and os.getenv("LLM_MODEL"))

app = FastAPI(title="SentinelForge AI API", version="0.1.0", description="Synthetic SOC demo and explainable detection endpoints")
cors_origins = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if origin.strip()]
app.add_middleware(CORSMiddleware, allow_origins=cors_origins, allow_credentials=True, allow_methods=["GET", "POST", "PATCH"], allow_headers=["Authorization", "Content-Type"])


async def analyst_guard(authorization: str | None = Header(default=None)) -> dict[str, str]:
    """Auth integration seam. In production, replace with issuer token verification and role lookup."""
    if AUTH_ENABLED:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Bearer token required")
        # Do not treat token presence as validation; configure a real OIDC/JWT verifier before enabling.
        raise HTTPException(status_code=501, detail="Identity provider verification is not configured")
    return {"sub": "demo-analyst", "role": "analyst"}


class Event(BaseModel):
    timestamp: datetime
    source_ip: IPvAnyAddress
    destination_ip: IPvAnyAddress | None = None
    username: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=80)
    outcome: str = Field(min_length=1, max_length=40)
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    asset: str = Field(default="unknown", max_length=200)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AnalyzeRequest(BaseModel):
    events: list[Event] = Field(max_length=10000)
    failed_login_threshold: int = Field(default=5, ge=3, le=100)
    login_window_minutes: int = Field(default=5, ge=1, le=120)
    port_threshold: int = Field(default=12, ge=5, le=1024)
    scan_window_minutes: int = Field(default=3, ge=1, le=60)


def risk_score(failed_logins: int = 0, distinct_ports: int = 0, multi_account: bool = False, asset_criticality: int = 0) -> tuple[int, list[dict[str, Any]]]:
    """Bounded, transparent score: each signal contributes at most its documented weight."""
    evidence = []
    score = 0
    if failed_logins:
        points = min(40, failed_logins * 4)
        score += points
        evidence.append({"signal": "failed_login_volume", "observed": failed_logins, "points": points, "max_points": 40})
    if distinct_ports:
        points = min(35, max(0, distinct_ports - 3) * 3)
        score += points
        evidence.append({"signal": "distinct_destination_ports", "observed": distinct_ports, "points": points, "max_points": 35})
    if multi_account:
        score += 15
        evidence.append({"signal": "multiple_accounts_targeted", "observed": True, "points": 15, "max_points": 15})
    criticality = max(0, min(10, asset_criticality))
    if criticality:
        score += criticality
        evidence.append({"signal": "asset_criticality", "observed": criticality, "points": criticality, "max_points": 10})
    return min(100, score), evidence


def run_rules(rows: list[Event], req: AnalyzeRequest) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    failed = [e for e in rows if e.event_type.lower() in {"ssh", "login", "authentication"} and e.outcome.lower() in {"failed", "failure", "denied"}]
    by_source: dict[str, list[Event]] = defaultdict(list)
    for event in failed:
        by_source[str(event.source_ip)].append(event)
    for source, group in by_source.items():
        group.sort(key=lambda e: e.timestamp)
        left = 0
        for right, event in enumerate(group):
            while event.timestamp - group[left].timestamp > timedelta(minutes=req.login_window_minutes):
                left += 1
            window = group[left:right + 1]
            if len(window) >= req.failed_login_threshold:
                usernames = {e.username for e in window}
                score, evidence = risk_score(failed_logins=len(window), multi_account=len(usernames) > 1)
                evidence.insert(0, {"signal": "rolling_window", "minutes": req.login_window_minutes, "from": window[0].timestamp.isoformat(), "to": event.timestamp.isoformat()})
                alerts.append({"rule_id": "repeated_auth_failures", "title": "Repeated authentication failures", "severity": "critical" if score >= 80 else "high" if score >= 60 else "medium", "risk_score": score, "source_ip": source, "destination_ip": str(event.destination_ip) if event.destination_ip else None, "usernames": sorted(usernames), "evidence": evidence})
                break

    network = [e for e in rows if e.destination_port is not None and e.event_type.lower() in {"connection", "network", "tcp"}]
    scan_groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in network:
        scan_groups[(str(event.source_ip), str(event.destination_ip or "unknown"))].append(event)
    for (source, destination), group in scan_groups.items():
        group.sort(key=lambda e: e.timestamp)
        left = 0
        for right, event in enumerate(group):
            while event.timestamp - group[left].timestamp > timedelta(minutes=req.scan_window_minutes):
                left += 1
            window = group[left:right + 1]
            ports = {e.destination_port for e in window}
            if len(ports) >= req.port_threshold:
                score, evidence = risk_score(distinct_ports=len(ports))
                evidence.insert(0, {"signal": "scan_window", "minutes": req.scan_window_minutes, "distinct_ports": sorted(ports)})
                alerts.append({"rule_id": "port_scan", "title": "Suspicious port scan", "severity": "high" if score >= 60 else "medium", "risk_score": score, "source_ip": source, "destination_ip": destination, "usernames": [], "evidence": evidence})
                break
    return alerts


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "mode": "demo", "ai_configured": LLM_CONFIGURED, "external_intel_configured": False, "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/api/v1/detections/analyze")
async def analyze(request: AnalyzeRequest, _: dict[str, str] = Depends(analyst_guard)) -> dict[str, Any]:
    alerts = run_rules(request.events, request)
    return {"mode": "demo", "alerts": alerts, "events_analyzed": len(request.events), "summary": "LLM provider is not configured; detection output contains rule evidence only." if not LLM_CONFIGURED else "LLM provider configured, but summary generation is an integration point and is not called by this demo endpoint."}


@app.post("/api/v1/detections/anomalies")
async def anomalies(request: AnalyzeRequest, _: dict[str, str] = Depends(analyst_guard)) -> dict[str, Any]:
    """Optional Isolation Forest over per-source counts; skips cleanly if sklearn is missing or sample too small."""
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return {"mode": "demo", "available": False, "message": "Install scikit-learn and numpy to enable anomaly scoring."}
    by_source: dict[str, Counter[str]] = defaultdict(Counter)
    for event in request.events:
        by_source[str(event.source_ip)][event.event_type.lower()] += 1
    sources = sorted(by_source)
    if len(sources) < 5:
        return {"mode": "demo", "available": False, "message": "At least five distinct sources are required for a useful baseline."}
    matrix = np.array([[by_source[s]["ssh"], by_source[s]["login"], by_source[s]["authentication"], by_source[s]["connection"], by_source[s]["network"], by_source[s]["http"]] for s in sources], dtype=float)
    model = IsolationForest(contamination="auto", random_state=17, n_estimators=100)
    labels = model.fit_predict(matrix)
    scores = model.decision_function(matrix)
    return {"mode": "demo", "available": True, "model": "IsolationForest", "results": [{"source_ip": s, "anomaly": bool(label == -1), "score": round(float(-score), 4)} for s, label, score in zip(sources, labels, scores)]}


@app.get("/api/v1/ai/status")
async def ai_status(_: dict[str, str] = Depends(analyst_guard)) -> dict[str, Any]:
    return {"configured": LLM_CONFIGURED, "provider": os.getenv("LLM_PROVIDER") if LLM_CONFIGURED else None, "mode": "integration_ready" if LLM_CONFIGURED else "template_demo", "message": "No model calls are made by the MVP."}
