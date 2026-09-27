"""
ECHOBOUND API Layer (FastAPI).

Versioned (/api/v1), documented (OpenAPI at /docs) and permission-aware REST
endpoints, plus a WebSocket for live updates. This is the single entry point
the Security Command Center frontend talks to.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from . import __version__
from .agent import AgentSelfHealthEngine, ContainerBoundaryEngine, HostIdentityLayer
from .archetypes import BehaviorArchetypeEngine
from .auth import current_principal, require_permission
from .baseline import BoundaryBaselineEngine
from .benchmark import BoundaryDetectionBenchmarkLab
from .boundary_engine import BoundaryMemoryEngine
from .collector_confidence import BlindSpotDetector, CollectorConfidenceModel
from .context_engine import MaintenanceContextEngine
from .drift import BoundaryDriftEngine
from .graph import TemporalSecurityGraph
from .incident import BoundaryIncidentCorrelator, FirstCauseTimeline, IncidentMemoryEngine
from .models import CaseState, FeedbackLabel, new_id, now_ts
from .pipeline import EventPipeline
from .platform_guard import PlatformBoundaryGuard
from .policy import BoundaryPolicyEngine
from .query_engine import QueryCostGuard, TemporalGraphQueryEngine
from .replay_snapshot import BoundaryReplayEngine, BoundarySnapshotEngine
from .report import SecurityReportGenerator
from .storage import get_storage
from .synthetic import SyntheticSecurityWorldGenerator
from .violation import BoundaryViolationEngine
from .websocket import manager

app = FastAPI(
    title="ECHOBOUND — Security Boundary Memory API",
    version=__version__,
    description="Temporal Behavioral Security Platform: boundary memory, drift, policy, investigation.",
)

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

storage = get_storage()
graph = TemporalSecurityGraph(storage)
pipeline = EventPipeline(storage)
memory_engine = BoundaryMemoryEngine(storage)
baseline_engine = BoundaryBaselineEngine(storage)
drift_engine = BoundaryDriftEngine(storage)
policy_engine = BoundaryPolicyEngine(storage)
violation_engine = BoundaryViolationEngine(storage)
query_engine = TemporalGraphQueryEngine(storage)
incident_correlator = BoundaryIncidentCorrelator(storage)
incident_memory = IncidentMemoryEngine(storage)
first_cause = FirstCauseTimeline(storage)
archetype_engine = BehaviorArchetypeEngine(storage)
context_engine = MaintenanceContextEngine(storage)
blind_spot_detector = BlindSpotDetector(storage)
confidence_model = CollectorConfidenceModel(storage)
platform_guard = PlatformBoundaryGuard(storage)
report_generator = SecurityReportGenerator(storage)
snapshot_engine = BoundarySnapshotEngine(storage)
replay_engine = BoundaryReplayEngine(storage)
host_identity = HostIdentityLayer(storage)
container_boundary = ContainerBoundaryEngine(storage)
agent_health = AgentSelfHealthEngine(storage)
benchmark_lab = BoundaryDetectionBenchmarkLab(storage)


# --------------------------------------------------------------------- misc
@app.get("/api/v1/health")
def health():
    return {"product": "ECHOBOUND", "version": __version__, "status": "ok", "time": time.time()}


@app.get("/api/v1/platform/health")
def platform_health():
    return platform_guard.ingestion_health()


# ------------------------------------------------------------------ events
class RawEventIn(BaseModel):
    kind: str
    payload: Dict[str, Any]
    host_id: str = "host-0"
    tenant: str = "default"
    source: str = "manual"


@app.post("/api/v1/events/ingest")
def ingest_event(ev: RawEventIn, principal=Depends(current_principal)):
    require_permission(principal, "ingest") if principal["role"] == "service" else require_permission(principal, "read")
    event = {
        "event_id": new_id("ev"), "tenant": ev.tenant, "ts": now_ts(), "host_id": ev.host_id,
        "kind": ev.kind, "payload": ev.payload, "source": ev.source, "integrity_flags": {},
    }
    pipeline.ingest(event)
    return {"ingested": True, "event_id": event["event_id"]}


# ---------------------------------------------------------------- entities
@app.get("/api/v1/entities")
def list_entities(type: Optional[str] = None, search: Optional[str] = None, tenant: str = "default",
                   limit: int = 200, principal=Depends(current_principal)):
    require_permission(principal, "read")
    return graph.find_entities(tenant=tenant, type_filter=type, search=search, limit=limit)


@app.get("/api/v1/entities/{entity_id}")
def get_entity(entity_id: str, principal=Depends(current_principal)):
    require_permission(principal, "read")
    e = graph.get_entity(entity_id)
    if not e:
        raise HTTPException(404, "entity not found")
    return e


@app.get("/api/v1/entities/{entity_id}/boundary")
def get_boundary(entity_id: str, principal=Depends(current_principal)):
    require_permission(principal, "read")
    memory_engine.rebuild_all_boundaries(entity_id)
    return memory_engine.get_full_boundary(entity_id)


@app.get("/api/v1/entities/{entity_id}/edges")
def get_edges(entity_id: str, state: Optional[str] = None, principal=Depends(current_principal)):
    require_permission(principal, "read")
    return graph.entity_edges(entity_id, state=state)


@app.get("/api/v1/entities/{entity_id}/archetype")
def get_archetype(entity_id: str, principal=Depends(current_principal)):
    require_permission(principal, "read")
    archetype = archetype_engine.classify(entity_id)
    return {"entity_id": entity_id, "archetype": archetype, "profile": archetype_engine.describe(archetype).__dict__}


class ArchetypeOverrideIn(BaseModel):
    archetype: str


@app.post("/api/v1/entities/{entity_id}/archetype/override")
def override_archetype(entity_id: str, body: ArchetypeOverrideIn, principal=Depends(current_principal)):
    require_permission(principal, "annotate")
    return archetype_engine.override(entity_id, body.archetype, principal["sub"])


@app.get("/api/v1/archetypes")
def list_archetypes(principal=Depends(current_principal)):
    require_permission(principal, "read")
    return archetype_engine.list_archetypes()


# ---------------------------------------------------------------- baselines
class BuildBaselineIn(BaseModel):
    context: Dict[str, Any] = Field(default_factory=dict)
    notes: str = ""
    freeze: bool = False


@app.post("/api/v1/entities/{entity_id}/baseline")
def build_baseline(entity_id: str, body: BuildBaselineIn, principal=Depends(current_principal)):
    require_permission(principal, "annotate")
    return baseline_engine.build_baseline(entity_id, body.context, body.notes, body.freeze)


@app.get("/api/v1/entities/{entity_id}/baseline/history")
def baseline_history(entity_id: str, principal=Depends(current_principal)):
    require_permission(principal, "read")
    return baseline_engine.history(entity_id)


class RollbackBaselineIn(BaseModel):
    context: Dict[str, Any] = Field(default_factory=dict)
    target_version_id: str


@app.post("/api/v1/entities/{entity_id}/baseline/rollback")
def rollback_baseline(entity_id: str, body: RollbackBaselineIn, principal=Depends(current_principal)):
    require_permission(principal, "annotate")
    return baseline_engine.rollback(entity_id, body.context, body.target_version_id, principal["sub"])


# ------------------------------------------------------------------- drift
@app.post("/api/v1/entities/{entity_id}/drift/run")
async def run_drift(entity_id: str, principal=Depends(current_principal)):
    require_permission(principal, "read")
    events = drift_engine.run_for_entity(entity_id)
    for ev in events:
        await manager.broadcast("drift_detected", ev.to_dict())
    return [e.to_dict() for e in events]


@app.get("/api/v1/drifts")
def list_drifts(entity_id: Optional[str] = None, severity: Optional[str] = None,
                 since: Optional[float] = None, principal=Depends(current_principal)):
    require_permission(principal, "read")
    return storage.list_drifts(entity_id=entity_id, since=since, severity=severity)


class FeedbackIn(BaseModel):
    label: str
    comment: str = ""


@app.post("/api/v1/drifts/{drift_id}/feedback")
def submit_feedback(drift_id: str, body: FeedbackIn, principal=Depends(current_principal)):
    require_permission(principal, "annotate")
    if body.label not in [f.value for f in FeedbackLabel]:
        raise HTTPException(400, "invalid feedback label")
    storage.save_feedback({"id": new_id("fb"), "drift_id": drift_id, "label": body.label,
                            "analyst": principal["sub"], "created_at": now_ts(), "comment": body.comment})
    return {"ok": True}


# ------------------------------------------------------------------ policy
class PolicyIn(BaseModel):
    entity_selector: Dict[str, Any]
    allowed_relationships: List[Dict[str, Any]] = Field(default_factory=list)
    forbidden_relationships: List[Dict[str, Any]] = Field(default_factory=list)
    expected_frequency: Dict[str, Any] = Field(default_factory=dict)
    time_windows: List[Dict[str, Any]] = Field(default_factory=list)
    allowed_sources: List[str] = Field(default_factory=list)
    allowed_destinations: List[str] = Field(default_factory=list)
    change_policy: str = "review"


@app.post("/api/v1/policies")
def create_policy(body: PolicyIn, principal=Depends(current_principal)):
    require_permission(principal, "annotate")
    return policy_engine.create_policy(**body.dict())


@app.get("/api/v1/policies")
def list_policies(principal=Depends(current_principal)):
    require_permission(principal, "read")
    return policy_engine.list_policies()


class SimulateIn(BaseModel):
    entity_id: str
    relation: str
    target_id: str


@app.post("/api/v1/policies/simulate")
def simulate_policy(body: SimulateIn, principal=Depends(current_principal)):
    require_permission(principal, "policy:simulate")
    return policy_engine.simulate(body.entity_id, {"relation": body.relation, "target_id": body.target_id})


@app.get("/api/v1/entities/{entity_id}/violations")
def get_violations(entity_id: str, principal=Depends(current_principal)):
    require_permission(principal, "read")
    return violation_engine.evaluate_entity(entity_id)


# --------------------------------------------------------------- incidents
@app.post("/api/v1/incidents/correlate")
def correlate_incidents(since: float, principal=Depends(current_principal)):
    require_permission(principal, "annotate")
    return incident_correlator.correlate_recent(since)


@app.get("/api/v1/incidents")
def list_incidents(state: Optional[str] = None, principal=Depends(current_principal)):
    require_permission(principal, "read")
    return incident_memory.list_incidents(state)


@app.get("/api/v1/incidents/{incident_id}/timeline")
def incident_timeline(incident_id: str, principal=Depends(current_principal)):
    require_permission(principal, "read")
    return first_cause.build(incident_id)


class IncidentStateIn(BaseModel):
    state: str


@app.post("/api/v1/incidents/{incident_id}/state")
async def set_incident_state(incident_id: str, body: IncidentStateIn, principal=Depends(current_principal)):
    require_permission(principal, "annotate")
    result = incident_memory.set_state(incident_id, CaseState(body.state), principal["sub"])
    await manager.broadcast("case_updated", result)
    return result


class IncidentNoteIn(BaseModel):
    text: str


@app.post("/api/v1/incidents/{incident_id}/notes")
def add_incident_note(incident_id: str, body: IncidentNoteIn, principal=Depends(current_principal)):
    require_permission(principal, "annotate")
    return incident_memory.add_note(incident_id, principal["sub"], body.text)


# ------------------------------------------------------------------- query
class QueryHistoryIn(BaseModel):
    entity_id: str
    since_ts: float
    timeout_s: float = 8.0


@app.post("/api/v1/query/history")
def query_history(body: QueryHistoryIn, principal=Depends(current_principal)):
    require_permission(principal, "read")
    guard = QueryCostGuard(timeout_s=body.timeout_s)
    return query_engine.boundary_changes_for_entity(body.entity_id, body.since_ts, guard)


@app.get("/api/v1/query/search")
def query_search(q: str, tenant: str = "default", principal=Depends(current_principal)):
    require_permission(principal, "read")
    return query_engine.search(q, tenant)


# --------------------------------------------------------------- ai / investigation
@app.get("/api/v1/ai/drift/{drift_id}/explain")
def explain_drift(drift_id: str, principal=Depends(current_principal)):
    require_permission(principal, "investigate")
    from .ai.investigator import LocalAIInvestigator
    return LocalAIInvestigator(storage).explain_drift(drift_id)


@app.get("/api/v1/ai/entities/{entity_id}/hypotheses")
def ai_hypotheses(entity_id: str, principal=Depends(current_principal)):
    require_permission(principal, "investigate")
    from .ai.investigator import LocalAIInvestigator
    return LocalAIInvestigator(storage).generate_hypotheses(entity_id)


# -------------------------------------------------------- operating hours
class QuickSetupIn(BaseModel):
    tenant: str = "default"
    timezone: str = "UTC"
    start_hhmm: str = "09:00"
    end_hhmm: str = "18:00"
    weekdays: List[int] = Field(default_factory=lambda: [0, 1, 2, 3, 4])


@app.post("/api/v1/context/operating-hours/quick-setup")
def quick_setup_operating_hours(body: QuickSetupIn, principal=Depends(current_principal)):
    require_permission(principal, "annotate")
    return context_engine.quick_setup_business_hours(
        body.tenant, body.timezone, body.start_hhmm, body.end_hhmm, body.weekdays, principal["sub"]
    )


class OperatingHoursWindowIn(BaseModel):
    weekday: int
    start_minute: int
    end_minute: int
    label: str = ""


class OperatingHoursIn(BaseModel):
    tenant: str = "default"
    timezone: str = "UTC"
    windows: List[OperatingHoursWindowIn]
    maintenance_windows: List[Dict[str, Any]] = Field(default_factory=list)


@app.post("/api/v1/context/operating-hours")
def save_operating_hours(body: OperatingHoursIn, principal=Depends(current_principal)):
    require_permission(principal, "annotate")
    return context_engine.save_config(
        body.tenant, body.timezone, [w.dict() for w in body.windows], body.maintenance_windows, principal["sub"]
    )


@app.get("/api/v1/context/operating-hours")
def get_operating_hours(tenant: str = "default", principal=Depends(current_principal)):
    require_permission(principal, "read")
    return context_engine.get_config(tenant)


@app.get("/api/v1/context/operating-hours/status")
def operating_hours_status(tenant: str = "default", principal=Depends(current_principal)):
    require_permission(principal, "read")
    return context_engine.current_status(tenant)


# ------------------------------------------------------------------ agents
@app.get("/api/v1/agents")
def list_agents(tenant: str = "default", principal=Depends(current_principal)):
    require_permission(principal, "read")
    return storage.list_agents(tenant)


class HeartbeatIn(BaseModel):
    agent_id: str
    host_id: str
    tenant: str = "default"
    events_per_sec: float = 0
    dropped_events: int = 0
    buffer_usage: float = 0
    kernel_hook_status: str = "attached"
    collector_latency_ms: float = 0
    agent_version: str = "1.0.0"
    kernel_version: str = "unknown"


@app.post("/api/v1/agents/heartbeat")
async def agent_heartbeat(body: HeartbeatIn, principal=Depends(current_principal)):
    require_permission(principal, "ingest") if principal["role"] == "service" else require_permission(principal, "annotate")
    result = agent_health.report(**body.dict())
    await manager.broadcast("agent_health", result)
    return result


@app.get("/api/v1/blind-spots")
def blind_spots(tenant: str = "default", principal=Depends(current_principal)):
    require_permission(principal, "read")
    return {
        "stale_agents": blind_spot_detector.stale_agents(tenant),
        "low_visibility_entities": blind_spot_detector.low_visibility_entities(tenant),
    }


# ------------------------------------------------------------------ reports
@app.get("/api/v1/reports/entity/{entity_id}")
def entity_report(entity_id: str, fmt: str = "json", principal=Depends(current_principal)):
    require_permission(principal, "read")
    report = report_generator.build_entity_report(entity_id)
    if fmt == "markdown":
        return {"content": report_generator.to_markdown(report)}
    if fmt == "html":
        return {"content": report_generator.to_html(report)}
    return report


@app.get("/api/v1/reports/organization")
def organization_report(tenant: str = "default", fmt: str = "json", principal=Depends(current_principal)):
    require_permission(principal, "read")
    report = report_generator.build_organization_report(tenant)
    if fmt == "markdown":
        return {"content": report_generator.to_markdown(report)}
    if fmt == "html":
        return {"content": report_generator.to_html(report)}
    return report


# ---------------------------------------------------------------- synthetic
class GenerateWorldIn(BaseModel):
    seed: int = 42
    tenant: str = "synthetic"


@app.post("/api/v1/synthetic/generate")
def generate_world(body: GenerateWorldIn, principal=Depends(current_principal)):
    require_permission(principal, "annotate")
    gen = SyntheticSecurityWorldGenerator(seed=body.seed, storage=storage)
    return gen.generate_world(tenant=body.tenant)


@app.post("/api/v1/benchmark/run")
def run_benchmark(seed: int = 42, principal=Depends(current_principal)):
    require_permission(principal, "annotate")
    return benchmark_lab.run(seed=seed)


# --------------------------------------------------------------- websocket
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # clients may send pings; ignored
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
