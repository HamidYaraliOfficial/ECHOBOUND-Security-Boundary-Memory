"""
ECHOBOUND CLI.

Commands: agent, collect, baseline, boundary, graph, query, drift, replay,
investigate, snapshot, simulate, benchmark, report.
"""
from __future__ import annotations

import json
import time

import typer

from .agent import AgentSelfHealthEngine
from .archetypes import BehaviorArchetypeEngine
from .baseline import BoundaryBaselineEngine
from .benchmark import BoundaryDetectionBenchmarkLab
from .boundary_engine import BoundaryMemoryEngine
from .collectors.ebpf_collector import EBPFTelemetryCollector, ebpf_available
from .collectors.proc_fallback_collector import ProcFallbackCollector
from .context_engine import MaintenanceContextEngine
from .drift import BoundaryDriftEngine
from .graph import TemporalSecurityGraph
from .pipeline import EventPipeline
from .policy import BoundaryPolicyEngine
from .query_engine import TemporalGraphQueryEngine
from .replay_snapshot import BoundaryReplayEngine, BoundarySnapshotEngine
from .report import SecurityReportGenerator
from .storage import get_storage
from .synthetic import SyntheticSecurityWorldGenerator

app = typer.Typer(help="ECHOBOUND — Security Boundary Memory CLI")
storage = get_storage()


def _print(obj):
    typer.echo(json.dumps(obj, indent=2, default=str))


@app.command()
def agent(action: str = typer.Argument(..., help="start|status")):
    """Manage the local telemetry agent."""
    if action == "status":
        _print({"ebpf_available": ebpf_available()})
    elif action == "start":
        pipeline = EventPipeline(storage)
        if ebpf_available():
            collector = EBPFTelemetryCollector("local-host", pipeline.ingest)
            collector.start()
            typer.echo("eBPF collector attached. Polling... Ctrl+C to stop.")
            try:
                while True:
                    collector.poll()
            except KeyboardInterrupt:
                collector.stop()
        else:
            typer.echo("eBPF unavailable on this host — using proc-fallback collector.")
            collector = ProcFallbackCollector("local-host", pipeline.ingest)
            collector.run_forever()
    else:
        typer.echo("unknown action")


@app.command()
def collect(kind: str, payload_json: str, host_id: str = "host-0", tenant: str = "default"):
    """Manually inject one event (useful for scripting/tests)."""
    pipeline = EventPipeline(storage)
    event = {
        "event_id": f"ev_{int(time.time()*1000)}", "tenant": tenant, "ts": time.time(),
        "host_id": host_id, "kind": kind, "payload": json.loads(payload_json), "source": "cli",
    }
    pipeline.ingest(event)
    typer.echo("ingested")


@app.command()
def baseline(action: str, entity_id: str, context_json: str = "{}"):
    """build|history|rollback baselines for an entity."""
    engine = BoundaryBaselineEngine(storage)
    ctx = json.loads(context_json)
    if action == "build":
        _print(engine.build_baseline(entity_id, ctx))
    elif action == "history":
        _print(engine.history(entity_id, ctx))
    else:
        typer.echo("unknown action")


@app.command()
def boundary(entity_id: str):
    """Show the full current boundary for an entity."""
    engine = BoundaryMemoryEngine(storage)
    engine.rebuild_all_boundaries(entity_id)
    _print(engine.get_full_boundary(entity_id))


@app.command()
def graph(action: str, entity_id: str = typer.Argument(None)):
    """entities|edges for the temporal security graph."""
    g = TemporalSecurityGraph(storage)
    if action == "entities":
        _print(g.find_entities())
    elif action == "edges" and entity_id:
        _print(g.entity_edges(entity_id))
    else:
        typer.echo("usage: graph entities | graph edges <entity_id>")


@app.command()
def query(kind: str, entity_id: str, since_days: float = 30):
    """new-destinations|history queries."""
    qe = TemporalGraphQueryEngine(storage)
    since_ts = time.time() - since_days * 86400
    if kind == "new-destinations":
        _print(qe.new_destinations_since(entity_id, since_ts))
    elif kind == "history":
        _print(qe.boundary_changes_for_entity(entity_id, since_ts))
    else:
        typer.echo("unknown query kind")


@app.command()
def drift(entity_id: str):
    """Run the drift pipeline for one entity."""
    engine = BoundaryDriftEngine(storage)
    events = engine.run_for_entity(entity_id)
    _print([e.to_dict() for e in events])


@app.command()
def replay(since_days: float = 7, step: int = 50):
    """Replay historical raw events."""
    r = BoundaryReplayEngine(storage)
    info = r.load(time.time() - since_days * 86400)
    typer.echo(f"loaded {info['loaded']} events")
    processed = r.step(step)
    typer.echo(f"stepped through {len(processed)} events")


@app.command()
def investigate(entity_id: str):
    """Print hypotheses + suggested queries for an entity."""
    from .ai.investigator import LocalAIInvestigator
    inv = LocalAIInvestigator(storage)
    _print({"hypotheses": inv.generate_hypotheses(entity_id), "suggested_queries": inv.suggest_investigation_queries(entity_id)})


@app.command()
def snapshot(action: str, entity_id: str):
    """take|list boundary snapshots."""
    from .boundary_engine import BoundaryMemoryEngine
    snap_engine = BoundarySnapshotEngine(storage)
    if action == "take":
        mem = BoundaryMemoryEngine(storage)
        mem.rebuild_all_boundaries(entity_id)
        _print(snap_engine.take_snapshot(entity_id, mem.get_full_boundary(entity_id)))
    elif action == "list":
        _print(snap_engine.list_snapshots(entity_id))
    else:
        typer.echo("unknown action")


@app.command()
def simulate(entity_id: str, relation: str, target_id: str):
    """Simulate a candidate relationship against active policies."""
    pe = BoundaryPolicyEngine(storage)
    _print(pe.simulate(entity_id, {"relation": relation, "target_id": target_id}))


@app.command()
def benchmark(seed: int = 42):
    """Run the detection benchmark lab against the synthetic world."""
    lab = BoundaryDetectionBenchmarkLab(storage)
    _print(lab.run(seed=seed))


@app.command()
def report(kind: str = "organization", entity_id: str = typer.Option(None), fmt: str = "json"):
    """entity|organization reports."""
    gen = SecurityReportGenerator(storage)
    if kind == "entity" and entity_id:
        rep = gen.build_entity_report(entity_id)
    else:
        rep = gen.build_organization_report()
    if fmt == "markdown":
        typer.echo(gen.to_markdown(rep))
    else:
        _print(rep)


@app.command()
def operating_hours(action: str, tenant: str = "default", timezone: str = "UTC",
                     start: str = "09:00", end: str = "18:00"):
    """quick-setup|status operating hours (business-hours context)."""
    ctx = MaintenanceContextEngine(storage)
    if action == "quick-setup":
        _print(ctx.quick_setup_business_hours(tenant, timezone, start, end))
    elif action == "status":
        _print(ctx.current_status(tenant))
    else:
        typer.echo("unknown action")


@app.command()
def seed_synthetic(seed: int = 42, tenant: str = "synthetic"):
    """Generate a synthetic security world for local testing/demo."""
    gen = SyntheticSecurityWorldGenerator(seed=seed, storage=storage)
    _print(gen.generate_world(tenant=tenant))


if __name__ == "__main__":
    app()
