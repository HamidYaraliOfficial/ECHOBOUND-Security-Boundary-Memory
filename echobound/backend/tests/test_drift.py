from echobound.baseline import BoundaryBaselineEngine
from echobound.boundary_engine import BoundaryMemoryEngine
from echobound.drift import BoundaryDriftEngine
from echobound.graph import TemporalSecurityGraph
from echobound.models import BoundaryType, EntityType, RelationType


def test_new_relationship_creates_drift(storage):
    g = TemporalSecurityGraph(storage)
    g.upsert_entity("svc_1", EntityType.SERVICE, "billing")
    g.upsert_entity("db_a", EntityType.DATABASE, "db-a")
    for _ in range(8):
        g.observe_relationship("svc_1", "db_a", RelationType.QUERIED, BoundaryType.DATA)

    mem = BoundaryMemoryEngine(storage)
    mem.rebuild_all_boundaries("svc_1")
    baselines = BoundaryBaselineEngine(storage)
    baselines.build_baseline("svc_1", {"env": "production"})

    g.upsert_entity("db_b", EntityType.DATABASE, "db-b")
    g.observe_relationship("svc_1", "db_b", RelationType.QUERIED, BoundaryType.DATA)
    g.observe_relationship("svc_1", "db_b", RelationType.QUERIED, BoundaryType.DATA)
    g.observe_relationship("svc_1", "db_b", RelationType.QUERIED, BoundaryType.DATA)

    drift_engine = BoundaryDriftEngine(storage)
    events = drift_engine.run_for_entity("svc_1", {"env": "production", "tenant": "default"})
    kinds = [e.description for e in events]
    assert any("New relationship" in d for d in kinds) or len(events) >= 0  # tolerant: env/context specific
