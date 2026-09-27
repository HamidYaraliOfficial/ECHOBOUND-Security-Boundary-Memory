from echobound.boundary_engine import BoundaryMemoryEngine
from echobound.graph import TemporalSecurityGraph
from echobound.models import BoundaryType, EntityType, RelationType


def test_rebuild_boundary_component(storage):
    g = TemporalSecurityGraph(storage)
    g.upsert_entity("proc_1", EntityType.PROCESS, "app")
    g.upsert_entity("db_1", EntityType.DATABASE, "db")
    for _ in range(6):
        g.observe_relationship("proc_1", "db_1", RelationType.QUERIED, BoundaryType.DATA)

    engine = BoundaryMemoryEngine(storage)
    components = engine.rebuild_all_boundaries("proc_1")
    assert len(components) >= 1
    full = engine.get_full_boundary("proc_1")
    assert BoundaryType.DATA.value in full


def test_stability_index_starts_reasonable(storage):
    g = TemporalSecurityGraph(storage)
    g.upsert_entity("proc_1", EntityType.PROCESS, "app")
    engine = BoundaryMemoryEngine(storage)
    assert engine.stability_index("proc_1") == 1.0  # no edges yet -> defined as stable
