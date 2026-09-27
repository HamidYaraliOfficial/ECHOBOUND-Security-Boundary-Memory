import time

from echobound.graph import TemporalSecurityGraph
from echobound.models import BoundaryType, EntityType, RelationType


def test_upsert_entity_and_edge(storage):
    g = TemporalSecurityGraph(storage)
    g.upsert_entity("proc_1", EntityType.PROCESS, "nginx")
    g.upsert_entity("db_1", EntityType.DATABASE, "postgres-primary")
    edge = g.observe_relationship("proc_1", "db_1", RelationType.QUERIED, BoundaryType.DATA)
    assert edge["state"] == "candidate"
    assert edge["frequency"] == 1

    edge2 = g.observe_relationship("proc_1", "db_1", RelationType.QUERIED, BoundaryType.DATA)
    assert edge2["frequency"] == 2
    assert edge2["id"] == edge["id"]


def test_boundary_at_reconstructs_point_in_time(storage):
    g = TemporalSecurityGraph(storage)
    g.upsert_entity("proc_1", EntityType.PROCESS, "worker")
    g.upsert_entity("ep_1", EntityType.NETWORK_ENDPOINT, "10.0.0.1:443")
    t0 = time.time()
    g.observe_relationship("proc_1", "ep_1", RelationType.CONNECTED_TO, BoundaryType.NETWORK)
    active = g.boundary_at("proc_1", time.time())
    assert len(active) == 1
    past = g.boundary_at("proc_1", t0 - 3600)
    assert len(past) == 0
