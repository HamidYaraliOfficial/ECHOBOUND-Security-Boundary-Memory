from echobound.graph import TemporalSecurityGraph
from echobound.models import EntityType
from echobound.policy import BoundaryPolicyEngine


def test_policy_simulation_forbidden(storage):
    g = TemporalSecurityGraph(storage)
    g.upsert_entity("svc_1", EntityType.SERVICE, "billing")
    pe = BoundaryPolicyEngine(storage)
    pe.create_policy(
        entity_selector={"type": "service"},
        forbidden_relationships=[{"relation": "connected_to", "target": "endpoint_evil"}],
    )
    verdict = pe.simulate("svc_1", {"relation": "connected_to", "target_id": "endpoint_evil"})
    assert verdict["verdict"] == "violation"

    verdict2 = pe.simulate("svc_1", {"relation": "connected_to", "target_id": "endpoint_ok"})
    assert verdict2["verdict"] in ("candidate", "allow", "review")
