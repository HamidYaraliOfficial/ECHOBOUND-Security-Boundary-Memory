"""
Local AI Investigator tool functions.

Every tool here reads real data from Storage/Graph/engines — nothing is
invented. The AI investigator (investigator.py) may call these to assemble
an evidence-grounded explanation, but never to take a final security
decision on its own.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..baseline import BoundaryBaselineEngine
from ..boundary_engine import BoundaryMemoryEngine
from ..drift import BehavioralBoundaryDiffEngine, FirstBoundaryDivergenceDetector
from ..graph import TemporalSecurityGraph
from ..incident import FirstCauseTimeline, IncidentMemoryEngine
from ..query_engine import TemporalGraphQueryEngine
from ..storage import SQLiteStorage, get_storage


class InvestigationTools:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self.graph = TemporalSecurityGraph(self.storage)
        self.memory = BoundaryMemoryEngine(self.storage)
        self.baselines = BoundaryBaselineEngine(self.storage)
        self.diff_engine = BehavioralBoundaryDiffEngine(self.storage)
        self.first_divergence = FirstBoundaryDivergenceDetector(self.storage)
        self.query_engine = TemporalGraphQueryEngine(self.storage)
        self.incident_memory = IncidentMemoryEngine(self.storage)
        self.first_cause = FirstCauseTimeline(self.storage)

    def inspect_boundary(self, entity_id: str) -> Dict[str, Any]:
        entity = self.graph.get_entity(entity_id)
        boundary = self.memory.get_full_boundary(entity_id)
        return {"entity": entity, "boundary": boundary}

    def compare_behavior(self, entity_id: str, t1: float, t2: float) -> Dict[str, Any]:
        return self.graph.diff_between(entity_id, t1, t2)

    def trace_relationship(self, entity_id: str, target_id: str, relation: str) -> Dict[str, Any]:
        edge = self.storage.find_edge(entity_id, target_id, relation)
        if not edge:
            return {"found": False}
        history = self.storage.edge_history(edge["id"])
        return {"found": True, "edge": edge, "history": history}

    def query_history(self, entity_id: str, since_ts: float) -> Dict[str, Any]:
        return self.query_engine.boundary_changes_for_entity(entity_id, since_ts)

    def find_first_divergence(self, entity_id: str, target_id: str, relation: str) -> Optional[float]:
        return self.first_divergence.find_first_divergence(entity_id, target_id, relation)

    def correlate_changes(self, entity_id: str, at_time: float) -> List[Dict[str, Any]]:
        return self.storage.recent_deployments(at_time - 3600 * 12, entity_id)

    def compare_entities(self, entity_id_a: str, entity_id_b: str) -> Dict[str, Any]:
        boundary_a = self.memory.get_full_boundary(entity_id_a)
        boundary_b = self.memory.get_full_boundary(entity_id_b)
        types_a = set(boundary_a.keys())
        types_b = set(boundary_b.keys())
        return {
            "shared_boundary_types": sorted(types_a & types_b),
            "only_in_a": sorted(types_a - types_b),
            "only_in_b": sorted(types_b - types_a),
        }

    def summarize_incident(self, incident_id: str) -> Dict[str, Any]:
        timeline = self.first_cause.build(incident_id)
        similar = self.incident_memory.similar_past_incidents(incident_id)
        return {"timeline": timeline, "similar_past_incidents": similar}


TOOL_REGISTRY = {
    "inspect_boundary": InvestigationTools.inspect_boundary,
    "compare_behavior": InvestigationTools.compare_behavior,
    "trace_relationship": InvestigationTools.trace_relationship,
    "query_history": InvestigationTools.query_history,
    "find_first_divergence": InvestigationTools.find_first_divergence,
    "correlate_changes": InvestigationTools.correlate_changes,
    "compare_entities": InvestigationTools.compare_entities,
    "summarize_incident": InvestigationTools.summarize_incident,
}
