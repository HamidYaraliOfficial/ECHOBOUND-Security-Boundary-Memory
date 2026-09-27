"""
Boundary Memory Engine.

Turns raw observed relationships into a stable per-entity Boundary Profile,
distinguishing transient behavior from established behavior using Memory
Decay, Stability, Recency, Frequency, Confidence, Repetition and Context.
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Any, Dict, List

from .confidence import compute_confidence, is_promotable_to_expected
from .graph import TemporalSecurityGraph
from .models import BoundaryComponent, BoundaryType, RelationState, now_ts
from .storage import SQLiteStorage, get_storage

RELATION_TO_BOUNDARY = {
    "spawned": BoundaryType.PROCESS,
    "executed_by": BoundaryType.PROCESS,
    "accessed": BoundaryType.FILE,
    "reads": BoundaryType.FILE,
    "writes": BoundaryType.FILE,
    "loads": BoundaryType.FILE,
    "connected_to": BoundaryType.NETWORK,
    "communicates_with": BoundaryType.NETWORK,
    "queried": BoundaryType.DATA,
    "authenticated_to": BoundaryType.IDENTITY,
    "contained_by": BoundaryType.CONTAINER,
    "depends_on": BoundaryType.SERVICE,
    "controls": BoundaryType.PRIVILEGE,
    "impersonates": BoundaryType.PRIVILEGE,
    "delegates_to": BoundaryType.PRIVILEGE,
    "belongs_to": BoundaryType.TRUST,
    "observed_with": BoundaryType.TRUST,
}


class BoundaryMemoryEngine:
    """Learns and maintains Boundary Components for every entity."""

    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self.graph = TemporalSecurityGraph(self.storage)

    def _distinct_days_seen(self, edge_id: str) -> int:
        hist = self.storage.edge_history(edge_id)
        days = {int(h["changed_at"] // 86400) for h in hist}
        return max(1, len(days))

    def update_confidence_and_state(self, edge: Dict[str, Any]) -> Dict[str, Any]:
        distinct_days = self._distinct_days_seen(edge["id"])
        confidence = compute_confidence(edge, distinct_days)
        state = edge["state"]
        if state == "candidate" and is_promotable_to_expected(edge, distinct_days):
            state = "observed"
        edge["confidence"] = confidence
        edge["state"] = state
        self.storage.upsert_edge(edge, record_history=False)
        return edge

    def rebuild_boundary_component(self, entity_id: str, boundary_type: BoundaryType) -> BoundaryComponent:
        edges = [
            e for e in self.graph.entity_edges(entity_id)
            if RELATION_TO_BOUNDARY.get(e["relation"], BoundaryType.PROCESS) == boundary_type
        ]
        observed = [e["id"] for e in edges if e["state"] in ("observed", "expected")]
        expected = [e["id"] for e in edges if e["state"] == "expected"]

        freq_profile: Dict[str, float] = defaultdict(float)
        for e in edges:
            freq_profile[e["target_id"]] += e.get("frequency", 0)

        # Timing profile: hour-of-day histogram derived from edge_history timestamps.
        hour_hist = [0] * 24
        for e in edges:
            hist = self.storage.edge_history(e["id"])
            for h in hist:
                hour_hist[int((h["changed_at"] % 86400) // 3600)] += 1

        confidences = [e["confidence"] for e in edges] or [0.0]
        component = BoundaryComponent(
            entity_id=entity_id,
            boundary_type=boundary_type,
            observed_relation_ids=observed,
            expected_relation_ids=expected,
            allowed_patterns=[{"target": k, "weight": v} for k, v in freq_profile.items()],
            frequency_profile=dict(freq_profile),
            timing_profile={"hour_histogram": hour_hist},
            confidence=round(sum(confidences) / len(confidences), 4),
            criticality="normal",
            version=1,
            provenance=[e["source"] for e in edges][:20],
            updated_at=now_ts(),
        )
        existing = self.storage.get_boundary_component(entity_id, boundary_type.value)
        if existing:
            component.version = existing["data"].get("version", 1) + 1
        self.storage.save_boundary_component(entity_id, boundary_type.value, component.__dict__)
        return component

    def rebuild_all_boundaries(self, entity_id: str) -> List[BoundaryComponent]:
        edges = self.graph.entity_edges(entity_id)
        for e in edges:
            self.update_confidence_and_state(e)
        touched_types = {RELATION_TO_BOUNDARY.get(e["relation"], BoundaryType.PROCESS) for e in edges}
        return [self.rebuild_boundary_component(entity_id, bt) for bt in touched_types] or []

    def get_full_boundary(self, entity_id: str) -> Dict[str, Any]:
        components = self.storage.all_boundary_components(entity_id)
        return {c["boundary_type"]: c["data"] for c in components}

    def stability_index(self, entity_id: str) -> float:
        """0..1 — how stable this entity's boundary has been recently.
        High churn (many candidate/new edges relative to observed/expected)
        lowers stability."""
        edges = self.graph.entity_edges(entity_id)
        if not edges:
            return 1.0
        stable = len([e for e in edges if e["state"] in ("observed", "expected")])
        return round(stable / len(edges), 4)
