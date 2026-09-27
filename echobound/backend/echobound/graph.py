"""
Temporal Security Graph.

Wraps Storage to provide graph-shaped operations over entities and edges,
where every edge carries start/end/last_seen/frequency/confidence/state, so
the graph is never a single point-in-time snapshot but a versioned history.
"""
from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Optional

from .config import settings
from .models import Edge, Entity, EntityType, RelationState, RelationType, BoundaryType, new_id, now_ts
from .storage import SQLiteStorage, get_storage


def stable_edge_id(source_id: str, target_id: str, relation: str, context_key: str = "") -> str:
    raw = f"{source_id}|{target_id}|{relation}|{context_key}"
    return "edge_" + hashlib.sha1(raw.encode()).hexdigest()[:20]


class TemporalSecurityGraph:
    def __init__(self, storage: Optional[SQLiteStorage] = None):
        self.storage = storage or get_storage()

    # ------------------------------------------------------------- entities
    def upsert_entity(self, entity_id: str, entity_type: EntityType, name: str,
                       tenant: str = "default", attributes: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        existing = self.storage.get_entity(entity_id)
        ts = now_ts()
        e = {
            "id": entity_id,
            "tenant": tenant,
            "type": entity_type.value if isinstance(entity_type, EntityType) else entity_type,
            "name": name,
            "first_seen": existing["first_seen"] if existing else ts,
            "last_seen": ts,
            "archetype": existing.get("archetype") if existing else None,
            "archetype_overridden": existing.get("archetype_overridden", False) if existing else False,
            "attributes": {**(existing.get("attributes", {}) if existing else {}), **(attributes or {})},
        }
        self.storage.upsert_entity(e)
        return e

    def get_entity(self, entity_id: str) -> Optional[Dict[str, Any]]:
        return self.storage.get_entity(entity_id)

    def find_entities(self, tenant="default", type_filter=None, search=None, limit=200):
        return self.storage.list_entities(tenant, type_filter, search, limit)

    # ---------------------------------------------------------------- edges
    def observe_relationship(
        self,
        source_id: str,
        target_id: str,
        relation: RelationType,
        boundary_type: BoundaryType,
        tenant: str = "default",
        source: str = "ebpf",
        context: Optional[Dict[str, Any]] = None,
        context_key: str = "",
        weight: int = 1,
    ) -> Dict[str, Any]:
        """Record a single observation of a relationship. New relationships
        start as CANDIDATE; repeated/aged observations are promoted by the
        Boundary Memory Engine (see boundary_engine.py), never automatically
        here, so a single event never silently rewrites the canonical
        boundary."""
        relation_value = relation.value if isinstance(relation, RelationType) else relation
        eid = stable_edge_id(source_id, target_id, relation_value, context_key)
        existing = self.storage.get_edge(eid)
        ts = now_ts()
        if existing:
            edge = {
                **existing,
                "end_time": None,
                "last_seen": ts,
                "frequency": existing["frequency"] + weight,
                "context": {**existing.get("context", {}), **(context or {})},
            }
        else:
            edge = Edge(
                id=eid, source_id=source_id, target_id=target_id, relation=relation,
                tenant=tenant, start_time=ts, last_seen=ts, frequency=weight,
                confidence=0.1, source=source, state=RelationState.CANDIDATE,
                version=1, context=context or {}, boundary_type=boundary_type,
            ).to_dict()
        self.storage.upsert_edge(edge)
        return edge

    def set_edge_state(self, edge_id: str, state: RelationState, confidence: Optional[float] = None):
        edge = self.storage.get_edge(edge_id)
        if not edge:
            return None
        edge["state"] = state.value if isinstance(state, RelationState) else state
        if confidence is not None:
            edge["confidence"] = confidence
        edge["version"] = edge.get("version", 1) + 1
        self.storage.upsert_edge(edge)
        return edge

    def entity_edges(self, entity_id: str, state: Optional[str] = None,
                      since: Optional[float] = None) -> List[Dict[str, Any]]:
        return self.storage.edges_for_entity(entity_id, True, True, state, since)

    def boundary_at(self, entity_id: str, timestamp: float) -> List[Dict[str, Any]]:
        """Reconstruct which relationships were active for an entity at a
        given point in time, using start_time/end_time/last_seen."""
        all_edges = self.storage.edges_for_entity(entity_id)
        out = []
        for e in all_edges:
            if e["start_time"] <= timestamp and (e["end_time"] is None or e["end_time"] >= timestamp):
                # last_seen must also be plausible: an edge "active" needs a
                # last_seen within a generous window of the query timestamp
                # OR the query timestamp is inside [start_time, last_seen].
                if e["start_time"] <= timestamp <= max(e["last_seen"], timestamp):
                    out.append(e)
        return out

    def diff_between(self, entity_id: str, t1: float, t2: float) -> Dict[str, Any]:
        before = {(e["target_id"], e["relation"]): e for e in self.boundary_at(entity_id, t1)}
        after = {(e["target_id"], e["relation"]): e for e in self.boundary_at(entity_id, t2)}
        added = [after[k] for k in after.keys() - before.keys()]
        removed = [before[k] for k in before.keys() - after.keys()]
        persisted = []
        for k in after.keys() & before.keys():
            b, a = before[k], after[k]
            shift = {}
            if abs(a.get("frequency", 0) - b.get("frequency", 0)) / max(1, b.get("frequency", 1)) > 0.5:
                shift["frequency_shift"] = {"from": b["frequency"], "to": a["frequency"]}
            if shift:
                persisted.append({"edge": a, "shift": shift})
        return {"added": added, "removed": removed, "shifted": persisted}

    def mark_stale_relationships(self, tenant: str = "default"):
        """Boundary Memory Decay/Retention: age relationships through
        observed -> dormant -> historical -> expired based on last_seen,
        never physically deleting them."""
        now = now_ts()
        rows = self.storage.raw_query(
            "SELECT * FROM edges WHERE tenant=? AND state IN ('observed','expected','candidate')",
            (tenant,),
        )
        for r in rows:
            age_days = (now - r["last_seen"]) / 86400.0
            new_state = None
            if age_days >= settings.expired_after_days:
                new_state = "expired"
            elif age_days >= settings.historical_after_days:
                new_state = "historical"
            elif age_days >= settings.dormant_after_days:
                new_state = "dormant"
            if new_state:
                self.set_edge_state(r["id"], RelationState(new_state))
