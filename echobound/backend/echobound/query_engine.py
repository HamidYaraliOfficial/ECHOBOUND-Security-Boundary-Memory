"""
Temporal Graph Query Engine.

Supports questions like "what new destinations did this process gain in the
last 30 days?", "which boundaries did this user change over 3 months?",
"which services gained new relationships after the latest deployment?", or
"when was this connection first created?" — protected by a Query Cost Guard
(timeout, depth limit, result limit, cancellation).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .config import settings
from .graph import TemporalSecurityGraph
from .storage import SQLiteStorage, get_storage


class QueryTimeoutError(Exception):
    pass


class QueryCancelled(Exception):
    pass


@dataclass
class QueryCostGuard:
    timeout_s: float = settings.query_default_timeout_s
    max_depth: int = settings.query_max_depth
    max_results: int = settings.query_max_results
    _start: float = field(default_factory=time.time)
    _cancelled: bool = False

    def check(self, depth: int = 0, result_count: int = 0):
        if self._cancelled:
            raise QueryCancelled("query was cancelled")
        if time.time() - self._start > self.timeout_s:
            raise QueryTimeoutError(f"query exceeded {self.timeout_s}s timeout")
        if depth > self.max_depth:
            raise QueryTimeoutError(f"query exceeded max depth {self.max_depth}")
        if result_count > self.max_results:
            raise QueryTimeoutError(f"query exceeded max results {self.max_results}")

    def cancel(self):
        self._cancelled = True


class TemporalGraphQueryEngine:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self.graph = TemporalSecurityGraph(self.storage)

    def new_destinations_since(self, entity_id: str, since_ts: float, guard: Optional[QueryCostGuard] = None) -> List[Dict[str, Any]]:
        guard = guard or QueryCostGuard()
        guard.check()
        edges = self.graph.entity_edges(entity_id, since=since_ts)
        out = []
        for e in edges:
            guard.check(result_count=len(out))
            hist = self.storage.edge_history(e["id"])
            created = [h for h in hist if h["change_type"] == "created"]
            first_ts = created[0]["changed_at"] if created else e["start_time"]
            if first_ts >= since_ts:
                out.append(e)
        return out

    def boundary_changes_for_entity(self, entity_id: str, since_ts: float, guard: Optional[QueryCostGuard] = None) -> Dict[str, Any]:
        guard = guard or QueryCostGuard()
        guard.check()
        drifts = [d for d in self.storage.list_drifts(entity_id=entity_id) if d["detected_at"] >= since_ts]
        new_edges = self.new_destinations_since(entity_id, since_ts, guard)
        return {"drifts": drifts, "new_relationships": new_edges}

    def services_with_new_relationships_after_deployment(self, deployment_ref: str, guard: Optional[QueryCostGuard] = None) -> List[Dict[str, Any]]:
        guard = guard or QueryCostGuard()
        guard.check()
        deploys = self.storage.raw_query("SELECT * FROM deployments WHERE ref=?", (deployment_ref,))
        results = []
        for dep in deploys:
            guard.check(result_count=len(results))
            entity_id = dep.get("entity_id")
            if not entity_id:
                continue
            new_edges = self.new_destinations_since(entity_id, dep["happened_at"], guard)
            if new_edges:
                results.append({"entity_id": entity_id, "deployment": dep, "new_relationships": new_edges})
        return results

    def first_creation_time(self, entity_id: str, target_id: str, relation: str) -> Optional[float]:
        e = self.storage.find_edge(entity_id, target_id, relation)
        if not e:
            return None
        hist = self.storage.edge_history(e["id"])
        created = [h for h in hist if h["change_type"] == "created"]
        return created[0]["changed_at"] if created else e["start_time"]

    def search(self, text: str, tenant: str = "default", limit: int = 50) -> List[Dict[str, Any]]:
        """Combined metadata search across entities (Full-Text + Metadata
        component of the Security Memory Search Engine — graph/temporal
        components are exposed via the other query methods above)."""
        return self.graph.find_entities(tenant=tenant, search=text, limit=limit)
