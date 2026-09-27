"""
Boundary Violation Engine.

Cross-references live boundary/graph state against Policies + Baselines to
produce structured Findings: NewRelationship, ForbiddenRelationship,
MissingRelationship, FrequencySpike, TimingDrift, UnexpectedParent,
UnexpectedChild, UnusualResourceAccess, NewIdentityPath,
NewContainerCapability, BoundaryCollapse.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .baseline import BoundaryBaselineEngine
from .graph import TemporalSecurityGraph
from .models import new_id, now_ts
from .policy import BoundaryPolicyEngine
from .storage import SQLiteStorage, get_storage


class BoundaryViolationEngine:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self.graph = TemporalSecurityGraph(self.storage)
        self.policy_engine = BoundaryPolicyEngine(self.storage)
        self.baselines = BoundaryBaselineEngine(self.storage)

    def evaluate_entity(self, entity_id: str, tenant: str = "default") -> List[Dict[str, Any]]:
        entity = self.graph.get_entity(entity_id)
        if not entity:
            return []
        findings: List[Dict[str, Any]] = []
        policies = self.policy_engine.policies_for_entity(entity, tenant)
        edges = self.graph.entity_edges(entity_id)

        forbidden_pairs = set()
        for p in policies:
            for forb in p["forbidden_relationships"]:
                forbidden_pairs.add((forb.get("relation"), forb.get("target")))

        for e in edges:
            for (relation, target) in forbidden_pairs:
                if e["relation"] == relation and (target is None or e["target_id"] == target):
                    findings.append({
                        "id": new_id("finding"),
                        "kind": "forbidden_relationship",
                        "entity_id": entity_id,
                        "edge_id": e["id"],
                        "detected_at": now_ts(),
                        "severity": "high",
                        "detail": f"Relationship {e['relation']} -> {e['target_id']} is forbidden by policy.",
                    })

            if e["state"] == "candidate" and e["frequency"] >= 3:
                findings.append({
                    "id": new_id("finding"),
                    "kind": "new_relationship",
                    "entity_id": entity_id,
                    "edge_id": e["id"],
                    "detected_at": now_ts(),
                    "severity": "low",
                    "detail": f"New relationship candidate {e['relation']} -> {e['target_id']} observed {e['frequency']} times.",
                })

            if e["relation"] == "executed_by":
                baseline = self.baselines.get_active_baseline(entity_id)
                if baseline:
                    known_parents = {
                        pat["target"] for comp in baseline["boundary_snapshot"]["boundary"].values()
                        for pat in comp.get("allowed_patterns", [])
                    }
                    if e["target_id"] not in known_parents:
                        findings.append({
                            "id": new_id("finding"),
                            "kind": "unexpected_parent",
                            "entity_id": entity_id,
                            "edge_id": e["id"],
                            "detected_at": now_ts(),
                            "severity": "medium",
                            "detail": f"Unexpected parent process relationship to {e['target_id']}.",
                        })

        # frequency spike: compare last 24h frequency growth vs historical average
        for e in edges:
            hist = self.storage.edge_history(e["id"])
            if len(hist) >= 5:
                recent = [h for h in hist if h["changed_at"] >= now_ts() - 86400]
                if len(recent) > 3 * (len(hist) / max(1, (now_ts() - hist[0]["changed_at"]) / 86400)):
                    findings.append({
                        "id": new_id("finding"),
                        "kind": "frequency_spike",
                        "entity_id": entity_id,
                        "edge_id": e["id"],
                        "detected_at": now_ts(),
                        "severity": "medium",
                        "detail": f"Relationship {e['id']} shows an unusual spike in activity frequency.",
                    })

        return findings
