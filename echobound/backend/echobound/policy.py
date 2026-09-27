"""
Boundary Policy Engine.

Lets analysts declare Expected Boundary Contracts ("this service must only
talk to these databases", "this container must never gain new
capabilities", ...). Policies are versioned, context-aware, explainable and
simulate-able before being turned on.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .graph import TemporalSecurityGraph
from .models import new_id, now_ts
from .storage import SQLiteStorage, get_storage


class BoundaryPolicyEngine:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self.graph = TemporalSecurityGraph(self.storage)

    def create_policy(
        self,
        entity_selector: Dict[str, Any],
        allowed_relationships: Optional[List[Dict[str, Any]]] = None,
        forbidden_relationships: Optional[List[Dict[str, Any]]] = None,
        expected_frequency: Optional[Dict[str, Any]] = None,
        time_windows: Optional[List[Dict[str, Any]]] = None,
        allowed_sources: Optional[List[str]] = None,
        allowed_destinations: Optional[List[str]] = None,
        change_policy: str = "review",
        tenant: str = "default",
    ) -> Dict[str, Any]:
        policy = {
            "id": new_id("policy"),
            "tenant": tenant,
            "entity_selector": entity_selector,
            "allowed_relationships": allowed_relationships or [],
            "forbidden_relationships": forbidden_relationships or [],
            "expected_frequency": expected_frequency or {},
            "time_windows": time_windows or [],
            "allowed_sources": allowed_sources or [],
            "allowed_destinations": allowed_destinations or [],
            "change_policy": change_policy,
            "version": 1,
            "created_at": now_ts(),
            "enabled": True,
        }
        self.storage.save_policy(policy)
        return policy

    def list_policies(self, tenant: str = "default") -> List[Dict[str, Any]]:
        return self.storage.list_policies(tenant)

    def _selector_matches(self, selector: Dict[str, Any], entity: Dict[str, Any]) -> bool:
        for key, value in selector.items():
            if key == "type" and entity.get("type") != value:
                return False
            if key == "archetype" and entity.get("archetype") != value:
                return False
            if key == "name_contains" and value not in entity.get("name", ""):
                return False
            if key == "attribute":
                for ak, av in value.items():
                    if entity.get("attributes", {}).get(ak) != av:
                        return False
        return True

    def policies_for_entity(self, entity: Dict[str, Any], tenant: str = "default") -> List[Dict[str, Any]]:
        return [p for p in self.list_policies(tenant) if p["enabled"] and self._selector_matches(p["entity_selector"], entity)]

    def simulate(self, entity_id: str, candidate_relationship: Dict[str, Any], tenant: str = "default") -> Dict[str, Any]:
        """Policy Simulator: given a hypothetical new relationship
        {relation, target_id}, evaluate what verdict it would receive under
        currently active policies without creating anything."""
        entity = self.graph.get_entity(entity_id)
        if not entity:
            return {"verdict": "unknown", "reason": "entity not found"}
        policies = self.policies_for_entity(entity, tenant)
        if not policies:
            return {"verdict": "candidate", "reason": "no policy governs this entity yet"}

        target = candidate_relationship.get("target_id")
        relation = candidate_relationship.get("relation")

        for p in policies:
            for forb in p["forbidden_relationships"]:
                if forb.get("relation") == relation and (forb.get("target") in (None, target)):
                    return {"verdict": "violation", "reason": f"forbidden by policy {p['id']}", "policy_id": p["id"]}

        for p in policies:
            for allow in p["allowed_relationships"]:
                if allow.get("relation") == relation and (allow.get("target") in (None, target)):
                    return {"verdict": "allow", "reason": f"explicitly allowed by policy {p['id']}", "policy_id": p["id"]}
            if p["allowed_destinations"] and target not in p["allowed_destinations"]:
                return {"verdict": "review", "reason": f"destination not in allowed_destinations for policy {p['id']}", "policy_id": p["id"]}

        return {"verdict": "candidate", "reason": "not explicitly allowed or forbidden; will be tracked as candidate"}
