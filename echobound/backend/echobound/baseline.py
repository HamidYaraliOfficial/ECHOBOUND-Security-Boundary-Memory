"""
Boundary Baseline Engine.

Builds Baselines from Boundary Components, scoped by Context (environment,
host, deployment version, container image, namespace, role, time-of-day,
day-of-week, maintenance window) so a normal behavior in staging is never
confused with production. Baselines are versioned, explainable, freezable,
reviewable, retrainable and rollback-able. Never blindly retrained during an
active incident.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .boundary_engine import BoundaryMemoryEngine
from .models import new_id, now_ts
from .storage import SQLiteStorage, get_storage


def context_key(context: Dict[str, Any]) -> str:
    parts = [f"{k}={context[k]}" for k in sorted(context.keys()) if context[k] not in (None, "")]
    return ";".join(parts) or "default"


class BoundaryBaselineEngine:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self.memory = BoundaryMemoryEngine(self.storage)

    def build_baseline(
        self,
        entity_id: str,
        context: Optional[Dict[str, Any]] = None,
        notes: str = "",
        freeze: bool = False,
        suspend_if_incident_active: bool = True,
        incident_active: bool = False,
    ) -> Dict[str, Any]:
        if suspend_if_incident_active and incident_active:
            raise RuntimeError(
                "Refusing to retrain baseline while an incident is active for this entity; "
                "resolve or explicitly override via the Boundary Relearning Workflow."
            )
        context = context or {}
        ck = context_key(context)
        boundary = self.memory.get_full_boundary(entity_id)
        existing_versions = self.storage.list_baseline_versions(entity_id, ck)
        parent_id = existing_versions[0]["id"] if existing_versions else None

        baseline = {
            "id": new_id("baseline"),
            "entity_id": entity_id,
            "context_key": ck,
            "boundary_snapshot": {"boundary": boundary, "context": context},
            "created_at": now_ts(),
            "frozen": freeze,
            "status": "frozen" if freeze else "active",
            "parent_version_id": parent_id,
            "notes": notes,
        }
        # Supersede the previous active baseline in the same context.
        for v in existing_versions:
            if v["status"] == "active":
                self.storage.update_baseline_status(v["id"], "superseded")
        self.storage.save_baseline_version(baseline)
        return baseline

    def get_active_baseline(self, entity_id: str, context: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        ck = context_key(context or {})
        versions = self.storage.list_baseline_versions(entity_id, ck)
        for v in versions:
            if v["status"] in ("active", "frozen"):
                return v
        return versions[0] if versions else None

    def freeze(self, baseline_id: str, analyst: str):
        self.storage.update_baseline_status(baseline_id, "frozen", frozen=True)
        self.storage.audit(analyst, "baseline_freeze", baseline_id, {})

    def rollback(self, entity_id: str, context: Optional[Dict[str, Any]], target_version_id: str, analyst: str):
        ck = context_key(context or {})
        versions = {v["id"]: v for v in self.storage.list_baseline_versions(entity_id, ck)}
        if target_version_id not in versions:
            raise ValueError("target baseline version not found for this entity/context")
        for v in versions.values():
            if v["status"] == "active":
                self.storage.update_baseline_status(v["id"], "superseded")
        self.storage.update_baseline_status(target_version_id, "active")
        self.storage.audit(analyst, "baseline_rollback", entity_id, {"target": target_version_id})
        return versions[target_version_id]

    def history(self, entity_id: str, context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        ck = context_key(context or {}) if context else None
        return self.storage.list_baseline_versions(entity_id, ck)

    def compare(self, baseline_a_id: str, baseline_b_id: str, entity_id: str) -> Dict[str, Any]:
        versions = {v["id"]: v for v in self.storage.list_baseline_versions(entity_id)}
        a, b = versions.get(baseline_a_id), versions.get(baseline_b_id)
        if not a or not b:
            raise ValueError("baseline version not found")

        def target_set(v):
            s = set()
            for bt, comp in v["boundary_snapshot"]["boundary"].items():
                for pat in comp.get("allowed_patterns", []):
                    s.add((bt, pat["target"]))
            return s

        sa, sb = target_set(a), target_set(b)
        return {
            "added": sorted(list(sb - sa)),
            "removed": sorted(list(sa - sb)),
            "unchanged_count": len(sa & sb),
        }
