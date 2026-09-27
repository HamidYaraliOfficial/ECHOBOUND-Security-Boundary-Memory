"""
Behavior Archetype Engine.

Classifies entities (mostly processes/services/containers) into explainable
behavioral archetypes based on observed relationship shape, so a new entity
inherits a sane initial Boundary Baseline instead of starting from zero.
Classification is always editable/overridable by an analyst.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from .graph import TemporalSecurityGraph
from .storage import SQLiteStorage, get_storage


@dataclass
class ArchetypeProfile:
    name: str
    description: str
    typical_baseline: Dict[str, Any]


ARCHETYPES: Dict[str, ArchetypeProfile] = {
    "web_server": ArchetypeProfile(
        "web_server",
        "Accepts many inbound connections, few outbound destinations, stable process tree.",
        {"expected_inbound": True, "outbound_diversity": "low", "schedule": "continuous"},
    ),
    "database": ArchetypeProfile(
        "database",
        "Almost exclusively inbound connections from a small stable set of clients.",
        {"expected_inbound": True, "outbound_diversity": "very_low", "schedule": "continuous"},
    ),
    "worker": ArchetypeProfile(
        "worker",
        "Outbound-heavy, connects to queues/databases, periodic or continuous schedule.",
        {"expected_inbound": False, "outbound_diversity": "medium", "schedule": "continuous"},
    ),
    "cli_process": ArchetypeProfile(
        "cli_process",
        "Short-lived, interactively spawned, high process-tree diversity, low network footprint.",
        {"expected_inbound": False, "outbound_diversity": "variable", "schedule": "bursty"},
    ),
    "developer_workstation": ArchetypeProfile(
        "developer_workstation",
        "Diverse process tree, business-hours schedule, many transient outbound destinations.",
        {"expected_inbound": False, "outbound_diversity": "high", "schedule": "business_hours"},
    ),
    "ci_runner": ArchetypeProfile(
        "ci_runner",
        "Ephemeral containers, bursty CPU/network, high churn in dependencies by design.",
        {"expected_inbound": False, "outbound_diversity": "high", "schedule": "bursty"},
    ),
    "kubernetes_pod": ArchetypeProfile(
        "kubernetes_pod",
        "Namespace-scoped, service-mesh communication pattern, stable dependency set.",
        {"expected_inbound": True, "outbound_diversity": "medium", "schedule": "continuous"},
    ),
    "background_job": ArchetypeProfile(
        "background_job",
        "Periodic/scheduled execution, narrow and repeatable relationship set.",
        {"expected_inbound": False, "outbound_diversity": "low", "schedule": "periodic"},
    ),
    "service_account": ArchetypeProfile(
        "service_account",
        "Non-interactive identity, narrow scope of resources, stable authentication pattern.",
        {"expected_inbound": False, "outbound_diversity": "low", "schedule": "continuous"},
    ),
    "unclassified": ArchetypeProfile(
        "unclassified", "Not enough signal yet to classify.", {},
    ),
}


class BehaviorArchetypeEngine:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self.graph = TemporalSecurityGraph(self.storage)

    def _features(self, entity_id: str) -> Dict[str, Any]:
        edges = self.graph.entity_edges(entity_id)
        outbound = [e for e in edges if e["source_id"] == entity_id]
        inbound = [e for e in edges if e["target_id"] == entity_id]
        distinct_out_targets = len({e["target_id"] for e in outbound})
        spawned = [e for e in outbound if e["relation"] == "spawned"]
        return {
            "inbound_count": len(inbound),
            "outbound_count": len(outbound),
            "distinct_out_targets": distinct_out_targets,
            "spawned_children": len(spawned),
            "total_edges": len(edges),
        }

    def classify(self, entity_id: str) -> str:
        entity = self.graph.get_entity(entity_id)
        if not entity:
            return "unclassified"
        if entity.get("archetype_overridden"):
            return entity.get("archetype") or "unclassified"

        feats = self._features(entity_id)
        etype = entity["type"]

        if feats["total_edges"] < 3:
            archetype = "unclassified"
        elif etype == "container" and feats["outbound_count"] > 0 and feats["inbound_count"] == 0:
            archetype = "ci_runner" if feats["distinct_out_targets"] > 6 else "background_job"
        elif etype in ("service", "process") and feats["inbound_count"] > 5 and feats["distinct_out_targets"] <= 2:
            archetype = "database"
        elif etype in ("service", "process") and feats["inbound_count"] > feats["outbound_count"]:
            archetype = "web_server"
        elif etype in ("service", "process") and feats["distinct_out_targets"] >= 5:
            archetype = "worker"
        elif etype == "user":
            archetype = "developer_workstation"
        elif etype == "identity":
            archetype = "service_account"
        elif etype == "container":
            archetype = "kubernetes_pod"
        elif feats["spawned_children"] == 0 and feats["outbound_count"] <= 2:
            archetype = "cli_process"
        else:
            archetype = "unclassified"

        self.storage.upsert_entity({**entity, "archetype": archetype})
        return archetype

    def override(self, entity_id: str, archetype: str, analyst: str):
        entity = self.graph.get_entity(entity_id)
        if not entity:
            return None
        entity["archetype"] = archetype
        entity["archetype_overridden"] = True
        self.storage.upsert_entity(entity)
        self.storage.audit(analyst, "archetype_override", entity_id, {"archetype": archetype})
        return entity

    def describe(self, archetype: str) -> ArchetypeProfile:
        return ARCHETYPES.get(archetype, ARCHETYPES["unclassified"])

    def list_archetypes(self) -> List[Dict[str, Any]]:
        return [
            {"name": a.name, "description": a.description, "typical_baseline": a.typical_baseline}
            for a in ARCHETYPES.values()
        ]
