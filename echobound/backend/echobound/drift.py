"""
Boundary Drift Engine and family.

Includes:
 - BoundaryDriftEngine: temporal, context-aware detection of boundary changes
 - BehavioralBoundaryDiffEngine: added/removed/shifted relationship diff
 - FirstBoundaryDivergenceDetector: finds the first moment behavior diverged
 - BoundaryExpansionDetector / BoundaryContractionDetector
 - BoundaryCollapseDetector: multiple independent boundaries overlapping
 - DeploymentAwareDriftEngine / ChangeCorrelationEngine
 - RecoveryBoundaryEngine
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from .baseline import BoundaryBaselineEngine
from .boundary_engine import BoundaryMemoryEngine
from .graph import TemporalSecurityGraph
from .models import DriftEvent, DriftSeverity, DriftType, BoundaryType, new_id, now_ts
from .storage import SQLiteStorage, get_storage

# Time-of-day drift needs the operating-hours context; imported lazily to
# avoid a circular import (context_engine also stays storage-only).
def _get_context_engine():
    from .context_engine import MaintenanceContextEngine
    return MaintenanceContextEngine


class BehavioralBoundaryDiffEngine:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self.graph = TemporalSecurityGraph(self.storage)

    def diff(self, entity_id: str, baseline_snapshot: Dict[str, Any]) -> Dict[str, Any]:
        current_edges = self.graph.entity_edges(entity_id, state=None)
        current_targets = {(e["relation"], e["target_id"]) for e in current_edges if e["state"] in ("observed", "expected")}

        baseline_targets = set()
        for bt, comp in baseline_snapshot.get("boundary", {}).items():
            for pat in comp.get("allowed_patterns", []):
                baseline_targets.add((bt, pat["target"]))
        # Normalize baseline_targets keyed by boundary_type into relation-shape
        # approximate comparison using target id only, since boundary_type maps
        # loosely to relation categories.
        baseline_target_ids = {t[1] for t in baseline_targets}
        current_target_ids = {t[1] for t in current_targets}

        added = current_target_ids - baseline_target_ids
        removed = baseline_target_ids - current_target_ids

        new_parents, new_children = [], []
        for e in current_edges:
            if e["relation"] == "spawned" and e["target_id"] not in baseline_target_ids:
                new_children.append(e["target_id"])
            if e["relation"] == "executed_by" and e["target_id"] not in baseline_target_ids:
                new_parents.append(e["target_id"])

        return {
            "added_relationships": sorted(added),
            "removed_relationships": sorted(removed),
            "new_parent": new_parents,
            "new_child": new_children,
        }


class FirstBoundaryDivergenceDetector:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()

    def find_first_divergence(self, entity_id: str, target_id: str, relation: str) -> Optional[float]:
        """Return the timestamp of the first edge_history record where this
        (target,relation) pair for the entity first appeared as a new/created
        relationship, i.e. the true start of drift rather than the moment an
        alert fired."""
        edges = self.storage.edges_for_entity(entity_id)
        for e in edges:
            if e["target_id"] == target_id and e["relation"] == relation:
                hist = self.storage.edge_history(e["id"])
                created = [h for h in hist if h["change_type"] == "created"]
                if created:
                    return created[0]["changed_at"]
                return e["start_time"]
        return None


class BoundaryExpansionDetector:
    """A boundary is *expanding* when new relationships/scopes appear that
    were never part of the entity's history. Interpreted with deployment
    context so an expected rollout isn't flagged as a threat."""

    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()

    def detect(self, entity_id: str, diff: Dict[str, Any], recent_deploy: bool) -> Optional[Dict[str, Any]]:
        added = diff.get("added_relationships", [])
        if not added:
            return None
        severity = "low" if recent_deploy else ("medium" if len(added) <= 2 else "high")
        return {
            "kind": "boundary_expansion",
            "added": added,
            "recent_deployment_context": recent_deploy,
            "severity": severity,
        }


class BoundaryContractionDetector:
    """A boundary *contracting* (relationships disappearing) is not
    inherently a threat — could be decommissioning — but is still worth
    surfacing with context."""

    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()

    def detect(self, entity_id: str, diff: Dict[str, Any], recent_deploy: bool) -> Optional[Dict[str, Any]]:
        removed = diff.get("removed_relationships", [])
        if not removed:
            return None
        severity = "info" if recent_deploy else "low"
        return {
            "kind": "boundary_contraction",
            "removed": removed,
            "recent_deployment_context": recent_deploy,
            "severity": severity,
        }


class BoundaryCollapseDetector:
    """Detects when several independent trust boundaries begin overlapping
    at once for one entity — e.g. a process suddenly touching resources from
    multiple historically-separate trust zones simultaneously."""

    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self.graph = TemporalSecurityGraph(self.storage)

    def detect(self, entity_id: str) -> Optional[Dict[str, Any]]:
        edges = self.graph.entity_edges(entity_id, since=now_ts() - 3600)
        zones = set()
        for e in edges:
            zone = e.get("context", {}).get("trust_zone")
            if zone:
                zones.add(zone)
        if len(zones) >= 3:
            return {
                "kind": "boundary_collapse",
                "trust_zones_involved": sorted(zones),
                "severity": "critical",
                "description": f"{len(zones)} independent trust zones observed simultaneously for this entity.",
            }
        return None


class DeploymentAwareDriftEngine:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()

    def recent_deployment_for(self, entity_id: str, window_seconds: float = 3600 * 6) -> bool:
        deploys = self.storage.recent_deployments(now_ts() - window_seconds, entity_id)
        return len(deploys) > 0

    def correlate(self, entity_id: str, drift_time: float, window_seconds: float = 3600 * 6) -> List[Dict[str, Any]]:
        return self.storage.recent_deployments(drift_time - window_seconds, entity_id)


class ChangeCorrelationEngine:
    """Correlates a drift with recent infra/app changes: deployments, config
    changes, feature flags. Kept intentionally simple/deterministic — this is
    a correlation signal for the analyst, not an automatic root-cause claim."""

    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()

    def correlate(self, entity_id: str, at_time: float, window_seconds: float = 3600 * 12) -> Dict[str, Any]:
        deploys = self.storage.recent_deployments(at_time - window_seconds, entity_id)
        return {
            "candidate_causes": deploys,
            "window_seconds": window_seconds,
            "note": "Temporal proximity only — not a confirmed causal link.",
        }


class RecoveryBoundaryEngine:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self.graph = TemporalSecurityGraph(self.storage)

    def assess(self, entity_id: str, pre_incident_snapshot: Dict[str, Any]) -> str:
        current_edges = self.graph.entity_edges(entity_id, state="observed")
        current_targets = {e["target_id"] for e in current_edges}
        pre_targets = set()
        for comp in pre_incident_snapshot.get("boundary", {}).values():
            for pat in comp.get("allowed_patterns", []):
                pre_targets.add(pat["target"])
        if not pre_targets:
            return "unknown"
        overlap = len(current_targets & pre_targets) / max(1, len(pre_targets))
        if overlap >= 0.9:
            return "recovered_to_previous_pattern"
        if overlap <= 0.3 and current_targets:
            return "new_stable_boundary_formed"
        return "unknown"


class BoundaryDriftEngine:
    """Top-level orchestrator that runs the whole drift pipeline for an
    entity and persists DriftEvent records."""

    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self.graph = TemporalSecurityGraph(self.storage)
        self.memory = BoundaryMemoryEngine(self.storage)
        self.baselines = BoundaryBaselineEngine(self.storage)
        self.diff_engine = BehavioralBoundaryDiffEngine(self.storage)
        self.first_divergence = FirstBoundaryDivergenceDetector(self.storage)
        self.expansion = BoundaryExpansionDetector(self.storage)
        self.contraction = BoundaryContractionDetector(self.storage)
        self.collapse = BoundaryCollapseDetector(self.storage)
        self.deploy_aware = DeploymentAwareDriftEngine(self.storage)
        self.correlation = ChangeCorrelationEngine(self.storage)

    def _schedule_drift(self, entity_id: str, context: Dict[str, Any]) -> Optional[DriftEvent]:
        ContextEngineCls = _get_context_engine()
        ctx_engine = ContextEngineCls(self.storage)
        status = ctx_engine.current_status(context.get("tenant", "default"))
        if status["is_open"]:
            return None
        recent = [e for e in self.graph.entity_edges(entity_id) if e["last_seen"] >= now_ts() - 900]
        if not recent:
            return None
        if status.get("in_maintenance_window"):
            return None
        return DriftEvent(
            id=new_id("drift"), entity_id=entity_id, boundary_type=BoundaryType.TEMPORAL,
            drift_type=DriftType.SCHEDULE, detected_at=now_ts(), first_divergence_at=now_ts(),
            description="Activity observed outside configured operating hours and outside any maintenance window.",
            evidence=[{"recent_edge_ids": [e["id"] for e in recent[:10]]}],
            confidence=0.6, severity=DriftSeverity.MEDIUM, context=context,
        )

    def run_for_entity(self, entity_id: str, context: Optional[Dict[str, Any]] = None) -> List[DriftEvent]:
        context = context or {}
        self.memory.rebuild_all_boundaries(entity_id)
        baseline = self.baselines.get_active_baseline(entity_id, context)
        events: List[DriftEvent] = []

        if baseline:
            diff = self.diff_engine.diff(entity_id, baseline["boundary_snapshot"])
            recent_deploy = self.deploy_aware.recent_deployment_for(entity_id)

            expansion = self.expansion.detect(entity_id, diff, recent_deploy)
            if expansion:
                first_div = None
                for target in expansion["added"][:1]:
                    first_div = self.first_divergence.find_first_divergence(entity_id, target, "connected_to")
                events.append(DriftEvent(
                    id=new_id("drift"), entity_id=entity_id, boundary_type=BoundaryType.NETWORK,
                    drift_type=DriftType.RELATIONSHIP, detected_at=now_ts(),
                    first_divergence_at=first_div, description="New relationship(s) outside learned boundary.",
                    evidence=[expansion], confidence=0.7,
                    severity=DriftSeverity(expansion["severity"]), context=context,
                    deployment_correlated=recent_deploy,
                ))

            contraction = self.contraction.detect(entity_id, diff, recent_deploy)
            if contraction:
                events.append(DriftEvent(
                    id=new_id("drift"), entity_id=entity_id, boundary_type=BoundaryType.NETWORK,
                    drift_type=DriftType.RELATIONSHIP, detected_at=now_ts(), first_divergence_at=None,
                    description="Previously established relationship(s) no longer observed.",
                    evidence=[contraction], confidence=0.4,
                    severity=DriftSeverity(contraction["severity"]), context=context,
                    deployment_correlated=recent_deploy,
                ))

        collapse = self.collapse.detect(entity_id)
        if collapse:
            events.append(DriftEvent(
                id=new_id("drift"), entity_id=entity_id, boundary_type=BoundaryType.TRUST,
                drift_type=DriftType.RELATIONSHIP, detected_at=now_ts(), first_divergence_at=now_ts(),
                description=collapse["description"], evidence=[collapse], confidence=0.85,
                severity=DriftSeverity.CRITICAL, context=context,
            ))

        schedule_drift = self._schedule_drift(entity_id, context)
        if schedule_drift:
            events.append(schedule_drift)

        for ev in events:
            self.storage.save_drift(ev.to_dict())
        return events
