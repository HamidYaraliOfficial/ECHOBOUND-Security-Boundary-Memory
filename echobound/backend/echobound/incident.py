"""
Boundary Incident Correlator + Incident Memory Engine + First Cause Timeline.

Groups temporally- and entity-adjacent drifts into Compound Boundary
Incidents, keeps a historical memory of incidents for later comparison, and
lays out a First Cause Timeline of nearby deployments/config/permission
changes without assuming a definitive cause.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .graph import TemporalSecurityGraph
from .models import CaseState, DriftSeverity, new_id, now_ts
from .storage import SQLiteStorage, get_storage

CORRELATION_WINDOW_SECONDS = 30 * 60
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class BoundaryIncidentCorrelator:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self.graph = TemporalSecurityGraph(self.storage)

    def _related(self, a: Dict[str, Any], b: Dict[str, Any]) -> bool:
        if abs(a["detected_at"] - b["detected_at"]) > CORRELATION_WINDOW_SECONDS:
            return False
        if a["entity_id"] == b["entity_id"]:
            return True
        # entity-aware/graph-aware: related if the two entities are directly
        # connected in the graph.
        edges_a = {e["target_id"] for e in self.graph.entity_edges(a["entity_id"])}
        return b["entity_id"] in edges_a

    def correlate_recent(self, since_ts: float, tenant: str = "default") -> List[Dict[str, Any]]:
        drifts = [d for d in self.storage.list_drifts(since=since_ts) if not d.get("incident_id")]
        drifts.sort(key=lambda d: d["detected_at"])
        groups: List[List[Dict[str, Any]]] = []
        for d in drifts:
            placed = False
            for g in groups:
                if any(self._related(d, member) for member in g):
                    g.append(d)
                    placed = True
                    break
            if not placed:
                groups.append([d])

        incidents = []
        for g in groups:
            if len(g) < 2:
                continue  # a lone drift is not yet a "compound" incident
            entity_ids = sorted({d["entity_id"] for d in g})
            severity = max((d["severity"] for d in g), key=lambda s: SEVERITY_ORDER.get(s, 0))
            incident = {
                "id": new_id("incident"),
                "tenant": tenant,
                "title": f"Compound boundary incident across {len(entity_ids)} entities",
                "drift_ids": [d["id"] for d in g],
                "entity_ids": entity_ids,
                "opened_at": now_ts(),
                "state": CaseState.OPEN.value,
                "severity": severity,
                "notes": [],
                "tags": ["auto_correlated"],
            }
            self.storage.save_incident(incident)
            for d in g:
                self.storage.set_drift_incident(d["id"], incident["id"])
            incidents.append(incident)
        return incidents


class IncidentMemoryEngine:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()

    def list_incidents(self, state=None):
        return self.storage.list_incidents(state)

    def similar_past_incidents(self, incident_id: str) -> List[Dict[str, Any]]:
        incidents = {i["id"]: i for i in self.storage.list_incidents()}
        target = incidents.get(incident_id)
        if not target:
            return []
        target_entities = set(target["entity_ids"])
        scored = []
        for i in incidents.values():
            if i["id"] == incident_id:
                continue
            overlap = len(target_entities & set(i["entity_ids"]))
            if overlap:
                scored.append((overlap, i))
        scored.sort(key=lambda t: t[0], reverse=True)
        return [i for _, i in scored[:10]]

    def add_note(self, incident_id: str, author: str, text: str):
        incidents = {i["id"]: i for i in self.storage.list_incidents()}
        inc = incidents.get(incident_id)
        if not inc:
            raise ValueError("incident not found")
        inc["notes"].append({"author": author, "text": text, "at": now_ts()})
        self.storage.save_incident(inc)
        return inc

    def set_state(self, incident_id: str, state: CaseState, actor: str):
        incidents = {i["id"]: i for i in self.storage.list_incidents()}
        inc = incidents.get(incident_id)
        if not inc:
            raise ValueError("incident not found")
        inc["state"] = state.value
        self.storage.save_incident(inc)
        self.storage.audit(actor, "incident_state_change", incident_id, {"state": state.value})
        return inc


class FirstCauseTimeline:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()

    def build(self, incident_id: str, window_seconds: float = 3600 * 6) -> Dict[str, Any]:
        incidents = {i["id"]: i for i in self.storage.list_incidents()}
        inc = incidents.get(incident_id)
        if not inc:
            raise ValueError("incident not found")
        drifts = [d for d in self.storage.list_drifts() if d["id"] in inc["drift_ids"]]
        drifts.sort(key=lambda d: d.get("first_divergence_at") or d["detected_at"])
        earliest = drifts[0] if drifts else None
        nearby_deploys: List[Dict[str, Any]] = []
        if earliest:
            anchor = earliest.get("first_divergence_at") or earliest["detected_at"]
            for eid in inc["entity_ids"]:
                nearby_deploys += self.storage.recent_deployments(anchor - window_seconds, eid)
        return {
            "incident_id": incident_id,
            "earliest_drift": earliest,
            "ordered_drifts": drifts,
            "nearby_changes": nearby_deploys,
            "disclaimer": "Temporal proximity is shown for investigation; no cause is assumed automatically.",
        }
