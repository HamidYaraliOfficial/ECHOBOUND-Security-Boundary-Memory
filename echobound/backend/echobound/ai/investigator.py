"""
Local AI Investigator.

Orchestrates the tool functions above to produce Explainable Anomaly Engine
answers: what was the previous boundary, what changed, when did it start,
what evidence shows it, what context existed, what data-quality caveats
apply, and what similar historical behavior exists. The AI never issues a
final verdict (allow/block/confirmed-incident) — that remains an analyst or
Policy Engine decision; the investigator only explains and hypothesizes.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from ..collector_confidence import CollectorConfidenceModel
from ..storage import SQLiteStorage, get_storage
from .model_abstraction import LocalModelAbstraction
from .tools import InvestigationTools


class LocalAIInvestigator:
    def __init__(self, storage: SQLiteStorage | None = None, model: Optional[LocalModelAbstraction] = None):
        self.storage = storage or get_storage()
        self.tools = InvestigationTools(self.storage)
        self.model = model or LocalModelAbstraction()
        self.confidence_model = CollectorConfidenceModel(self.storage)

    def explain_drift(self, drift_id: str) -> Dict[str, Any]:
        drifts = self.storage.list_drifts()
        drift = next((d for d in drifts if d["id"] == drift_id), None)
        if not drift:
            return {"error": "drift not found"}

        entity_id = drift["entity_id"]
        boundary = self.tools.inspect_boundary(entity_id)
        baseline = self.storage.list_baseline_versions(entity_id)
        first_div = drift.get("first_divergence_at")
        nearby_changes = self.tools.correlate_changes(entity_id, drift["detected_at"])
        low_reliability = self.confidence_model.should_discount_drift(entity_id)

        evidence_bundle = {
            "drift": drift,
            "current_boundary": boundary,
            "most_recent_baseline": baseline[0] if baseline else None,
            "nearby_changes": nearby_changes,
            "data_quality_caveat": (
                "Evidence for this entity leans on lower-reliability telemetry sources; "
                "treat this explanation with extra caution."
                if low_reliability else "Telemetry sources for this entity are considered reliable."
            ),
        }

        structured_answer = {
            "previous_boundary": evidence_bundle["most_recent_baseline"],
            "what_changed": drift["description"],
            "when_it_started": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(first_div)) if first_div else "unknown",
            "evidence": drift["evidence"],
            "context": drift.get("context", {}),
            "data_quality_caveats": evidence_bundle["data_quality_caveat"],
            "similar_historical_behavior": self._find_similar_history(entity_id, drift),
        }

        prompt = (
            "You are assisting a security analyst. Using ONLY the evidence JSON below, "
            "explain what changed for this entity's security boundary, when it likely started, "
            "what evidence supports it, and any caveats. Do not invent facts not present below.\n\n"
            f"EVIDENCE:\n{json.dumps(evidence_bundle, default=str)[:6000]}"
        )
        narrative = self.model.generate(prompt)

        return {"structured": structured_answer, "narrative": narrative, "evidence_bundle": evidence_bundle}

    def _find_similar_history(self, entity_id: str, drift: Dict[str, Any]) -> List[Dict[str, Any]]:
        past = [
            d for d in self.storage.list_drifts(entity_id=entity_id)
            if d["id"] != drift["id"] and d["drift_type"] == drift["drift_type"]
        ]
        return past[:5]

    def generate_hypotheses(self, entity_id: str) -> List[str]:
        """Suggests investigation directions grounded in real correlated
        changes and drift history — phrased as hypotheses to check, not
        conclusions."""
        drifts = self.storage.list_drifts(entity_id=entity_id, limit=10)
        deploys = self.storage.recent_deployments(time.time() - 86400 * 7, entity_id)
        hypotheses = []
        if drifts and deploys:
            hypotheses.append(
                "This entity has both recent boundary drift and a recent deployment/config change — "
                "check whether the drift timestamp falls after the deployment timestamp."
            )
        if drifts and not deploys:
            hypotheses.append(
                "Boundary drift with no correlated deployment nearby — consider whether this is "
                "unauthorized change, a missed/unlogged change, or a slow behavioral shift."
            )
        if not drifts:
            hypotheses.append("No recent drift recorded for this entity; boundary currently appears stable.")
        return hypotheses

    def suggest_investigation_queries(self, entity_id: str) -> List[str]:
        return [
            f"new destinations for {entity_id} in the last 30 days",
            f"boundary changes for {entity_id} in the last 90 days",
            f"first creation time of the most recent new relationship for {entity_id}",
            f"compare {entity_id} boundary now vs its most recent frozen baseline",
        ]
