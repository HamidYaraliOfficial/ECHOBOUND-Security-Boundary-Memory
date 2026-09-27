"""
Boundary Detection Benchmark Lab + Model Evaluation Sandbox + Rule Tuning
Studio + Security Regression Suite.

Runs detectors against the Synthetic Security World's ground-truth
scenarios and reports detection latency, false-positive/negative candidate
rate, boundary stability, and basic resource/throughput numbers.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from .drift import BoundaryDriftEngine
from .storage import SQLiteStorage, get_storage
from .synthetic import SCENARIOS, SyntheticSecurityWorldGenerator


class BoundaryDetectionBenchmarkLab:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self.drift_engine = BoundaryDriftEngine(self.storage)

    def run(self, seed: int = 42, scenarios: List[str] | None = None) -> Dict[str, Any]:
        scenarios = scenarios or SCENARIOS
        generator = SyntheticSecurityWorldGenerator(seed=seed, storage=self.storage)
        world = generator.generate_world(tenant="benchmark")

        results = []
        for scenario in scenarios:
            t0 = time.time()
            try:
                injected = generator.inject_scenario(scenario, tenant="benchmark")
            except Exception as exc:
                results.append({"scenario": scenario, "error": str(exc)})
                continue
            drifts = self.drift_engine.run_for_entity(injected["entity_id"], context={"tenant": "benchmark"})
            latency_ms = (time.time() - t0) * 1000
            results.append({
                "scenario": scenario,
                "entity_id": injected["entity_id"],
                "drifts_detected": len(drifts),
                "detection_latency_ms": round(latency_ms, 2),
            })

        expected_to_detect = {"new_relationship", "burst_drift", "deployment_induced_drift"}
        detected_scenarios = {r["scenario"] for r in results if r.get("drifts_detected", 0) > 0}
        false_negatives = expected_to_detect - detected_scenarios
        return {
            "world": world,
            "results": results,
            "false_negative_candidates": sorted(false_negatives),
            "summary": {
                "scenarios_run": len(results),
                "avg_latency_ms": round(sum(r.get("detection_latency_ms", 0) for r in results) / max(1, len(results)), 2),
            },
        }


class ModelEvaluationSandbox:
    """Runs alternative baseline-building strategies over the same historical
    replay so an analyst can compare results before enabling one in
    production. Reference implementation ships one strategy (the default
    BoundaryBaselineEngine); the interface is designed for more to be added."""

    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()

    def evaluate(self, entity_id: str) -> Dict[str, Any]:
        from .boundary_engine import BoundaryMemoryEngine
        engine = BoundaryMemoryEngine(self.storage)
        stability = engine.stability_index(entity_id)
        return {"entity_id": entity_id, "strategy": "default", "stability_index": stability}


class RuleTuningStudio:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()

    def simulate_threshold(self, min_observations: int, min_span_hours: float, entity_id: str) -> Dict[str, Any]:
        from .confidence import is_promotable_to_expected
        from .graph import TemporalSecurityGraph
        graph = TemporalSecurityGraph(self.storage)
        edges = graph.entity_edges(entity_id)
        promoted = 0
        for e in edges:
            span_hours = (e["last_seen"] - e["start_time"]) / 3600.0
            if e.get("frequency", 0) >= min_observations and span_hours >= min_span_hours:
                promoted += 1
        return {"entity_id": entity_id, "would_promote": promoted, "total_edges": len(edges)}


class SecurityRegressionSuite:
    """Re-runs previously recorded scenarios after a detector/baseline/
    schema/collector change and reports which scenario outcomes changed."""

    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self.benchmark = BoundaryDetectionBenchmarkLab(self.storage)

    def run_regression(self, baseline_results: Dict[str, Any], seed: int = 42) -> Dict[str, Any]:
        current = self.benchmark.run(seed=seed)
        baseline_by_scenario = {r["scenario"]: r for r in baseline_results.get("results", [])}
        regressions = []
        for r in current["results"]:
            prior = baseline_by_scenario.get(r["scenario"])
            if prior and prior.get("drifts_detected", 0) > 0 and r.get("drifts_detected", 0) == 0:
                regressions.append({"scenario": r["scenario"], "issue": "detection_lost"})
        return {"current": current, "regressions": regressions}
