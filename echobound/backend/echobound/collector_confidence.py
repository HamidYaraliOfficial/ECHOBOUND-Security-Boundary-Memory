"""
Collector Confidence Model + Telemetry Integrity Layer + Blind Spot Detector.

Estimates how reliable each telemetry source is, detects pipeline-health
problems (event drop, backpressure, clock skew, duplicates, out-of-order,
parser failures) so that a dip in event volume caused by a broken collector
is never mistaken for a security-relevant absence of activity, and reports
which entities currently lack adequate visibility.
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Any, Dict, List

from .storage import SQLiteStorage, get_storage

SOURCE_BASE_RELIABILITY = {
    "ebpf": 0.95,
    "ebpf_lsm": 0.97,
    "proc_fallback": 0.6,
    "cloud_audit_log": 0.85,
    "manual": 0.5,
    "synthetic": 0.9,
}


class CollectorConfidenceModel:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()

    def reliability_for_source(self, source: str) -> float:
        return SOURCE_BASE_RELIABILITY.get(source, 0.4)

    def entity_source_breakdown(self, entity_id: str) -> Dict[str, int]:
        edges = self.storage.edges_for_entity(entity_id)
        counts: Dict[str, int] = defaultdict(int)
        for e in edges:
            counts[e.get("source", "unknown")] += 1
        return dict(counts)

    def should_discount_drift(self, entity_id: str) -> bool:
        """If most recent evidence for an entity comes from a low-reliability
        source, drift derived from it should be discounted (surfaced with
        lower confidence) rather than treated as high-confidence security
        signal."""
        breakdown = self.entity_source_breakdown(entity_id)
        total = sum(breakdown.values()) or 1
        low_reliability = sum(v for k, v in breakdown.items() if self.reliability_for_source(k) < 0.7)
        return (low_reliability / total) > 0.5


class TelemetryIntegrityLayer:
    """Tracks per-host pipeline health signals reported by agents."""

    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()

    def record_agent_heartbeat(self, host_id: str, agent_id: str, tenant: str,
                                events_per_sec: float, dropped_events: int,
                                buffer_usage: float, agent_version: str, kernel_version: str,
                                clock_skew_ms: float = 0.0):
        status = "healthy"
        issues = []
        if buffer_usage > 0.85:
            issues.append("backpressure")
            status = "degraded"
        if dropped_events > 0:
            issues.append("event_drop")
            status = "degraded"
        if abs(clock_skew_ms) > 2000:
            issues.append("clock_skew")
            status = "degraded"
        self.storage.upsert_agent({
            "id": agent_id, "tenant": tenant, "host_id": host_id, "agent_version": agent_version,
            "kernel_version": kernel_version, "status": status, "events_per_sec": events_per_sec,
            "dropped_events": dropped_events, "buffer_usage": buffer_usage, "last_heartbeat": time.time(),
            "capabilities": {"issues": issues},
        })
        return {"status": status, "issues": issues}

    def detect_duplicate(self, event_id: str) -> bool:
        rows = self.storage.raw_query("SELECT 1 FROM raw_events WHERE event_id=?", (event_id,))
        return len(rows) > 0

    def detect_out_of_order(self, host_id: str, event_ts: float, tolerance_s: float = 5.0) -> bool:
        rows = self.storage.raw_query(
            "SELECT ts FROM raw_events WHERE host_id=? ORDER BY ts DESC LIMIT 1", (host_id,)
        )
        if not rows:
            return False
        return event_ts < (rows[0]["ts"] - tolerance_s)


class BlindSpotDetector:
    """Flags entities/hosts with insufficient telemetry coverage: important
    processes with incomplete data, or network relationships backed by too
    few/low-reliability sources."""

    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self.confidence_model = CollectorConfidenceModel(self.storage)

    def stale_agents(self, tenant: str = "default", stale_after_seconds: float = 300) -> List[Dict[str, Any]]:
        agents = self.storage.list_agents(tenant)
        now = time.time()
        return [a for a in agents if now - a["last_heartbeat"] > stale_after_seconds]

    def low_visibility_entities(self, tenant: str = "default", limit: int = 50) -> List[Dict[str, Any]]:
        entities = self.storage.list_entities(tenant, limit=limit)
        blind = []
        for e in entities:
            edges = self.storage.edges_for_entity(e["id"])
            if not edges:
                blind.append({"entity": e, "reason": "no_observed_relationships"})
                continue
            if self.confidence_model.should_discount_drift(e["id"]):
                blind.append({"entity": e, "reason": "low_reliability_sources_dominant"})
        return blind
