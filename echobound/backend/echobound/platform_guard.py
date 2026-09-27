"""
Platform Boundary Guard + Self-Observing Detection Layer.

ECHOBOUND models the health of its *own* pipeline the same way it models
any monitored entity, so a drop in ingested events caused by a broken
worker, database connection or queue is never misinterpreted as a security
signal ("nothing happened") rather than a platform-health problem
("we stopped being able to see anything").
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from .storage import SQLiteStorage, get_storage


class PlatformBoundaryGuard:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()

    def ingestion_health(self, window_seconds: float = 300) -> Dict[str, Any]:
        since = time.time() - window_seconds
        rows = self.storage.raw_query("SELECT COUNT(*) as c FROM raw_events WHERE ts>=?", (since,))
        count = rows[0]["c"] if rows else 0
        rate = count / window_seconds
        healthy = rate > 0 or window_seconds < 60  # brand-new deployments get a grace period
        return {
            "window_seconds": window_seconds, "event_count": count, "events_per_sec": round(rate, 3),
            "healthy": healthy,
            "note": "A drop to zero here means investigate the pipeline, not the absence of a threat.",
        }


class SelfObservingDetectionLayer:
    """ECHOBOUND's own components (workers, detectors, DB connections,
    queues, AI components) get a lightweight boundary memory too: expected
    heartbeat cadence, expected connection targets. Anomalies here point at
    the platform itself, not a monitored entity."""

    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self._component_heartbeats: Dict[str, float] = {}
        self._expected_cadence_s: Dict[str, float] = {}

    def register_component(self, name: str, expected_cadence_s: float):
        self._expected_cadence_s[name] = expected_cadence_s

    def heartbeat(self, name: str):
        self._component_heartbeats[name] = time.time()

    def check_components(self) -> List[Dict[str, Any]]:
        now = time.time()
        findings = []
        for name, cadence in self._expected_cadence_s.items():
            last = self._component_heartbeats.get(name)
            if last is None:
                findings.append({"component": name, "status": "never_seen"})
                continue
            if now - last > cadence * 3:
                findings.append({
                    "component": name, "status": "missed_heartbeats",
                    "seconds_since_last": round(now - last, 1),
                })
        return findings
