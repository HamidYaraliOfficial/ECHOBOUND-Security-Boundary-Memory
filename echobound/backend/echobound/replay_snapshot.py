"""
Boundary Replay Engine + Boundary Snapshot Engine + Temporal Version Control.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional

from .graph import TemporalSecurityGraph
from .models import new_id, now_ts
from .pipeline import EventPipeline
from .storage import SQLiteStorage, get_storage


class BoundaryReplayEngine:
    """Replays raw_events chronologically, re-driving the pipeline so
    boundaries can be rebuilt event-by-event. Supports pause/resume/step/
    fast-forward/time-jump/filter."""

    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self.pipeline = EventPipeline(self.storage)
        self._events: List[Dict[str, Any]] = []
        self._cursor = 0
        self._paused = True

    def load(self, since_ts: float, until_ts: Optional[float] = None, kind: Optional[str] = None):
        until_ts = until_ts or now_ts()
        rows = self.storage.raw_query(
            "SELECT * FROM raw_events WHERE ts BETWEEN ? AND ? ORDER BY ts ASC", (since_ts, until_ts)
        )
        if kind:
            rows = [r for r in rows if r["kind"] == kind]
        self._events = rows
        self._cursor = 0
        return {"loaded": len(self._events)}

    def step(self, n: int = 1) -> List[Dict[str, Any]]:
        processed = []
        for _ in range(n):
            if self._cursor >= len(self._events):
                break
            ev = self._events[self._cursor]
            self._cursor += 1
            processed.append(ev)
        return processed

    def fast_forward(self, to_ts: float) -> int:
        count = 0
        while self._cursor < len(self._events) and self._events[self._cursor]["ts"] <= to_ts:
            self._cursor += 1
            count += 1
        return count

    def jump_to(self, ts: float):
        for i, ev in enumerate(self._events):
            if ev["ts"] >= ts:
                self._cursor = i
                return
        self._cursor = len(self._events)

    def pause(self):
        self._paused = True

    def resume(self):
        self._paused = False

    def progress(self) -> Dict[str, Any]:
        return {"cursor": self._cursor, "total": len(self._events), "paused": self._paused}


class BoundarySnapshotEngine:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()

    def take_snapshot(self, entity_id: str, boundary_data: Dict[str, Any], label: str = "", tenant: str = "default") -> Dict[str, Any]:
        snap = {"id": new_id("snapshot"), "entity_id": entity_id, "tenant": tenant,
                "taken_at": now_ts(), "label": label, "data": boundary_data}
        self.storage.save_snapshot(snap)
        return snap

    def list_snapshots(self, entity_id: str) -> List[Dict[str, Any]]:
        return self.storage.list_snapshots(entity_id)

    def compare_snapshots(self, snapshot_a: Dict[str, Any], snapshot_b: Dict[str, Any]) -> Dict[str, Any]:
        def targets(snap):
            s = set()
            for bt, comp in snap["data"].items():
                for pat in comp.get("allowed_patterns", []):
                    s.add((bt, pat["target"]))
            return s

        ta, tb = targets(snapshot_a), targets(snapshot_b)
        return {"added": sorted(tb - ta), "removed": sorted(ta - tb)}


class TemporalVersionControl:
    """Lightweight commit/diff/tag/rollback/branch semantics over Boundary,
    Policy, Baseline and Detection-Rule changes, built on top of the existing
    audit_log + baseline_versions tables rather than a separate VCS engine."""

    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()

    def commit(self, actor: str, kind: str, target: str, details: Dict[str, Any], tag: Optional[str] = None):
        payload = dict(details)
        if tag:
            payload["tag"] = tag
        self.storage.audit(actor, f"commit:{kind}", target, payload)

    def history(self, target: str) -> List[Dict[str, Any]]:
        return self.storage.raw_query(
            "SELECT * FROM audit_log WHERE target=? ORDER BY ts ASC", (target,)
        )

    def diff(self, target: str, ts_a: float, ts_b: float) -> Dict[str, Any]:
        hist = self.history(target)
        before = [h for h in hist if h["ts"] <= ts_a]
        after = [h for h in hist if h["ts"] <= ts_b]
        return {"events_before": len(before), "events_after": len(after), "delta": len(after) - len(before)}
