"""
Storage layer for ECHOBOUND.

Design goal: keep a clean provider-independent interface (`Storage`) so the
reference SQLite implementation (`SQLiteStorage`) can later be swapped for a
PostgreSQL / graph-native backend without touching the engines above it. All
engines in this codebase talk to `Storage`, never to SQL directly.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Optional

from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS entities (
    id TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    archetype TEXT,
    archetype_overridden INTEGER DEFAULT 0,
    attributes TEXT
);
CREATE INDEX IF NOT EXISTS idx_entities_tenant_type ON entities(tenant, type);

CREATE TABLE IF NOT EXISTS edges (
    id TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    start_time REAL NOT NULL,
    end_time REAL,
    last_seen REAL NOT NULL,
    frequency INTEGER DEFAULT 1,
    confidence REAL DEFAULT 0.1,
    source TEXT,
    state TEXT NOT NULL,
    version INTEGER DEFAULT 1,
    boundary_type TEXT,
    context TEXT
);
CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(source_id);
CREATE INDEX IF NOT EXISTS idx_edges_tgt ON edges(target_id);
CREATE INDEX IF NOT EXISTS idx_edges_state ON edges(state);
CREATE INDEX IF NOT EXISTS idx_edges_last_seen ON edges(last_seen);

CREATE TABLE IF NOT EXISTS edge_history (
    hist_id INTEGER PRIMARY KEY AUTOINCREMENT,
    edge_id TEXT NOT NULL,
    changed_at REAL NOT NULL,
    change_type TEXT NOT NULL,
    snapshot TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_edge_history_edge ON edge_history(edge_id);

CREATE TABLE IF NOT EXISTS raw_events (
    event_id TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    ts REAL NOT NULL,
    monotonic_ts REAL,
    host_id TEXT,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    source TEXT,
    integrity_flags TEXT
);
CREATE INDEX IF NOT EXISTS idx_raw_events_ts ON raw_events(ts);
CREATE INDEX IF NOT EXISTS idx_raw_events_kind ON raw_events(kind);

CREATE TABLE IF NOT EXISTS boundary_components (
    entity_id TEXT NOT NULL,
    boundary_type TEXT NOT NULL,
    data TEXT NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (entity_id, boundary_type)
);

CREATE TABLE IF NOT EXISTS boundary_snapshots (
    id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL,
    tenant TEXT NOT NULL,
    taken_at REAL NOT NULL,
    label TEXT,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_entity ON boundary_snapshots(entity_id);

CREATE TABLE IF NOT EXISTS baseline_versions (
    id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL,
    context_key TEXT NOT NULL,
    boundary_snapshot TEXT NOT NULL,
    created_at REAL NOT NULL,
    frozen INTEGER DEFAULT 0,
    status TEXT DEFAULT 'active',
    parent_version_id TEXT,
    notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_baseline_entity ON baseline_versions(entity_id, context_key);

CREATE TABLE IF NOT EXISTS drifts (
    id TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    boundary_type TEXT NOT NULL,
    drift_type TEXT NOT NULL,
    detected_at REAL NOT NULL,
    first_divergence_at REAL,
    description TEXT,
    evidence TEXT,
    confidence REAL,
    severity TEXT,
    context TEXT,
    deployment_correlated INTEGER DEFAULT 0,
    feedback_label TEXT,
    incident_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_drifts_entity ON drifts(entity_id);
CREATE INDEX IF NOT EXISTS idx_drifts_time ON drifts(detected_at);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    title TEXT,
    drift_ids TEXT,
    entity_ids TEXT,
    opened_at REAL,
    state TEXT,
    severity TEXT,
    notes TEXT,
    tags TEXT
);

CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    entity_selector TEXT,
    allowed_relationships TEXT,
    forbidden_relationships TEXT,
    expected_frequency TEXT,
    time_windows TEXT,
    allowed_sources TEXT,
    allowed_destinations TEXT,
    change_policy TEXT,
    version INTEGER,
    created_at REAL,
    enabled INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS operating_hours (
    id TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    timezone TEXT,
    windows TEXT,
    maintenance_windows TEXT,
    updated_at REAL,
    updated_by TEXT
);

CREATE TABLE IF NOT EXISTS deployments (
    id TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    entity_id TEXT,
    kind TEXT,
    ref TEXT,
    happened_at REAL,
    metadata TEXT
);
CREATE INDEX IF NOT EXISTS idx_deployments_time ON deployments(happened_at);

CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    title TEXT,
    state TEXT,
    entity_ids TEXT,
    drift_ids TEXT,
    notes TEXT,
    created_at REAL,
    updated_at REAL
);

CREATE TABLE IF NOT EXISTS feedback (
    id TEXT PRIMARY KEY,
    drift_id TEXT NOT NULL,
    label TEXT NOT NULL,
    analyst TEXT,
    created_at REAL,
    comment TEXT
);

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    host_id TEXT,
    agent_version TEXT,
    kernel_version TEXT,
    status TEXT,
    events_per_sec REAL,
    dropped_events INTEGER,
    buffer_usage REAL,
    last_heartbeat REAL,
    capabilities TEXT
);

CREATE TABLE IF NOT EXISTS candidate_relations (
    id TEXT PRIMARY KEY,
    edge_id TEXT NOT NULL,
    first_seen REAL,
    observations INTEGER DEFAULT 1,
    analyst_action TEXT DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    actor TEXT,
    action TEXT,
    target TEXT,
    details TEXT
);
"""


class SQLiteStorage:
    """Reference storage backend. Thread-safe via a single serialized lock,
    which is sufficient for the reference/demo deployment profile; swap for
    PostgreSQL (see deploy/docker/postgres-init.sql) for concurrent production
    workloads."""

    def __init__(self, path: Optional[str] = None):
        self.path = path or settings.sqlite_path
        self._local = threading.local()
        self._lock = threading.RLock()
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            conn = sqlite3.connect(self.path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            self._local.conn = conn
        return self._local.conn

    def _init_schema(self):
        with self._lock:
            self._conn().executescript(SCHEMA)
            self._conn().commit()

    @contextmanager
    def tx(self):
        with self._lock:
            conn = self._conn()
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    # ---------------------------------------------------------------- utils
    @staticmethod
    def _j(obj: Any) -> str:
        return json.dumps(obj, default=str)

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return {k: row[k] for k in row.keys()}

    # -------------------------------------------------------------- entities
    def upsert_entity(self, e: Dict[str, Any]):
        with self.tx() as c:
            c.execute(
                """INSERT INTO entities(id, tenant, type, name, first_seen, last_seen,
                       archetype, archetype_overridden, attributes)
                   VALUES(?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                       last_seen=excluded.last_seen,
                       name=excluded.name,
                       attributes=excluded.attributes,
                       archetype=CASE WHEN entities.archetype_overridden=1
                                       THEN entities.archetype ELSE excluded.archetype END
                """,
                (
                    e["id"], e.get("tenant", "default"), e["type"], e["name"],
                    e["first_seen"], e["last_seen"], e.get("archetype"),
                    int(e.get("archetype_overridden", False)), self._j(e.get("attributes", {})),
                ),
            )

    def get_entity(self, entity_id: str) -> Optional[Dict[str, Any]]:
        cur = self._conn().execute("SELECT * FROM entities WHERE id=?", (entity_id,))
        row = cur.fetchone()
        if not row:
            return None
        d = self._row_to_dict(row)
        d["attributes"] = json.loads(d["attributes"] or "{}")
        return d

    def list_entities(self, tenant: str = "default", type_filter: Optional[str] = None,
                       search: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        q = "SELECT * FROM entities WHERE tenant=?"
        params: List[Any] = [tenant]
        if type_filter:
            q += " AND type=?"
            params.append(type_filter)
        if search:
            q += " AND name LIKE ?"
            params.append(f"%{search}%")
        q += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        rows = self._conn().execute(q, params).fetchall()
        out = []
        for r in rows:
            d = self._row_to_dict(r)
            d["attributes"] = json.loads(d["attributes"] or "{}")
            out.append(d)
        return out

    # ----------------------------------------------------------------- edges
    def upsert_edge(self, e: Dict[str, Any], record_history: bool = True):
        with self.tx() as c:
            existing = c.execute("SELECT * FROM edges WHERE id=?", (e["id"],)).fetchone()
            c.execute(
                """INSERT INTO edges(id, tenant, source_id, target_id, relation, start_time,
                       end_time, last_seen, frequency, confidence, source, state, version,
                       boundary_type, context)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                       end_time=excluded.end_time, last_seen=excluded.last_seen,
                       frequency=excluded.frequency, confidence=excluded.confidence,
                       state=excluded.state, version=excluded.version, context=excluded.context
                """,
                (
                    e["id"], e.get("tenant", "default"), e["source_id"], e["target_id"],
                    e["relation"], e["start_time"], e.get("end_time"), e["last_seen"],
                    e.get("frequency", 1), e.get("confidence", 0.1), e.get("source", "ebpf"),
                    e["state"], e.get("version", 1), e.get("boundary_type", "process_boundary"),
                    self._j(e.get("context", {})),
                ),
            )
            if record_history:
                change_type = "created" if existing is None else "updated"
                c.execute(
                    "INSERT INTO edge_history(edge_id, changed_at, change_type, snapshot) VALUES(?,?,?,?)",
                    (e["id"], time.time(), change_type, self._j(e)),
                )

    def get_edge(self, edge_id: str) -> Optional[Dict[str, Any]]:
        row = self._conn().execute("SELECT * FROM edges WHERE id=?", (edge_id,)).fetchone()
        if not row:
            return None
        d = self._row_to_dict(row)
        d["context"] = json.loads(d["context"] or "{}")
        return d

    def find_edge(self, source_id: str, target_id: str, relation: str) -> Optional[Dict[str, Any]]:
        row = self._conn().execute(
            "SELECT * FROM edges WHERE source_id=? AND target_id=? AND relation=?",
            (source_id, target_id, relation),
        ).fetchone()
        if not row:
            return None
        d = self._row_to_dict(row)
        d["context"] = json.loads(d["context"] or "{}")
        return d

    def edges_for_entity(self, entity_id: str, as_source=True, as_target=True,
                          state: Optional[str] = None,
                          since: Optional[float] = None) -> List[Dict[str, Any]]:
        clauses = []
        params: List[Any] = []
        if as_source and as_target:
            clauses.append("(source_id=? OR target_id=?)")
            params += [entity_id, entity_id]
        elif as_source:
            clauses.append("source_id=?")
            params.append(entity_id)
        else:
            clauses.append("target_id=?")
            params.append(entity_id)
        if state:
            clauses.append("state=?")
            params.append(state)
        if since:
            clauses.append("last_seen>=?")
            params.append(since)
        q = "SELECT * FROM edges WHERE " + " AND ".join(clauses) + " ORDER BY last_seen DESC"
        rows = self._conn().execute(q, params).fetchall()
        out = []
        for r in rows:
            d = self._row_to_dict(r)
            d["context"] = json.loads(d["context"] or "{}")
            out.append(d)
        return out

    def edge_history(self, edge_id: str) -> List[Dict[str, Any]]:
        rows = self._conn().execute(
            "SELECT * FROM edge_history WHERE edge_id=? ORDER BY changed_at ASC", (edge_id,)
        ).fetchall()
        out = []
        for r in rows:
            d = self._row_to_dict(r)
            d["snapshot"] = json.loads(d["snapshot"])
            out.append(d)
        return out

    # -------------------------------------------------------------- raw events
    def insert_raw_event(self, ev: Dict[str, Any]):
        with self.tx() as c:
            c.execute(
                """INSERT OR IGNORE INTO raw_events(event_id, tenant, ts, monotonic_ts, host_id,
                       kind, payload, source, integrity_flags) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    ev["event_id"], ev.get("tenant", "default"), ev["ts"], ev.get("monotonic_ts"),
                    ev.get("host_id"), ev["kind"], self._j(ev.get("payload", {})),
                    ev.get("source", "unknown"), self._j(ev.get("integrity_flags", {})),
                ),
            )

    def recent_events(self, kind: Optional[str] = None, limit: int = 500) -> List[Dict[str, Any]]:
        q = "SELECT * FROM raw_events"
        params: List[Any] = []
        if kind:
            q += " WHERE kind=?"
            params.append(kind)
        q += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        rows = self._conn().execute(q, params).fetchall()
        out = []
        for r in rows:
            d = self._row_to_dict(r)
            d["payload"] = json.loads(d["payload"])
            d["integrity_flags"] = json.loads(d["integrity_flags"] or "{}")
            out.append(d)
        return out

    # ---------------------------------------------------------- boundary comp
    def save_boundary_component(self, entity_id: str, boundary_type: str, data: Dict[str, Any]):
        with self.tx() as c:
            c.execute(
                """INSERT INTO boundary_components(entity_id, boundary_type, data, updated_at)
                   VALUES(?,?,?,?)
                   ON CONFLICT(entity_id, boundary_type) DO UPDATE SET
                       data=excluded.data, updated_at=excluded.updated_at""",
                (entity_id, boundary_type, self._j(data), time.time()),
            )

    def get_boundary_component(self, entity_id: str, boundary_type: str) -> Optional[Dict[str, Any]]:
        row = self._conn().execute(
            "SELECT * FROM boundary_components WHERE entity_id=? AND boundary_type=?",
            (entity_id, boundary_type),
        ).fetchone()
        if not row:
            return None
        d = self._row_to_dict(row)
        d["data"] = json.loads(d["data"])
        return d

    def all_boundary_components(self, entity_id: str) -> List[Dict[str, Any]]:
        rows = self._conn().execute(
            "SELECT * FROM boundary_components WHERE entity_id=?", (entity_id,)
        ).fetchall()
        out = []
        for r in rows:
            d = self._row_to_dict(r)
            d["data"] = json.loads(d["data"])
            out.append(d)
        return out

    # ------------------------------------------------------------- snapshots
    def save_snapshot(self, snap: Dict[str, Any]):
        with self.tx() as c:
            c.execute(
                "INSERT INTO boundary_snapshots(id, entity_id, tenant, taken_at, label, data) VALUES(?,?,?,?,?,?)",
                (snap["id"], snap["entity_id"], snap.get("tenant", "default"), snap["taken_at"],
                 snap.get("label", ""), self._j(snap["data"])),
            )

    def list_snapshots(self, entity_id: str) -> List[Dict[str, Any]]:
        rows = self._conn().execute(
            "SELECT * FROM boundary_snapshots WHERE entity_id=? ORDER BY taken_at DESC", (entity_id,)
        ).fetchall()
        out = []
        for r in rows:
            d = self._row_to_dict(r)
            d["data"] = json.loads(d["data"])
            out.append(d)
        return out

    # ------------------------------------------------------------- baselines
    def save_baseline_version(self, b: Dict[str, Any]):
        with self.tx() as c:
            c.execute(
                """INSERT INTO baseline_versions(id, entity_id, context_key, boundary_snapshot,
                       created_at, frozen, status, parent_version_id, notes)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (b["id"], b["entity_id"], b["context_key"], self._j(b["boundary_snapshot"]),
                 b["created_at"], int(b.get("frozen", False)), b.get("status", "active"),
                 b.get("parent_version_id"), b.get("notes", "")),
            )

    def update_baseline_status(self, baseline_id: str, status: str, frozen: Optional[bool] = None):
        with self.tx() as c:
            if frozen is None:
                c.execute("UPDATE baseline_versions SET status=? WHERE id=?", (status, baseline_id))
            else:
                c.execute(
                    "UPDATE baseline_versions SET status=?, frozen=? WHERE id=?",
                    (status, int(frozen), baseline_id),
                )

    def list_baseline_versions(self, entity_id: str, context_key: Optional[str] = None) -> List[Dict[str, Any]]:
        q = "SELECT * FROM baseline_versions WHERE entity_id=?"
        params: List[Any] = [entity_id]
        if context_key:
            q += " AND context_key=?"
            params.append(context_key)
        q += " ORDER BY created_at DESC"
        rows = self._conn().execute(q, params).fetchall()
        out = []
        for r in rows:
            d = self._row_to_dict(r)
            d["boundary_snapshot"] = json.loads(d["boundary_snapshot"])
            out.append(d)
        return out

    # ---------------------------------------------------------------- drifts
    def save_drift(self, d: Dict[str, Any]):
        with self.tx() as c:
            c.execute(
                """INSERT INTO drifts(id, tenant, entity_id, boundary_type, drift_type, detected_at,
                       first_divergence_at, description, evidence, confidence, severity, context,
                       deployment_correlated, feedback_label, incident_id)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (d["id"], d.get("tenant", "default"), d["entity_id"], d["boundary_type"],
                 d["drift_type"], d["detected_at"], d.get("first_divergence_at"),
                 d.get("description", ""), self._j(d.get("evidence", [])), d.get("confidence", 0.5),
                 d.get("severity", "low"), self._j(d.get("context", {})),
                 int(d.get("deployment_correlated", False)), d.get("feedback_label"),
                 d.get("incident_id")),
            )

    def set_drift_feedback(self, drift_id: str, label: str):
        with self.tx() as c:
            c.execute("UPDATE drifts SET feedback_label=? WHERE id=?", (label, drift_id))

    def set_drift_incident(self, drift_id: str, incident_id: str):
        with self.tx() as c:
            c.execute("UPDATE drifts SET incident_id=? WHERE id=?", (incident_id, drift_id))

    def list_drifts(self, entity_id: Optional[str] = None, since: Optional[float] = None,
                     severity: Optional[str] = None, limit: int = 500) -> List[Dict[str, Any]]:
        q = "SELECT * FROM drifts WHERE 1=1"
        params: List[Any] = []
        if entity_id:
            q += " AND entity_id=?"
            params.append(entity_id)
        if since:
            q += " AND detected_at>=?"
            params.append(since)
        if severity:
            q += " AND severity=?"
            params.append(severity)
        q += " ORDER BY detected_at DESC LIMIT ?"
        params.append(limit)
        rows = self._conn().execute(q, params).fetchall()
        out = []
        for r in rows:
            d = self._row_to_dict(r)
            d["evidence"] = json.loads(d["evidence"] or "[]")
            d["context"] = json.loads(d["context"] or "{}")
            out.append(d)
        return out

    # ------------------------------------------------------------- incidents
    def save_incident(self, inc: Dict[str, Any]):
        with self.tx() as c:
            c.execute(
                """INSERT INTO incidents(id, tenant, title, drift_ids, entity_ids, opened_at, state,
                       severity, notes, tags) VALUES(?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET state=excluded.state, notes=excluded.notes,
                       tags=excluded.tags, severity=excluded.severity""",
                (inc["id"], inc.get("tenant", "default"), inc["title"], self._j(inc["drift_ids"]),
                 self._j(inc["entity_ids"]), inc["opened_at"], inc.get("state", "open"),
                 inc.get("severity", "medium"), self._j(inc.get("notes", [])), self._j(inc.get("tags", []))),
            )

    def list_incidents(self, state: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        q = "SELECT * FROM incidents"
        params: List[Any] = []
        if state:
            q += " WHERE state=?"
            params.append(state)
        q += " ORDER BY opened_at DESC LIMIT ?"
        params.append(limit)
        rows = self._conn().execute(q, params).fetchall()
        out = []
        for r in rows:
            d = self._row_to_dict(r)
            d["drift_ids"] = json.loads(d["drift_ids"] or "[]")
            d["entity_ids"] = json.loads(d["entity_ids"] or "[]")
            d["notes"] = json.loads(d["notes"] or "[]")
            d["tags"] = json.loads(d["tags"] or "[]")
            out.append(d)
        return out

    # -------------------------------------------------------------- policies
    def save_policy(self, p: Dict[str, Any]):
        with self.tx() as c:
            c.execute(
                """INSERT INTO policies(id, tenant, entity_selector, allowed_relationships,
                       forbidden_relationships, expected_frequency, time_windows, allowed_sources,
                       allowed_destinations, change_policy, version, created_at, enabled)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                       allowed_relationships=excluded.allowed_relationships,
                       forbidden_relationships=excluded.forbidden_relationships,
                       expected_frequency=excluded.expected_frequency,
                       time_windows=excluded.time_windows,
                       allowed_sources=excluded.allowed_sources,
                       allowed_destinations=excluded.allowed_destinations,
                       change_policy=excluded.change_policy, version=excluded.version,
                       enabled=excluded.enabled""",
                (p["id"], p.get("tenant", "default"), self._j(p["entity_selector"]),
                 self._j(p.get("allowed_relationships", [])), self._j(p.get("forbidden_relationships", [])),
                 self._j(p.get("expected_frequency", {})), self._j(p.get("time_windows", [])),
                 self._j(p.get("allowed_sources", [])), self._j(p.get("allowed_destinations", [])),
                 p.get("change_policy", "review"), p.get("version", 1), p.get("created_at", time.time()),
                 int(p.get("enabled", True))),
            )

    def list_policies(self, tenant: str = "default") -> List[Dict[str, Any]]:
        rows = self._conn().execute("SELECT * FROM policies WHERE tenant=?", (tenant,)).fetchall()
        out = []
        for r in rows:
            d = self._row_to_dict(r)
            for f in ("entity_selector", "allowed_relationships", "forbidden_relationships",
                      "expected_frequency", "time_windows", "allowed_sources", "allowed_destinations"):
                d[f] = json.loads(d[f] or "null")
            out.append(d)
        return out

    # -------------------------------------------------------- operating hours
    def save_operating_hours(self, cfg: Dict[str, Any]):
        with self.tx() as c:
            c.execute(
                """INSERT INTO operating_hours(id, tenant, timezone, windows, maintenance_windows,
                       updated_at, updated_by) VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET timezone=excluded.timezone, windows=excluded.windows,
                       maintenance_windows=excluded.maintenance_windows, updated_at=excluded.updated_at,
                       updated_by=excluded.updated_by""",
                (cfg["id"], cfg["tenant"], cfg.get("timezone", "UTC"), self._j(cfg.get("windows", [])),
                 self._j(cfg.get("maintenance_windows", [])), cfg.get("updated_at", time.time()),
                 cfg.get("updated_by", "system")),
            )

    def get_operating_hours(self, tenant: str = "default") -> Optional[Dict[str, Any]]:
        row = self._conn().execute(
            "SELECT * FROM operating_hours WHERE tenant=? ORDER BY updated_at DESC LIMIT 1", (tenant,)
        ).fetchone()
        if not row:
            return None
        d = self._row_to_dict(row)
        d["windows"] = json.loads(d["windows"] or "[]")
        d["maintenance_windows"] = json.loads(d["maintenance_windows"] or "[]")
        return d

    # -------------------------------------------------------------- deploys
    def save_deployment(self, dep: Dict[str, Any]):
        with self.tx() as c:
            c.execute(
                "INSERT INTO deployments(id, tenant, entity_id, kind, ref, happened_at, metadata) VALUES(?,?,?,?,?,?,?)",
                (dep["id"], dep.get("tenant", "default"), dep.get("entity_id"), dep["kind"],
                 dep.get("ref", ""), dep["happened_at"], self._j(dep.get("metadata", {}))),
            )

    def recent_deployments(self, since: float, entity_id: Optional[str] = None) -> List[Dict[str, Any]]:
        q = "SELECT * FROM deployments WHERE happened_at>=?"
        params: List[Any] = [since]
        if entity_id:
            q += " AND (entity_id=? OR entity_id IS NULL)"
            params.append(entity_id)
        rows = self._conn().execute(q, params).fetchall()
        out = []
        for r in rows:
            d = self._row_to_dict(r)
            d["metadata"] = json.loads(d["metadata"] or "{}")
            out.append(d)
        return out

    # ---------------------------------------------------------------- cases
    def save_case(self, case: Dict[str, Any]):
        with self.tx() as c:
            c.execute(
                """INSERT INTO cases(id, tenant, title, state, entity_ids, drift_ids, notes, created_at, updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET title=excluded.title, state=excluded.state,
                       entity_ids=excluded.entity_ids, drift_ids=excluded.drift_ids,
                       notes=excluded.notes, updated_at=excluded.updated_at""",
                (case["id"], case.get("tenant", "default"), case["title"], case.get("state", "open"),
                 self._j(case.get("entity_ids", [])), self._j(case.get("drift_ids", [])),
                 self._j(case.get("notes", [])), case.get("created_at", time.time()), time.time()),
            )

    def list_cases(self, tenant: str = "default") -> List[Dict[str, Any]]:
        rows = self._conn().execute("SELECT * FROM cases WHERE tenant=? ORDER BY updated_at DESC", (tenant,)).fetchall()
        out = []
        for r in rows:
            d = self._row_to_dict(r)
            d["entity_ids"] = json.loads(d["entity_ids"] or "[]")
            d["drift_ids"] = json.loads(d["drift_ids"] or "[]")
            d["notes"] = json.loads(d["notes"] or "[]")
            out.append(d)
        return out

    # ------------------------------------------------------------- feedback
    def save_feedback(self, fb: Dict[str, Any]):
        with self.tx() as c:
            c.execute(
                "INSERT INTO feedback(id, drift_id, label, analyst, created_at, comment) VALUES(?,?,?,?,?,?)",
                (fb["id"], fb["drift_id"], fb["label"], fb.get("analyst", "unknown"),
                 fb.get("created_at", time.time()), fb.get("comment", "")),
            )
        self.set_drift_feedback(fb["drift_id"], fb["label"])

    # --------------------------------------------------------------- agents
    def upsert_agent(self, a: Dict[str, Any]):
        with self.tx() as c:
            c.execute(
                """INSERT INTO agents(id, tenant, host_id, agent_version, kernel_version, status,
                       events_per_sec, dropped_events, buffer_usage, last_heartbeat, capabilities)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET status=excluded.status,
                       events_per_sec=excluded.events_per_sec, dropped_events=excluded.dropped_events,
                       buffer_usage=excluded.buffer_usage, last_heartbeat=excluded.last_heartbeat""",
                (a["id"], a.get("tenant", "default"), a.get("host_id"), a.get("agent_version"),
                 a.get("kernel_version"), a.get("status", "unknown"), a.get("events_per_sec", 0),
                 a.get("dropped_events", 0), a.get("buffer_usage", 0), a.get("last_heartbeat", time.time()),
                 self._j(a.get("capabilities", {}))),
            )

    def list_agents(self, tenant: str = "default") -> List[Dict[str, Any]]:
        rows = self._conn().execute("SELECT * FROM agents WHERE tenant=?", (tenant,)).fetchall()
        out = []
        for r in rows:
            d = self._row_to_dict(r)
            d["capabilities"] = json.loads(d["capabilities"] or "{}")
            out.append(d)
        return out

    # ----------------------------------------------------------------- audit
    def audit(self, actor: str, action: str, target: str, details: Dict[str, Any]):
        with self.tx() as c:
            c.execute(
                "INSERT INTO audit_log(ts, actor, action, target, details) VALUES(?,?,?,?,?)",
                (time.time(), actor, action, target, self._j(details)),
            )

    # ------------------------------------------------------------- raw query
    def raw_query(self, sql: str, params: Iterable[Any] = ()) -> List[Dict[str, Any]]:
        rows = self._conn().execute(sql, tuple(params)).fetchall()
        return [self._row_to_dict(r) for r in rows]


_storage_singleton: Optional[SQLiteStorage] = None


def get_storage() -> SQLiteStorage:
    global _storage_singleton
    if _storage_singleton is None:
        _storage_singleton = SQLiteStorage()
    return _storage_singleton
