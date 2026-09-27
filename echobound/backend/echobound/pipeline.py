"""
Event Pipeline.

Normalizes raw collector events (eBPF or proc-fallback) into Entities and
Relationships inside the Temporal Security Graph, and produces the
Process/Service Identity Fingerprints used to identify entities logically
rather than by name alone.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

from .graph import TemporalSecurityGraph
from .models import EntityType, RelationType, BoundaryType
from .storage import SQLiteStorage, get_storage


def process_fingerprint(host_id: str, pid: int, comm: str, ppid: Optional[int] = None,
                         container_id: Optional[str] = None, user: Optional[str] = None) -> str:
    """A Process Identity Fingerprint that does not rely on name alone: it
    folds in host, pid, parent, container and user context so the same
    binary run in a different context is (correctly) a different logical
    process identity over time, while restarts of the *same* long-lived
    daemon under process-manager supervision can still be recognized by the
    caller via the (host, comm, container, user) subset if desired."""
    raw = f"{host_id}|{pid}|{comm}|{ppid}|{container_id}|{user}"
    return "proc_" + hashlib.sha1(raw.encode()).hexdigest()[:20]


def service_fingerprint(name: str, namespace: Optional[str] = None, version: Optional[str] = None) -> str:
    raw = f"{name}|{namespace}|{version}"
    return "svc_" + hashlib.sha1(raw.encode()).hexdigest()[:20]


class EventPipeline:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self.graph = TemporalSecurityGraph(self.storage)

    def ingest(self, event: Dict[str, Any]):
        self.storage.insert_raw_event(event)
        kind = event["kind"]
        payload = event["payload"]
        host_id = event.get("host_id", "unknown-host")
        tenant = event.get("tenant", "default")

        if kind == "process_exec":
            self._handle_process_exec(host_id, tenant, payload)
        elif kind == "process_exit":
            pass  # last_seen already tracked via entity upsert on next sighting
        elif kind == "tcp_connect":
            self._handle_tcp_connect(host_id, tenant, payload)
        elif kind == "file_access":
            self._handle_file_access(host_id, tenant, payload)
        elif kind == "auth_event":
            self._handle_auth_event(host_id, tenant, payload)
        elif kind == "container_event":
            self._handle_container_event(host_id, tenant, payload)

    def _handle_process_exec(self, host_id: str, tenant: str, payload: Dict[str, Any]):
        pid = payload.get("pid")
        ppid = payload.get("ppid")
        comm = payload.get("comm", "unknown")
        container_id = payload.get("container_id")
        user = payload.get("user") or str(payload.get("uid", ""))

        proc_id = process_fingerprint(host_id, pid, comm, ppid, container_id, user)
        self.graph.upsert_entity(proc_id, EntityType.PROCESS, comm, tenant,
                                  {"host_id": host_id, "pid": pid, "container_id": container_id})

        if ppid is not None:
            parent_id = process_fingerprint(host_id, ppid, payload.get("parent_comm", "?"))
            self.graph.upsert_entity(parent_id, EntityType.PROCESS, payload.get("parent_comm", "?"), tenant)
            self.graph.observe_relationship(parent_id, proc_id, RelationType.SPAWNED, BoundaryType.PROCESS,
                                             tenant, source=payload.get("_source", "ebpf"))
            self.graph.observe_relationship(proc_id, parent_id, RelationType.EXECUTED_BY, BoundaryType.PROCESS,
                                             tenant, source=payload.get("_source", "ebpf"))

        if user:
            user_id = f"user_{user}"
            self.graph.upsert_entity(user_id, EntityType.USER, user, tenant)
            self.graph.observe_relationship(user_id, proc_id, RelationType.CONTROLS, BoundaryType.IDENTITY, tenant)

        if container_id:
            cont_id = f"container_{container_id}"
            self.graph.upsert_entity(cont_id, EntityType.CONTAINER, container_id, tenant)
            self.graph.observe_relationship(proc_id, cont_id, RelationType.CONTAINED_BY, BoundaryType.CONTAINER, tenant)

    def _handle_tcp_connect(self, host_id: str, tenant: str, payload: Dict[str, Any]):
        pid = payload.get("pid")
        comm = payload.get("comm", "unknown")
        proc_id = process_fingerprint(host_id, pid, comm)
        self.graph.upsert_entity(proc_id, EntityType.PROCESS, comm, tenant)

        daddr = payload.get("daddr")
        dport = payload.get("dport")
        endpoint_id = f"endpoint_{daddr}_{dport}"
        self.graph.upsert_entity(endpoint_id, EntityType.NETWORK_ENDPOINT, f"{daddr}:{dport}", tenant,
                                  {"ip": daddr, "port": dport})
        self.graph.observe_relationship(proc_id, endpoint_id, RelationType.CONNECTED_TO, BoundaryType.NETWORK,
                                         tenant, context={"protocol": payload.get("protocol", "tcp")})

    def _handle_file_access(self, host_id: str, tenant: str, payload: Dict[str, Any]):
        pid = payload.get("pid")
        comm = payload.get("comm", "unknown")
        proc_id = process_fingerprint(host_id, pid, comm)
        path_group = payload.get("path_group") or payload.get("path", "unknown")
        file_id = f"file_{path_group}"
        self.graph.upsert_entity(file_id, EntityType.FILE, path_group, tenant, {"file_type": payload.get("file_type")})
        relation = RelationType.WRITES if payload.get("operation") == "write" else RelationType.READS
        self.graph.observe_relationship(proc_id, file_id, relation, BoundaryType.FILE, tenant)

    def _handle_auth_event(self, host_id: str, tenant: str, payload: Dict[str, Any]):
        user = payload.get("user", "unknown")
        target = payload.get("target", "unknown_service")
        user_id = f"user_{user}"
        target_id = f"service_{target}"
        self.graph.upsert_entity(user_id, EntityType.USER, user, tenant)
        self.graph.upsert_entity(target_id, EntityType.SERVICE, target, tenant)
        self.graph.observe_relationship(user_id, target_id, RelationType.AUTHENTICATED_TO, BoundaryType.IDENTITY,
                                         tenant, context={"device": payload.get("device"), "session": payload.get("session")})

    def _handle_container_event(self, host_id: str, tenant: str, payload: Dict[str, Any]):
        container_id = payload.get("container_id")
        namespace = payload.get("namespace", "default")
        cont_id = f"container_{container_id}"
        ns_id = f"namespace_{namespace}"
        self.graph.upsert_entity(cont_id, EntityType.CONTAINER, container_id, tenant,
                                  {"image": payload.get("image"), "capabilities": payload.get("capabilities")})
        self.graph.upsert_entity(ns_id, EntityType.NAMESPACE, namespace, tenant)
        self.graph.observe_relationship(cont_id, ns_id, RelationType.BELONGS_TO, BoundaryType.CONTAINER, tenant)
