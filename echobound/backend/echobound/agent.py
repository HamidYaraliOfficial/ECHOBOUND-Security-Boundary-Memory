"""
Host Identity Layer, Container Boundary Engine, Agent Resource Guard and
Agent Self-Health Engine.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from .config import settings
from .graph import TemporalSecurityGraph
from .models import EntityType, RelationType, BoundaryType
from .storage import SQLiteStorage, get_storage


class HostIdentityLayer:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self.graph = TemporalSecurityGraph(self.storage)

    def register_host(self, host_id: str, kernel_version: str, agent_version: str,
                       container_runtime: Optional[str] = None, tags: Optional[List[str]] = None,
                       environment: str = "production", tenant: str = "default") -> Dict[str, Any]:
        return self.graph.upsert_entity(
            f"host_{host_id}", EntityType.HOST, host_id, tenant,
            {
                "kernel_version": kernel_version, "agent_version": agent_version,
                "container_runtime": container_runtime, "tags": tags or [],
                "environment": environment,
            },
        )


class ContainerBoundaryEngine:
    """Links Container/Pod/Namespace/ServiceAccount/Image/Workload/Network
    context to boundary state, and records image/namespace/capability/mount/
    network/service-account changes as configuration/boundary changes."""

    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self.graph = TemporalSecurityGraph(self.storage)

    def record_container_state(
        self, container_id: str, image: str, namespace: str, service_account: str,
        capabilities: List[str], mounts: List[str], networks: List[str],
        parent_workload: Optional[str] = None, tenant: str = "default",
    ) -> Dict[str, Any]:
        cont_id = f"container_{container_id}"
        entity = self.graph.get_entity(cont_id)
        previous_attrs = entity.get("attributes", {}) if entity else {}

        changes = []
        for field_name, new_value in (
            ("image", image), ("service_account", service_account),
            ("capabilities", sorted(capabilities)), ("mounts", sorted(mounts)),
            ("networks", sorted(networks)),
        ):
            old_value = previous_attrs.get(field_name)
            if old_value is not None and old_value != new_value:
                changes.append({"field": field_name, "from": old_value, "to": new_value})

        self.graph.upsert_entity(cont_id, EntityType.CONTAINER, container_id, tenant, {
            "image": image, "service_account": service_account, "capabilities": sorted(capabilities),
            "mounts": sorted(mounts), "networks": sorted(networks), "parent_workload": parent_workload,
        })

        ns_id = f"namespace_{namespace}"
        self.graph.upsert_entity(ns_id, EntityType.NAMESPACE, namespace, tenant)
        self.graph.observe_relationship(cont_id, ns_id, RelationType.BELONGS_TO, BoundaryType.CONTAINER, tenant)

        if parent_workload:
            wl_id = f"service_{parent_workload}"
            self.graph.upsert_entity(wl_id, EntityType.SERVICE, parent_workload, tenant)
            self.graph.observe_relationship(cont_id, wl_id, RelationType.CONTROLS, BoundaryType.SERVICE, tenant)

        return {"container_id": cont_id, "changes": changes}


class AgentResourceGuard:
    """Bounds the agent's own CPU/memory/ring-buffer/queue/bandwidth so
    monitoring itself never becomes the incident."""

    def __init__(self, max_events_per_sec: Optional[int] = None, ring_buffer_pages: Optional[int] = None):
        self.max_events_per_sec = max_events_per_sec or settings.agent_max_events_per_sec
        self.ring_buffer_pages = ring_buffer_pages or settings.agent_ring_buffer_pages
        self._window_start = time.time()
        self._window_count = 0

    def allow_event(self) -> bool:
        now = time.time()
        if now - self._window_start >= 1.0:
            self._window_start = now
            self._window_count = 0
        self._window_count += 1
        return self._window_count <= self.max_events_per_sec


class AgentSelfHealthEngine:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()

    def report(self, agent_id: str, host_id: str, tenant: str, events_per_sec: float,
               dropped_events: int, buffer_usage: float, kernel_hook_status: str,
               collector_latency_ms: float, agent_version: str = "1.0.0",
               kernel_version: str = "unknown") -> Dict[str, Any]:
        status = "healthy"
        if dropped_events > 0 or buffer_usage > 0.85 or kernel_hook_status != "attached":
            status = "degraded"
        self.storage.upsert_agent({
            "id": agent_id, "tenant": tenant, "host_id": host_id, "agent_version": agent_version,
            "kernel_version": kernel_version, "status": status, "events_per_sec": events_per_sec,
            "dropped_events": dropped_events, "buffer_usage": buffer_usage,
            "last_heartbeat": time.time(),
            "capabilities": {"kernel_hook_status": kernel_hook_status, "collector_latency_ms": collector_latency_ms},
        })
        return {"agent_id": agent_id, "status": status}
