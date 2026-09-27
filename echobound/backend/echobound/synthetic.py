"""
Synthetic Security World Generator.

Generates a seeded, reproducible population of entities/relationships/events
with stable behavior plus injected drift/recovery/failure scenarios, used by
the Benchmark Lab, the Evaluation Sandbox and for local demo/testing.
"""
from __future__ import annotations

import random
import time
from typing import Any, Dict, List

from .graph import TemporalSecurityGraph
from .models import EntityType, RelationType, BoundaryType
from .pipeline import EventPipeline
from .storage import SQLiteStorage, get_storage

SCENARIOS = [
    "new_relationship", "removed_relationship", "gradual_drift", "burst_drift",
    "periodic_drift", "contextual_drift", "false_drift", "deployment_induced_drift",
    "collector_failure", "recovery",
]


class SyntheticSecurityWorldGenerator:
    def __init__(self, seed: int = 42, storage: SQLiteStorage | None = None):
        self.seed = seed
        self.rng = random.Random(seed)
        self.storage = storage or get_storage()
        self.graph = TemporalSecurityGraph(self.storage)
        self.pipeline = EventPipeline(self.storage)

    def generate_world(
        self, tenant: str = "synthetic", num_hosts: int = 3, num_services: int = 6,
        num_users: int = 8, num_processes_per_host: int = 12, days_of_history: int = 14,
    ) -> Dict[str, Any]:
        hosts = [f"host-{i}" for i in range(num_hosts)]
        services = [f"svc-{name}" for name in
                    self.rng.sample(["auth", "billing", "orders", "search", "notify", "reporting",
                                      "gateway", "inventory", "payments", "analytics"], num_services)]
        users = [f"user-{i}" for i in range(num_users)]
        databases = [f"db-{name}" for name in ["primary", "replica", "analytics"]]

        now = time.time()
        start = now - days_of_history * 86400

        events_emitted = 0
        for host in hosts:
            for p in range(num_processes_per_host):
                comm = self.rng.choice(services + ["worker", "cli-tool"])
                pid = 1000 + p
                self._emit_process_history(host, tenant, pid, comm, start, now)
                events_emitted += 1

        for svc in services:
            targets = self.rng.sample(databases, k=self.rng.randint(1, len(databases)))
            for target in targets:
                self._emit_service_dependency(svc, target, tenant, start, now)
                events_emitted += 1

        for user in users:
            for svc in self.rng.sample(services, k=self.rng.randint(1, 3)):
                self.pipeline.ingest({
                    "event_id": f"ev_{self.rng.randint(1, 10**9)}", "tenant": tenant,
                    "ts": self.rng.uniform(start, now), "host_id": self.rng.choice(hosts),
                    "kind": "auth_event", "payload": {"user": user, "target": svc.replace("svc-", "")},
                    "source": "synthetic",
                })
                events_emitted += 1

        return {"hosts": hosts, "services": services, "users": users, "databases": databases, "events_emitted": events_emitted}

    def _emit_process_history(self, host: str, tenant: str, pid: int, comm: str, start: float, end: float):
        n_events = self.rng.randint(20, 80)
        for _ in range(n_events):
            self.pipeline.ingest({
                "event_id": f"ev_{self.rng.randint(1, 10**9)}", "tenant": tenant,
                "ts": self.rng.uniform(start, end), "host_id": host, "kind": "process_exec",
                "payload": {"pid": pid, "ppid": 1, "comm": comm, "uid": self.rng.randint(1000, 1010)},
                "source": "synthetic",
            })

    def _emit_service_dependency(self, service: str, target_db: str, tenant: str, start: float, end: float):
        proc_id = f"proc_{service}"
        db_id = f"db_{target_db}"
        self.graph.upsert_entity(proc_id, EntityType.SERVICE, service, tenant)
        self.graph.upsert_entity(db_id, EntityType.DATABASE, target_db, tenant)
        for _ in range(self.rng.randint(30, 200)):
            self.graph.observe_relationship(proc_id, db_id, RelationType.QUERIED, BoundaryType.DATA, tenant, source="synthetic")

    def inject_scenario(self, scenario: str, tenant: str = "synthetic") -> Dict[str, Any]:
        if scenario not in SCENARIOS:
            raise ValueError(f"unknown scenario {scenario}, expected one of {SCENARIOS}")

        entities = self.graph.find_entities(tenant=tenant, limit=50)
        if not entities:
            raise RuntimeError("generate_world() must be called before injecting scenarios")
        entity = self.rng.choice(entities)

        if scenario == "new_relationship":
            target_id = f"endpoint_synthetic_{self.rng.randint(1,999)}"
            self.graph.upsert_entity(target_id, EntityType.NETWORK_ENDPOINT, target_id, tenant)
            self.graph.observe_relationship(entity["id"], target_id, RelationType.CONNECTED_TO,
                                             BoundaryType.NETWORK, tenant, source="synthetic")
        elif scenario == "burst_drift":
            for _ in range(30):
                target_id = f"endpoint_burst_{self.rng.randint(1,50)}"
                self.graph.upsert_entity(target_id, EntityType.NETWORK_ENDPOINT, target_id, tenant)
                self.graph.observe_relationship(entity["id"], target_id, RelationType.CONNECTED_TO,
                                                 BoundaryType.NETWORK, tenant, source="synthetic")
        elif scenario == "deployment_induced_drift":
            self.storage.save_deployment({
                "id": f"dep_{self.rng.randint(1,10**6)}", "tenant": tenant, "entity_id": entity["id"],
                "kind": "deployment", "ref": "v-synthetic", "happened_at": time.time() - 60,
                "metadata": {"synthetic": True},
            })
            target_id = f"endpoint_postdeploy_{self.rng.randint(1,50)}"
            self.graph.upsert_entity(target_id, EntityType.NETWORK_ENDPOINT, target_id, tenant)
            self.graph.observe_relationship(entity["id"], target_id, RelationType.CONNECTED_TO,
                                             BoundaryType.NETWORK, tenant, source="synthetic")
        elif scenario == "collector_failure":
            pass  # represented purely via agent heartbeat health, see collector_confidence.py
        else:
            # gradual/periodic/contextual/false-drift/removed/recovery share the
            # same primitive: a burst of new or removed observations over time.
            target_id = f"endpoint_{scenario}_{self.rng.randint(1,50)}"
            self.graph.upsert_entity(target_id, EntityType.NETWORK_ENDPOINT, target_id, tenant)
            self.graph.observe_relationship(entity["id"], target_id, RelationType.CONNECTED_TO,
                                             BoundaryType.NETWORK, tenant, source="synthetic")

        return {"scenario": scenario, "entity_id": entity["id"]}
