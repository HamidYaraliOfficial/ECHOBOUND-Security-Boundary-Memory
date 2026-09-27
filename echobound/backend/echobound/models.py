"""
Core domain models for ECHOBOUND.

These dataclasses describe the Security Boundary Model: Entities, the
Temporal Security Graph's Nodes/Edges, Boundary Components, Drift Events,
Incidents, Policies/Contracts and Operating-Hours context.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def now_ts() -> float:
    return time.time()


class EntityType(str, Enum):
    PROCESS = "process"
    USER = "user"
    SERVICE = "service"
    CONTAINER = "container"
    HOST = "host"
    API = "api"
    FILE = "file"
    DATABASE = "database"
    NETWORK_ENDPOINT = "network_endpoint"
    IDENTITY = "identity"
    NAMESPACE = "namespace"
    SECURITY_CONTROL = "security_control"


class BoundaryType(str, Enum):
    IDENTITY = "identity_boundary"
    PROCESS = "process_boundary"
    FILE = "file_boundary"
    NETWORK = "network_boundary"
    DATA = "data_boundary"
    TEMPORAL = "temporal_boundary"
    PRIVILEGE = "privilege_boundary"
    CONTAINER = "container_boundary"
    SERVICE = "service_boundary"
    TRUST = "trust_boundary"


class RelationType(str, Enum):
    SPAWNED = "spawned"
    EXECUTED_BY = "executed_by"
    ACCESSED = "accessed"
    CONNECTED_TO = "connected_to"
    QUERIED = "queried"
    AUTHENTICATED_TO = "authenticated_to"
    CONTAINED_BY = "contained_by"
    COMMUNICATES_WITH = "communicates_with"
    READS = "reads"
    WRITES = "writes"
    LOADS = "loads"
    DEPENDS_ON = "depends_on"
    CONTROLS = "controls"
    IMPERSONATES = "impersonates"
    DELEGATES_TO = "delegates_to"
    BELONGS_TO = "belongs_to"
    OBSERVED_WITH = "observed_with"


class RelationState(str, Enum):
    CANDIDATE = "candidate"
    EXPECTED = "expected"
    OBSERVED = "observed"
    HISTORICAL = "historical"
    DORMANT = "dormant"
    EXPIRED = "expired"
    FORBIDDEN = "forbidden"


class DriftType(str, Enum):
    NETWORK = "network_boundary_drift"
    FILE = "file_boundary_drift"
    PROCESS = "process_boundary_drift"
    IDENTITY = "identity_boundary_drift"
    PRIVILEGE = "privilege_boundary_drift"
    CONTAINER = "container_boundary_drift"
    SCHEDULE = "schedule_boundary_drift"
    API = "api_boundary_drift"
    RELATIONSHIP = "relationship_drift"
    DELEGATION = "delegation_drift"
    ACCESS = "access_boundary_drift"


class DriftSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TimelinePhase(str, Enum):
    BOUNDARY_BIRTH = "boundary_birth"
    STABLE_PERIOD = "stable_period"
    DRIFT_START = "drift_start"
    ESCALATION = "escalation"
    RECOVERY = "recovery"
    RELEARN = "relearn"
    RESET = "reset"


class CaseState(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    VALIDATED = "validated"
    EXPECTED_CHANGE = "expected_change"
    MONITORING = "monitoring"
    RESOLVED = "resolved"
    CLOSED = "closed"


class FeedbackLabel(str, Enum):
    EXPECTED = "expected"
    LEGITIMATE_CHANGE = "legitimate_change"
    FALSE_POSITIVE_CANDIDATE = "false_positive_candidate"
    INVESTIGATION_REQUIRED = "investigation_required"
    CONFIRMED_BEHAVIORAL_DRIFT = "confirmed_behavioral_drift"


@dataclass
class Entity:
    id: str
    type: EntityType
    name: str
    tenant: str = "default"
    first_seen: float = field(default_factory=now_ts)
    last_seen: float = field(default_factory=now_ts)
    archetype: Optional[str] = None
    archetype_overridden: bool = False
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value if isinstance(self.type, Enum) else self.type
        return d


@dataclass
class Edge:
    """A temporal relationship (graph edge) between two entities."""
    id: str
    source_id: str
    target_id: str
    relation: RelationType
    tenant: str = "default"
    start_time: float = field(default_factory=now_ts)
    end_time: Optional[float] = None
    last_seen: float = field(default_factory=now_ts)
    frequency: int = 1
    confidence: float = 0.1
    source: str = "ebpf"
    state: RelationState = RelationState.CANDIDATE
    version: int = 1
    context: Dict[str, Any] = field(default_factory=dict)
    boundary_type: BoundaryType = BoundaryType.PROCESS

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["relation"] = self.relation.value if isinstance(self.relation, Enum) else self.relation
        d["state"] = self.state.value if isinstance(self.state, Enum) else self.state
        d["boundary_type"] = (
            self.boundary_type.value if isinstance(self.boundary_type, Enum) else self.boundary_type
        )
        return d


@dataclass
class BoundaryComponent:
    """One facet (Identity/Process/File/Network/...) of an entity's boundary."""
    entity_id: str
    boundary_type: BoundaryType
    observed_relation_ids: List[str] = field(default_factory=list)
    expected_relation_ids: List[str] = field(default_factory=list)
    allowed_patterns: List[Dict[str, Any]] = field(default_factory=list)
    frequency_profile: Dict[str, float] = field(default_factory=dict)
    timing_profile: Dict[str, Any] = field(default_factory=dict)
    source: str = "boundary_memory_engine"
    confidence: float = 0.0
    criticality: str = "normal"
    version: int = 1
    provenance: List[str] = field(default_factory=list)
    updated_at: float = field(default_factory=now_ts)


@dataclass
class DriftEvent:
    id: str
    entity_id: str
    boundary_type: BoundaryType
    drift_type: DriftType
    detected_at: float
    first_divergence_at: Optional[float]
    description: str
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.5
    severity: DriftSeverity = DriftSeverity.LOW
    context: Dict[str, Any] = field(default_factory=dict)
    deployment_correlated: bool = False
    tenant: str = "default"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["boundary_type"] = self.boundary_type.value
        d["drift_type"] = self.drift_type.value
        d["severity"] = self.severity.value
        return d


@dataclass
class Incident:
    id: str
    title: str
    drift_ids: List[str]
    entity_ids: List[str]
    opened_at: float
    state: CaseState = CaseState.OPEN
    severity: DriftSeverity = DriftSeverity.MEDIUM
    tenant: str = "default"
    notes: List[Dict[str, Any]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["state"] = self.state.value
        d["severity"] = self.severity.value
        return d


@dataclass
class BoundaryContract:
    """Expected Boundary Contract — declarative allowed/forbidden shape."""
    id: str
    entity_selector: Dict[str, Any]
    allowed_relationships: List[Dict[str, Any]] = field(default_factory=list)
    forbidden_relationships: List[Dict[str, Any]] = field(default_factory=list)
    expected_frequency: Dict[str, Any] = field(default_factory=dict)
    time_windows: List[Dict[str, Any]] = field(default_factory=list)
    allowed_sources: List[str] = field(default_factory=list)
    allowed_destinations: List[str] = field(default_factory=list)
    change_policy: str = "review"  # review | auto | frozen
    version: int = 1
    created_at: float = field(default_factory=now_ts)
    enabled: bool = True


@dataclass
class OperatingHoursWindow:
    """A single recurring open window, e.g. Monday 09:00-18:00."""
    weekday: int  # 0=Monday .. 6=Sunday
    start_minute: int  # minutes from midnight, local tz
    end_minute: int
    label: str = ""


@dataclass
class OperatingHoursConfig:
    id: str
    tenant: str
    timezone: str = "UTC"
    windows: List[OperatingHoursWindow] = field(default_factory=list)
    maintenance_windows: List[Dict[str, Any]] = field(default_factory=list)
    updated_at: float = field(default_factory=now_ts)
    updated_by: str = "system"


@dataclass
class BaselineVersion:
    id: str
    entity_id: str
    context_key: str  # e.g. env=production;host=x;version=1.4.0
    boundary_snapshot: Dict[str, Any]
    created_at: float
    frozen: bool = False
    status: str = "active"  # active | frozen | rolled_back | superseded
    parent_version_id: Optional[str] = None
    notes: str = ""
