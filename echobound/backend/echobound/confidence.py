"""
Boundary Relationship Confidence Engine.

Confidence is a continuous function of frequency, recency, duration,
repetition (distinct time-buckets seen), context stability and source
reliability, not a binary "known/unknown" flag.
"""
from __future__ import annotations

import math
import time
from typing import Any, Dict

from .config import settings

SOURCE_RELIABILITY = {
    "ebpf": 0.95,
    "ebpf_lsm": 0.97,
    "proc_fallback": 0.6,
    "cloud_audit_log": 0.85,
    "manual": 0.5,
    "synthetic": 0.9,
}


def recency_score(last_seen: float, now: float | None = None) -> float:
    now = now or time.time()
    age_days = max(0.0, (now - last_seen) / 86400.0)
    half_life = settings.decay_half_life_days
    return math.exp(-math.log(2) * age_days / half_life)


def frequency_score(frequency: int) -> float:
    # Saturating curve: fast early growth, diminishing returns after ~50 obs.
    return 1 - math.exp(-frequency / 12.0)


def duration_score(start_time: float, last_seen: float) -> float:
    span_days = max(0.0, (last_seen - start_time) / 86400.0)
    return min(1.0, span_days / 30.0)  # a relationship spanning 30+ days is "mature"


def repetition_score(distinct_days_seen: int) -> float:
    return min(1.0, distinct_days_seen / 14.0)


def source_reliability(source: str) -> float:
    return SOURCE_RELIABILITY.get(source, 0.5)


def compute_confidence(edge: Dict[str, Any], distinct_days_seen: int = 1) -> float:
    r = recency_score(edge["last_seen"])
    f = frequency_score(edge.get("frequency", 1))
    d = duration_score(edge["start_time"], edge["last_seen"])
    p = repetition_score(distinct_days_seen)
    s = source_reliability(edge.get("source", "ebpf"))
    # Weighted geometric-ish blend so no single factor alone can push
    # confidence to 1.0 for a barely-observed relationship.
    score = (0.28 * f) + (0.22 * d) + (0.18 * p) + (0.17 * r) + (0.15 * s)
    return round(max(0.0, min(1.0, score)), 4)


def is_promotable_to_expected(edge: Dict[str, Any], distinct_days_seen: int) -> bool:
    span_hours = (edge["last_seen"] - edge["start_time"]) / 3600.0
    return (
        edge.get("frequency", 0) >= settings.candidate_promotion_min_observations
        and span_hours >= settings.candidate_promotion_min_span_hours
        and distinct_days_seen >= 2
    )
