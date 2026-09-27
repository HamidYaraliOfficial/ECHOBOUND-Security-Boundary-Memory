"""
Proc Fallback Collector.

Used automatically (see collector_confidence.py) whenever eBPF is not
available: non-Linux hosts, kernels without BPF, containers without the
right capabilities, or a locked-down environment where installing a kernel
agent isn't possible. Polls /proc (Linux) or `psutil` (cross-platform) for
process lifecycle and network connections. Strictly lower fidelity/latency
than the eBPF path — the Collector Confidence Model marks its output with a
lower source-reliability weight so drift derived from it is treated more
cautiously.
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Callable, Dict, Set

from .privacy_filter import PrivacyFilter

logger = logging.getLogger("echobound.proc_fallback_collector")


class ProcFallbackCollector:
    def __init__(self, host_id: str, on_event: Callable[[Dict[str, Any]], None], tenant: str = "default"):
        self.host_id = host_id
        self.tenant = tenant
        self.on_event = on_event
        self.privacy = PrivacyFilter()
        self._known_pids: Set[int] = set()
        self._known_conns: Set[tuple] = set()

    def _emit(self, kind: str, payload: Dict[str, Any]):
        event = {
            "event_id": f"ev_{uuid.uuid4().hex[:20]}",
            "tenant": self.tenant,
            "ts": time.time(),
            "monotonic_ts": time.monotonic(),
            "host_id": self.host_id,
            "kind": kind,
            "payload": self.privacy.apply(payload),
            "source": "proc_fallback",
            "integrity_flags": {"lower_fidelity": True},
        }
        self.on_event(event)

    def poll_once(self):
        try:
            import psutil
        except ImportError:
            logger.warning("psutil not installed; ProcFallbackCollector cannot poll process/network state")
            return

        current_pids = set()
        for proc in psutil.process_iter(attrs=["pid", "ppid", "name", "username"]):
            info = proc.info
            current_pids.add(info["pid"])
            if info["pid"] not in self._known_pids:
                self._emit("process_exec", {
                    "pid": info["pid"], "ppid": info.get("ppid"),
                    "comm": info.get("name"), "user": info.get("username"),
                })
        exited = self._known_pids - current_pids
        for pid in exited:
            self._emit("process_exit", {"pid": pid})
        self._known_pids = current_pids

        current_conns = set()
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status != "ESTABLISHED" or not c.raddr:
                    continue
                key = (c.pid, c.raddr.ip, c.raddr.port)
                current_conns.add(key)
                if key not in self._known_conns:
                    self._emit("tcp_connect", {
                        "pid": c.pid, "daddr": c.raddr.ip, "dport": c.raddr.port,
                    })
        except (psutil.AccessDenied, PermissionError):
            logger.debug("insufficient privileges to enumerate all network connections")
        self._known_conns = current_conns

    def run_forever(self, interval_seconds: float = 2.0, stop_flag: Callable[[], bool] = lambda: False):
        while not stop_flag():
            self.poll_once()
            time.sleep(interval_seconds)
