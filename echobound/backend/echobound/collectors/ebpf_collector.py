"""
eBPF Telemetry Collector.

Collects *metadata only* (never raw payloads/file content) about process
execution, parent/child lifecycle, socket connections and container context
using standard Linux tracing primitives (tracepoints / kprobes, via BCC).
This module requires: Linux, a kernel with BPF support, `bcc` installed, and
(typically) root or CAP_BPF/CAP_PERFMON. When those preconditions are not
met — e.g. macOS/Windows dev machines, containers without the right
capabilities — the collector gracefully degrades to `ProcFallbackCollector`
(see proc_fallback_collector.py) rather than silently producing no data.

This is a defensive security telemetry component (the same class of tool as
Falco / Tetragon / bpftrace-based EDR agents): it observes and reports, it
does not modify kernel behavior, inject code into other processes, or grant
itself elevated privileges beyond what the host administrator explicitly
provides when installing the agent.
"""
from __future__ import annotations

import ctypes
import logging
import os
import platform
import socket
import struct
import time
import uuid
from typing import Any, Callable, Dict, Optional

from ..config import settings
from .privacy_filter import PrivacyFilter

logger = logging.getLogger("echobound.ebpf_collector")

# The embedded BPF C program. Kept intentionally small and metadata-only:
# it reports PID/PPID/UID/GID/comm on process exec, and PID/daddr/dport on
# outbound TCP connect — nothing else. Loaded only if BCC + kernel support
# are available.
BPF_PROGRAM_EXEC = r"""
#include <linux/sched.h>
struct exec_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(exec_events);

int trace_exec(struct tracepoint__sched__sched_process_exec *ctx) {
    struct exec_event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = task->real_parent->tgid;
    u64 uid_gid = bpf_get_current_uid_gid();
    event.uid = uid_gid & 0xffffffff;
    event.gid = uid_gid >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    exec_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

BPF_PROGRAM_TCP = r"""
struct connect_event_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 dport;
};
BPF_PERF_OUTPUT(connect_events);

int trace_connect(struct pt_regs *ctx, struct sock *sk) {
    u16 family = sk->__sk_common.skc_family;
    if (family != 2) { // AF_INET only in this reference collector
        return 0;
    }
    struct connect_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.saddr = sk->__sk_common.skc_rcv_saddr;
    event.daddr = sk->__sk_common.skc_daddr;
    event.dport = sk->__sk_common.skc_dport;
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""


def ebpf_available() -> bool:
    if platform.system() != "Linux":
        return False
    if not os.path.exists("/sys/kernel/debug/tracing") and not os.path.exists("/sys/kernel/tracing"):
        return False
    try:
        import bcc  # noqa: F401
        return True
    except ImportError:
        return False


class EBPFTelemetryCollector:
    """Attaches to kernel tracepoints/kprobes and forwards normalized,
    privacy-filtered events to `on_event`."""

    def __init__(self, host_id: str, on_event: Callable[[Dict[str, Any]], None],
                 tenant: str = "default"):
        self.host_id = host_id
        self.tenant = tenant
        self.on_event = on_event
        self.privacy = PrivacyFilter()
        self._bpf_exec = None
        self._bpf_tcp = None
        self.dropped_events = 0
        self.events_seen = 0

    def start(self):
        if not ebpf_available():
            raise RuntimeError(
                "eBPF is not available on this host (needs Linux + kernel BPF "
                "support + the `bcc` package + sufficient privileges). "
                "Use ProcFallbackCollector instead."
            )
        from bcc import BPF  # imported lazily; only present on supported hosts

        self._bpf_exec = BPF(text=BPF_PROGRAM_EXEC)
        self._bpf_exec["exec_events"].open_perf_buffer(self._handle_exec_event)

        self._bpf_tcp = BPF(text=BPF_PROGRAM_TCP)
        self._bpf_tcp.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")
        self._bpf_tcp["connect_events"].open_perf_buffer(self._handle_connect_event)
        logger.info("eBPF collector attached: process exec + TCP connect tracepoints/kprobes")

    def poll(self, timeout_ms: int = 200):
        if self._bpf_exec:
            self._bpf_exec.perf_buffer_poll(timeout=timeout_ms)
        if self._bpf_tcp:
            self._bpf_tcp.perf_buffer_poll(timeout=timeout_ms)

    # ------------------------------------------------------------ handlers
    def _emit(self, kind: str, payload: Dict[str, Any]):
        self.events_seen += 1
        event = {
            "event_id": f"ev_{uuid.uuid4().hex[:20]}",
            "tenant": self.tenant,
            "ts": time.time(),
            "monotonic_ts": time.monotonic(),
            "host_id": self.host_id,
            "kind": kind,
            "payload": self.privacy.apply(payload),
            "source": "ebpf",
            "integrity_flags": {},
        }
        self.on_event(event)

    def _handle_exec_event(self, cpu, data, size):
        event = self._bpf_exec["exec_events"].event(data)
        self._emit("process_exec", {
            "pid": event.pid,
            "ppid": event.ppid,
            "uid": event.uid,
            "gid": event.gid,
            "comm": event.comm.decode(errors="replace"),
        })

    def _handle_connect_event(self, cpu, data, size):
        event = self._bpf_tcp["connect_events"].event(data)
        self._emit("tcp_connect", {
            "pid": event.pid,
            "saddr": socket.inet_ntoa(struct.pack("I", event.saddr)),
            "daddr": socket.inet_ntoa(struct.pack("I", event.daddr)),
            "dport": socket.htons(event.dport),
        })

    def stop(self):
        self._bpf_exec = None
        self._bpf_tcp = None
