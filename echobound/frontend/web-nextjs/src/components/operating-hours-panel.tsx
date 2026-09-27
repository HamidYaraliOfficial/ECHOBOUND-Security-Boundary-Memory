"use client";

import { useCallback, useEffect, useState } from "react";
import { useLanguage } from "./language-provider";

const API_BASE = process.env.NEXT_PUBLIC_ECHOBOUND_API_BASE || "http://localhost:8088";

interface OperatingHoursStatus {
  configured: boolean;
  is_open: boolean;
  in_maintenance_window: boolean;
  current_local_time: string | null;
  timezone: string;
  next_change_at: string | null;
  seconds_until_next_change: number | null;
  human_readable_countdown: string | null;
}

const WEEKDAYS = [0, 1, 2, 3, 4, 5, 6];

export default function OperatingHoursPanel() {
  const { dict } = useLanguage();
  const [status, setStatus] = useState<OperatingHoursStatus | null>(null);
  const [countdown, setCountdown] = useState<number | null>(null);
  const [timezone, setTimezone] = useState("UTC");
  const [start, setStart] = useState("09:00");
  const [end, setEnd] = useState("18:00");
  const [days, setDays] = useState<number[]>([0, 1, 2, 3, 4]);
  const [saving, setSaving] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/context/operating-hours/status`);
      const data: OperatingHoursStatus = await res.json();
      setStatus(data);
      setCountdown(data.seconds_until_next_change);
    } catch {
      // network error — leave previous state, the UI shows a stale-but-safe view
    }
  }, []);

  useEffect(() => {
    refresh();
    const poll = setInterval(refresh, 30000);
    return () => clearInterval(poll);
  }, [refresh]);

  useEffect(() => {
    if (countdown == null) return;
    const tick = setInterval(() => {
      setCountdown((c) => {
        if (c == null) return c;
        if (c <= 1) {
          refresh();
          return 0;
        }
        return c - 1;
      });
    }, 1000);
    return () => clearInterval(tick);
  }, [countdown, refresh]);

  const toggleDay = (d: number) => {
    setDays((prev) => (prev.includes(d) ? prev.filter((x) => x !== d) : [...prev, d].sort()));
  };

  const save = async () => {
    setSaving(true);
    try {
      await fetch(`${API_BASE}/api/v1/context/operating-hours/quick-setup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant: "default",
          timezone,
          start_hhmm: start,
          end_hhmm: end,
          weekdays: days,
        }),
      });
      await refresh();
    } finally {
      setSaving(false);
    }
  };

  const fmt = (secs: number | null) => {
    if (secs == null) return "—";
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    return `${h}h ${m}m ${s}s`;
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div className="rounded-lg border p-5" style={{ borderColor: "var(--border)", background: "var(--bg-card)" }}>
        <h3 className="text-sm font-semibold mb-3">{dict.operatingHours}</h3>

        <label className="block text-xs opacity-70 mb-1">{dict.timezone}</label>
        <input
          className="w-full mb-3 px-3 py-2 rounded border bg-transparent"
          style={{ borderColor: "var(--border)" }}
          value={timezone}
          onChange={(e) => setTimezone(e.target.value)}
          placeholder="Asia/Baku, Europe/London, UTC…"
        />

        <div className="grid grid-cols-2 gap-3 mb-3">
          <div>
            <label className="block text-xs opacity-70 mb-1">{dict.startTime}</label>
            <input type="time" className="w-full px-3 py-2 rounded border bg-transparent"
              style={{ borderColor: "var(--border)" }} value={start} onChange={(e) => setStart(e.target.value)} />
          </div>
          <div>
            <label className="block text-xs opacity-70 mb-1">{dict.endTime}</label>
            <input type="time" className="w-full px-3 py-2 rounded border bg-transparent"
              style={{ borderColor: "var(--border)" }} value={end} onChange={(e) => setEnd(e.target.value)} />
          </div>
        </div>

        <div className="flex gap-2 flex-wrap mb-4">
          {WEEKDAYS.map((d) => (
            <button
              key={d}
              onClick={() => toggleDay(d)}
              className="px-3 py-1 rounded-full text-xs border"
              style={{
                borderColor: "var(--border)",
                background: days.includes(d) ? "var(--accent)" : "transparent",
                color: days.includes(d) ? "#fff" : "inherit",
              }}
            >
              {["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][d]}
            </button>
          ))}
        </div>

        <button
          onClick={save}
          disabled={saving}
          className="px-4 py-2 rounded font-semibold text-sm"
          style={{ background: "var(--accent)", color: "#fff" }}
        >
          {dict.save}
        </button>
      </div>

      <div className="rounded-lg border p-5" style={{ borderColor: "var(--border)", background: "var(--bg-card)" }}>
        <h3 className="text-sm font-semibold mb-3">Current Status</h3>
        {!status || !status.configured ? (
          <p className="text-sm opacity-70">No operating hours configured yet.</p>
        ) : (
          <>
            <div className="flex items-center gap-2 mb-2">
              <span
                className="inline-block w-2.5 h-2.5 rounded-full"
                style={{ background: status.in_maintenance_window ? "#f5a623" : status.is_open ? "#2ecc71" : "#888" }}
              />
              <span className="font-bold">
                {status.in_maintenance_window ? "MAINTENANCE" : status.is_open ? dict.open : dict.closed}
              </span>
              <span className="text-xs opacity-60">
                {status.current_local_time} ({status.timezone})
              </span>
            </div>
            <div className="text-xs opacity-70 mb-1">
              {dict.nextChange}: {status.next_change_at || "—"}
            </div>
            <div className="text-3xl font-extrabold tracking-tight">{fmt(countdown)}</div>
          </>
        )}
      </div>
    </div>
  );
}
