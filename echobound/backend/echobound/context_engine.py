"""
Maintenance & Deployment Context Engine.

Lets the user fully define their own organization's operating hours
(per weekday, with start/end times and a timezone) plus ad-hoc maintenance
windows. The engine can then answer, at any instant:
  - is the system currently "open" (inside business hours)?
  - what time is it right now, in the configured timezone?
  - when does the current state change next, and how long until then?
  - are we currently inside a planned maintenance window?

This directly powers the Boundary Drift Engine's schedule-aware detection
(so 3am activity is only suspicious if 3am is actually outside the hours the
user told the system about) and the frontend's "Operating Hours" settings
page / live countdown widget.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

from .models import OperatingHoursConfig, OperatingHoursWindow, new_id, now_ts
from .storage import SQLiteStorage, get_storage

WEEKDAY_NAMES = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]


def _minute_of_day(dt: datetime) -> int:
    return dt.hour * 60 + dt.minute


class MaintenanceContextEngine:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()

    # --------------------------------------------------------------- CRUD
    def save_config(
        self,
        tenant: str,
        timezone: str,
        windows: List[Dict[str, Any]],
        maintenance_windows: Optional[List[Dict[str, Any]]] = None,
        updated_by: str = "user",
    ) -> Dict[str, Any]:
        """`windows`: list of {weekday(0-6), start_minute, end_minute, label}
        as entered by the user for each day they consider "open" / normal
        business hours. `maintenance_windows`: list of
        {start_ts, end_ts, label, recurring?} for planned one-off or
        recurring maintenance periods that should never be treated as
        anomalous."""
        # validate timezone early so bad user input fails fast and clearly
        ZoneInfo(timezone)
        cfg = {
            "id": new_id("opshours"),
            "tenant": tenant,
            "timezone": timezone,
            "windows": windows,
            "maintenance_windows": maintenance_windows or [],
            "updated_at": now_ts(),
            "updated_by": updated_by,
        }
        self.storage.save_operating_hours(cfg)
        self.storage.audit(updated_by, "operating_hours_updated", tenant, {"windows": len(windows)})
        return cfg

    def get_config(self, tenant: str = "default") -> Optional[Dict[str, Any]]:
        return self.storage.get_operating_hours(tenant)

    # ------------------------------------------------------------- status
    def current_status(self, tenant: str = "default", at: Optional[float] = None) -> Dict[str, Any]:
        cfg = self.get_config(tenant)
        if not cfg or not cfg.get("windows"):
            return {
                "configured": False,
                "is_open": True,  # fail open: no configured hours means "always normal"
                "in_maintenance_window": False,
                "current_local_time": None,
                "timezone": "UTC",
                "next_change_at": None,
                "seconds_until_next_change": None,
                "message": "No operating hours configured yet — all hours are treated as normal.",
            }

        tz = ZoneInfo(cfg["timezone"])
        now_dt = datetime.fromtimestamp(at or now_ts(), tz)

        in_maintenance = self._in_maintenance_window(cfg, at or now_ts())
        is_open, next_change_dt = self._evaluate_windows(cfg["windows"], now_dt, tz)

        seconds_until_next = None
        if next_change_dt is not None:
            seconds_until_next = max(0, int((next_change_dt - now_dt).total_seconds()))

        return {
            "configured": True,
            "is_open": is_open,
            "in_maintenance_window": in_maintenance,
            "current_local_time": now_dt.strftime("%Y-%m-%d %H:%M:%S %Z"),
            "current_weekday": WEEKDAY_NAMES[now_dt.weekday()],
            "timezone": cfg["timezone"],
            "next_change_at": next_change_dt.strftime("%Y-%m-%d %H:%M:%S %Z") if next_change_dt else None,
            "seconds_until_next_change": seconds_until_next,
            "human_readable_countdown": self._humanize(seconds_until_next),
            "windows": cfg["windows"],
            "maintenance_windows": cfg["maintenance_windows"],
        }

    # -------------------------------------------------------------- helpers
    @staticmethod
    def _humanize(seconds: Optional[int]) -> Optional[str]:
        if seconds is None:
            return None
        h, rem = divmod(seconds, 3600)
        m, _ = divmod(rem, 60)
        if h and m:
            return f"{h}h {m}m"
        if h:
            return f"{h}h"
        return f"{m}m"

    @staticmethod
    def _in_maintenance_window(cfg: Dict[str, Any], ts: float) -> bool:
        for mw in cfg.get("maintenance_windows", []):
            if mw.get("start_ts") and mw.get("end_ts"):
                if mw["start_ts"] <= ts <= mw["end_ts"]:
                    return True
        return False

    def _evaluate_windows(self, windows: List[Dict[str, Any]], now_dt: datetime, tz: ZoneInfo):
        """Returns (is_open_now, next_change_datetime) by scanning up to 8
        days ahead of `now_dt` (covers any weekly schedule + wraparound)."""
        today_minute = _minute_of_day(now_dt)
        today_weekday = now_dt.weekday()

        is_open_now = False
        for w in windows:
            if w["weekday"] == today_weekday and w["start_minute"] <= today_minute < w["end_minute"]:
                is_open_now = True
                break

        # Build a flat, time-ordered list of all (datetime, event) transitions
        # for the next 8 days, then find the first one after `now_dt`.
        transitions = []
        for day_offset in range(0, 9):
            day = now_dt + timedelta(days=day_offset)
            wd = day.weekday()
            for w in windows:
                if w["weekday"] != wd:
                    continue
                start_dt = day.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(minutes=w["start_minute"])
                end_dt = day.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(minutes=w["end_minute"])
                transitions.append((start_dt, "open"))
                transitions.append((end_dt, "close"))

        transitions.sort(key=lambda t: t[0])
        for dt, _kind in transitions:
            if dt > now_dt:
                return is_open_now, dt
        return is_open_now, None

    # ---------------------------------------------------- convenience setup
    def quick_setup_business_hours(
        self, tenant: str, timezone: str, start_hhmm: str, end_hhmm: str,
        weekdays: Optional[List[int]] = None, updated_by: str = "user",
    ) -> Dict[str, Any]:
        """Convenience helper for the common case: "we're open Mon-Fri,
        09:00 to 18:00" entered once by the user."""
        weekdays = weekdays if weekdays is not None else [0, 1, 2, 3, 4]
        sh, sm = [int(x) for x in start_hhmm.split(":")]
        eh, em = [int(x) for x in end_hhmm.split(":")]
        windows = [
            {"weekday": wd, "start_minute": sh * 60 + sm, "end_minute": eh * 60 + em, "label": "business_hours"}
            for wd in weekdays
        ]
        return self.save_config(tenant, timezone, windows, updated_by=updated_by)
