"""
Security Report Generator.

Builds Boundary Evolution / Drift / Blind Spot / Relationship Churn /
Historical Comparison / Incident Summary reports and exports them as JSON,
CSV, Markdown or HTML (HTML output is print-to-PDF ready from any browser).
"""
from __future__ import annotations

import csv
import io
import json
import time
from typing import Any, Dict, List

from .boundary_engine import BoundaryMemoryEngine
from .collector_confidence import BlindSpotDetector
from .graph import TemporalSecurityGraph
from .storage import SQLiteStorage, get_storage


class SecurityReportGenerator:
    def __init__(self, storage: SQLiteStorage | None = None):
        self.storage = storage or get_storage()
        self.graph = TemporalSecurityGraph(self.storage)
        self.memory = BoundaryMemoryEngine(self.storage)
        self.blind_spots = BlindSpotDetector(self.storage)

    def build_entity_report(self, entity_id: str) -> Dict[str, Any]:
        entity = self.graph.get_entity(entity_id)
        boundary = self.memory.get_full_boundary(entity_id)
        drifts = self.storage.list_drifts(entity_id=entity_id)
        snapshots = self.storage.list_snapshots(entity_id)
        stability = self.memory.stability_index(entity_id)
        return {
            "generated_at": time.time(),
            "entity": entity,
            "boundary": boundary,
            "drift_history": drifts,
            "snapshots": [s["id"] for s in snapshots],
            "stability_index": stability,
        }

    def build_organization_report(self, tenant: str = "default") -> Dict[str, Any]:
        entities = self.storage.list_entities(tenant, limit=1000)
        drifts = self.storage.list_drifts(limit=1000)
        incidents = self.storage.list_incidents()
        blind = self.blind_spots.low_visibility_entities(tenant)
        return {
            "generated_at": time.time(),
            "tenant": tenant,
            "entity_count": len(entities),
            "drift_count": len(drifts),
            "incident_count": len(incidents),
            "blind_spot_count": len(blind),
            "top_drift_entities": self._top_drift_entities(drifts),
        }

    @staticmethod
    def _top_drift_entities(drifts: List[Dict[str, Any]], top_n: int = 10) -> List[Dict[str, Any]]:
        counts: Dict[str, int] = {}
        for d in drifts:
            counts[d["entity_id"]] = counts.get(d["entity_id"], 0) + 1
        ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
        return [{"entity_id": k, "drift_count": v} for k, v in ranked]

    # ------------------------------------------------------------- exports
    def to_json(self, report: Dict[str, Any]) -> str:
        return json.dumps(report, indent=2, default=str)

    def to_csv(self, rows: List[Dict[str, Any]]) -> str:
        if not rows:
            return ""
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
        return buf.getvalue()

    def to_markdown(self, report: Dict[str, Any], title: str = "ECHOBOUND Security Report") -> str:
        lines = [f"# {title}", "", f"_Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(report.get('generated_at', time.time())))}_", ""]
        for key, value in report.items():
            if key == "generated_at":
                continue
            lines.append(f"## {key.replace('_', ' ').title()}")
            if isinstance(value, (dict, list)):
                lines.append("```json")
                lines.append(json.dumps(value, indent=2, default=str))
                lines.append("```")
            else:
                lines.append(str(value))
            lines.append("")
        return "\n".join(lines)

    def to_html(self, report: Dict[str, Any], title: str = "ECHOBOUND Security Report") -> str:
        md = self.to_markdown(report, title)
        body = md.replace("\n", "<br/>\n")
        return f"""<!doctype html><html><head><meta charset="utf-8"><title>{title}</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;background:#0b0e14;color:#e6e9ef;padding:32px;}}
h1,h2{{color:#5ad1ff}} pre{{background:#141924;padding:12px;border-radius:8px;overflow:auto}}</style>
</head><body><pre>{md}</pre></body></html>"""
