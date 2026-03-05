from __future__ import annotations

from collections import Counter
from typing import Any


def _incident_map(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    incidents = payload.get("incidents", [])
    mapped: dict[str, dict[str, Any]] = {}
    for incident in incidents:
        if not isinstance(incident, dict):
            continue
        title = str(incident.get("title", "")).strip()
        if title:
            mapped[title] = incident
    return mapped


def compare_reports(baseline_payload: dict[str, Any], current_payload: dict[str, Any]) -> dict[str, Any]:
    baseline = _incident_map(baseline_payload)
    current = _incident_map(current_payload)
    new_titles = sorted(set(current) - set(baseline))
    resolved_titles = sorted(set(baseline) - set(current))
    new_incidents = [current[title] for title in new_titles]
    severity_counts = Counter(str(item.get("severity", "unknown")).lower() for item in new_incidents)

    baseline_count = int(baseline_payload.get("incident_count", len(baseline_payload.get("incidents", []))))
    current_count = int(current_payload.get("incident_count", len(current_payload.get("incidents", []))))

    return {
        "baseline_incident_count": baseline_count,
        "current_incident_count": current_count,
        "incident_count_delta": current_count - baseline_count,
        "new_incident_titles": new_titles,
        "resolved_incident_titles": resolved_titles,
        "new_incidents_by_severity": dict(severity_counts),
        "status": "regression" if severity_counts.get("high", 0) or severity_counts.get("critical", 0) else "stable",
    }
