from __future__ import annotations

import json
from pathlib import Path

from guardintent.models import Incident


def write_json_report(path: str | Path, incidents: list[Incident], run_meta: dict) -> Path:
    p = Path(path)
    payload = {
        "run": run_meta,
        "incident_count": len(incidents),
        "incidents": [
            {
                "title": i.title,
                "severity": i.severity,
                "score": i.score,
                "rule_hits": i.rule_hits,
                "entities": i.entities,
                "evidence": i.evidence,
                "recommendations": i.recommendations,
                "mitre_techniques": i.mitre_techniques,
                "enrichments": i.enrichments,
            }
            for i in incidents
        ],
    }
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return p
