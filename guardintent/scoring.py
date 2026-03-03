from __future__ import annotations

from collections import defaultdict

from guardintent.models import Incident, RuleHit


def severity_from_score(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _entity_key(entities: dict[str, object]) -> str:
    src = entities.get("src_ip") or ""
    user = entities.get("user") or ""
    host = entities.get("hostname") or ""
    return f"{src}|{user}|{host}"


def aggregate_hits(hits: list[RuleHit]) -> list[Incident]:
    grouped: dict[str, list[RuleHit]] = defaultdict(list)
    for hit in hits:
        key = _entity_key(hit.entities)
        if key == "||":
            key = f"rule:{hit.rule_id}:{len(grouped)}"
        grouped[key].append(hit)

    incidents: list[Incident] = []
    for _, group in grouped.items():
        score = sum(h.score for h in group)
        rule_ids = sorted({h.rule_id for h in group})
        entities: dict[str, object] = {}
        for hit in group:
            entities.update({k: v for k, v in hit.entities.items() if v})
        recommendations = sorted({h.recommendation for h in group})
        mitre_techniques = sorted({tech for h in group for tech in h.mitre_techniques})
        title = " & ".join(h.name for h in group[:2])
        incidents.append(
            Incident(
                title=f"{title} detected",
                severity=severity_from_score(score),
                score=score,
                rule_hits=rule_ids,
                entities=entities,
                evidence=[h.evidence for h in group],
                recommendations=recommendations,
                mitre_techniques=mitre_techniques,
            )
        )
    incidents.sort(key=lambda i: i.score, reverse=True)
    return incidents


def filter_by_min_severity(incidents: list[Incident], min_severity: str) -> list[Incident]:
    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    threshold = rank[min_severity.lower()]
    return [i for i in incidents if rank[i.severity] >= threshold]
