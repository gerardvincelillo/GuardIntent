from __future__ import annotations

import base64
import json
from typing import Any
from urllib import error, request

from guardintent.models import Incident


def post_webhook(url: str, incidents: list[Incident], timeout: int = 8) -> bool:
    payload = {
        "source": "guardintent",
        "incident_count": len(incidents),
        "incidents": [
            {
                "title": i.title,
                "severity": i.severity,
                "score": i.score,
                "rule_hits": i.rule_hits,
                "entities": i.entities,
            }
            for i in incidents
        ],
    }
    req = request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=timeout):
            return True
    except (error.URLError, TimeoutError):
        return False


def create_jira_issues(
    base_url: str,
    user: str,
    token: str,
    project_key: str,
    issue_type: str,
    incidents: list[Incident],
    timeout: int = 8,
) -> list[dict[str, Any]]:
    auth = base64.b64encode(f"{user}:{token}".encode("utf-8")).decode("utf-8")
    created: list[dict[str, Any]] = []

    for incident in incidents:
        body = {
            "fields": {
                "project": {"key": project_key},
                "summary": f"[GuardIntent] {incident.severity.upper()} - {incident.title}",
                "description": (
                    f"Score: {incident.score}\n"
                    f"Rule hits: {', '.join(incident.rule_hits)}\n"
                    f"Entities: {incident.entities}\n"
                    f"Recommendations: {incident.recommendations}"
                ),
                "issuetype": {"name": issue_type},
            }
        }
        req = request.Request(
            f"{base_url.rstrip('/')}/rest/api/3/issue",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Basic {auth}",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
                created.append(payload)
        except (error.URLError, TimeoutError, json.JSONDecodeError):
            continue
    return created
