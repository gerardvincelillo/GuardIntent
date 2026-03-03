from __future__ import annotations

import json
import os
from typing import Any
from urllib import error, request


class VirusTotalClient:
    def __init__(self, api_key: str | None = None, timeout: int = 8) -> None:
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.timeout = timeout

    def enabled(self) -> bool:
        return bool(self.api_key)

    def lookup_ioc(self, ioc: str) -> dict[str, Any] | None:
        if not self.api_key:
            return None

        url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
        req = request.Request(
            url,
            headers={
                "x-apikey": self.api_key,
                "accept": "application/json",
            },
            method="GET",
        )
        try:
            with request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
                meta = payload.get("meta", {})
                return {
                    "query": ioc,
                    "count": meta.get("count", 0),
                    "engine": "virustotal",
                }
        except (error.URLError, TimeoutError, json.JSONDecodeError):
            return None


def collect_iocs_for_enrichment(incident_evidence: list[dict[str, Any]]) -> set[str]:
    values: set[str] = set()
    for evidence in incident_evidence:
        for match in evidence.get("matches", []):
            value = match.get("value")
            if value:
                values.add(str(value))
    return values
