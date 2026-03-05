from guard_intent.reporting.diff import compare_reports


def test_compare_reports_detects_regression_and_resolution() -> None:
    baseline = {
        "incident_count": 2,
        "incidents": [
            {"title": "Brute force activity", "severity": "high"},
            {"title": "Rare process launch", "severity": "medium"},
        ],
    }
    current = {
        "incident_count": 2,
        "incidents": [
            {"title": "Rare process launch", "severity": "medium"},
            {"title": "Lateral movement pattern", "severity": "critical"},
        ],
    }

    result = compare_reports(baseline, current)
    assert result["new_incident_titles"] == ["Lateral movement pattern"]
    assert result["resolved_incident_titles"] == ["Brute force activity"]
    assert result["new_incidents_by_severity"] == {"critical": 1}
    assert result["status"] == "regression"
