# GuardIntent

GuardIntent is a CLI-based security automation and triage framework that ingests log dumps, correlates against IOC feeds, runs detection rules, scores incident risk, and exports incident-style reports in Markdown and JSON.

## Why This Project

GuardIntent demonstrates:
- SOC detection engineering mindset
- Python modular architecture for security workflows
- IOC correlation and rule-driven detections
- Practical CLI UX for repeatable triage
- Shareable outputs for analyst and stakeholder review

## Features (v1 MVP)

- Log ingestion: `.jsonl`, `.json`, `.csv`
- IOC ingestion: `.txt` and `.json`
- IOC support: IPv4/IPv6, domains, URLs, SHA-256
- Detections:
  - `ioc_match`
  - `brute_force`
  - `privileged_abnormal`
  - `rare_process`
  - `lateral_movement`
- Incident scoring and severity mapping
- Report exports:
  - Markdown incident report
  - JSON structured incident report
- Timestamped outputs under `reports/`

## Repository Layout

```text
GuardIntent/
├── guardintent/
│   ├── cli.py
│   ├── config.py
│   ├── models.py
│   ├── scoring.py
│   ├── utils.py
│   ├── normalize/
│   ├── iocs/
│   ├── rules/
│   └── reporting/
├── data/
│   ├── sample_logs.jsonl
│   └── sample_iocs.txt
├── reports/
├── tests/
├── config.yaml
├── PLAN.md
├── pyproject.toml
└── README.md
```

## Installation

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

python -m pip install -U pip
python -m pip install -e .
python -m pip install pytest
```

## CLI Usage

### 1) Full scan pipeline

```bash
guardintent scan \
  --logs data/sample_logs.jsonl \
  --iocs data/sample_iocs.txt \
  --out reports \
  --format md,json \
  --min-severity medium \
  --config config.yaml \
  --verbose
```

### 2) Normalize logs only

```bash
guardintent parse --logs data/sample_logs.jsonl --out data/normalized_logs.jsonl
```

### 3) Validate and count IOCs

```bash
guardintent iocs --iocs data/sample_iocs.txt
```

### 4) Rule discovery

```bash
guardintent rules --list
guardintent rules --show brute_force
```

## Event Schema

All parsed records normalize into this common event shape:

```json
{
  "timestamp": "2026-02-28T09:00:01Z",
  "source": "firewall|auth|endpoint|dns",
  "event_type": "auth|network|process|dns|web",
  "src_ip": "1.2.3.4",
  "dst_ip": "5.6.7.8",
  "domain": "example.com",
  "url": "http://example.com/path",
  "username": "user123",
  "hostname": "HOST01",
  "process_name": "powershell.exe",
  "hash_sha256": "abcdef...",
  "action": "allowed|blocked|failed|success",
  "raw": {}
}
```

## Scoring and Severity

- `0-24`: Low
- `25-49`: Medium
- `50-74`: High
- `75+`: Critical

Scores are cumulative across rule hits grouped by affected entities.

## Output Reports

`guardintent scan` writes timestamped files, for example:
- `reports/guardintent_report_20260303T150000Z.md`
- `reports/guardintent_report_20260303T150000Z.json`

Markdown report sections:
- Executive Summary
- Incident Overview
- Severity Breakdown
- Rule Hits & Evidence
- Matched IOCs
- Affected Assets
- Timeline
- Recommendations
- Appendix

## Test

```bash
pytest -q
```

## Milestone Status (v1)

- Milestone 1: Basic CLI - complete
- Milestone 2: Log parsing/normalization - complete
- Milestone 3: IOC engine - complete
- Milestone 4: Detection rules/scoring - complete
- Milestone 5: Report generation - complete
- Milestone 6: tests and sample dataset - complete

## Next Enhancements (v2+)

- Rule plugin architecture
- MITRE ATT&CK technique tagging
- Threat intel enrichment connectors
- Jira/webhook integrations
- HTML dashboard output
- GitHub Actions CI and Docker packaging
