from pathlib import Path

from typer.testing import CliRunner

from guardintent.cli import app


runner = CliRunner()


def test_scan_generates_reports(tmp_path: Path):
    result = runner.invoke(
        app,
        [
            "scan",
            "--logs",
            "data/sample_logs.jsonl",
            "--iocs",
            "data/sample_iocs.txt",
            "--out",
            str(tmp_path),
            "--format",
            "md,json",
            "--min-severity",
            "medium",
        ],
    )
    assert result.exit_code == 0

    md_reports = list(tmp_path.glob("*.md"))
    json_reports = list(tmp_path.glob("*.json"))
    assert len(md_reports) == 1
    assert len(json_reports) == 1

    payload = json_reports[0].read_text(encoding="utf-8")
    assert "incidents" in payload
