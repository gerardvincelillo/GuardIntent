from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from guardintent.config import Config
from guardintent.iocs.loader import ioc_stats, load_iocs
from guardintent.models import RuleHit
from guardintent.normalize.normalizer import parse_logs
from guardintent.reporting.json import write_json_report
from guardintent.reporting.markdown import write_markdown_report
from guardintent.rules.base import available_rules
from guardintent.scoring import aggregate_hits, filter_by_min_severity
from guardintent.utils import ensure_dir, now_utc_iso, ts_for_filename

app = typer.Typer(help="GuardIntent CLI: security automation and triage framework")
console = Console()


def _parse_formats(fmt: str) -> set[str]:
    allowed = {"md", "json"}
    selected = {x.strip().lower() for x in fmt.split(",") if x.strip()}
    if not selected or not selected.issubset(allowed):
        raise typer.BadParameter("--format must use md and/or json (comma-separated)")
    return selected


@app.command()
def parse(
    logs: str = typer.Option(..., "--logs", help="Input logs path (.jsonl/.json/.csv)"),
    out: str = typer.Option(..., "--out", help="Output normalized JSONL path"),
) -> None:
    """Normalize raw logs into the GuardIntent event schema."""
    events = parse_logs(logs)
    output_path = Path(out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(e.to_dict()) for e in events]
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    console.print(f"[green]Normalized {len(events)} events[/green] -> {output_path}")


@app.command("iocs")
def iocs_command(
    iocs: str = typer.Option(..., "--iocs", help="IOC file path (.txt/.json)"),
) -> None:
    """Load, validate, and count IOC entries."""
    loaded = load_iocs(iocs)
    stats = ioc_stats(loaded)

    table = Table(title="IOC Stats")
    table.add_column("Type")
    table.add_column("Count", justify="right")
    for key in ["ip", "domain", "url", "sha256"]:
        table.add_row(key, str(stats[key]))
    table.add_row("total", str(sum(stats.values())))
    console.print(table)


@app.command("rules")
def rules_command(
    list_rules: bool = typer.Option(False, "--list", help="List all rules"),
    show: str | None = typer.Option(None, "--show", help="Show details for a specific rule id"),
) -> None:
    """List available detection rules and details."""
    rules = [rule_cls() for rule_cls in available_rules()]
    if list_rules:
        for rule in rules:
            console.print(f"- [cyan]{rule.rule_id}[/cyan]: {rule.name}")
        return
    if show:
        target = next((r for r in rules if r.rule_id == show), None)
        if not target:
            raise typer.BadParameter(f"Unknown rule id: {show}")
        console.print(f"[bold]{target.name}[/bold]")
        console.print(f"id: {target.rule_id}")
        console.print(target.description)
        return
    raise typer.BadParameter("Use --list or --show <rule_id>")


@app.command()
def scan(
    logs: str = typer.Option(..., "--logs", help="Input log file"),
    iocs: str = typer.Option(..., "--iocs", help="IOC feed file"),
    out: str = typer.Option("reports", "--out", help="Output report directory"),
    format: str = typer.Option("md,json", "--format", help="Comma-separated formats: md,json"),
    config: str | None = typer.Option(None, "--config", help="Optional config.yaml path"),
    min_severity: str = typer.Option("low", "--min-severity", help="low|medium|high|critical"),
    verbose: bool = typer.Option(False, "--verbose", help="Verbose output"),
) -> None:
    """Run full triage workflow: parse, detect, score, report."""
    min_severity = min_severity.lower()
    if min_severity not in {"low", "medium", "high", "critical"}:
        raise typer.BadParameter("--min-severity must be low|medium|high|critical")

    formats = _parse_formats(format)
    cfg = Config.load(config)
    events = parse_logs(logs)
    ioc_feed = load_iocs(iocs)

    if verbose:
        console.print(f"Loaded {len(events)} normalized events")
        console.print(f"IOC counts: {ioc_stats(ioc_feed)}")

    hits: list[RuleHit] = []
    for rule_cls in available_rules():
        rule = rule_cls()
        rule_hits = rule.run(events, cfg, iocs=ioc_feed)
        hits.extend(rule_hits)
        if verbose:
            console.print(f"Rule {rule.rule_id}: {len(rule_hits)} hit(s)")

    incidents = aggregate_hits(hits)
    incidents = filter_by_min_severity(incidents, min_severity)

    output_dir = ensure_dir(out)
    stamp = ts_for_filename()
    run_meta = {
        "generated_at": now_utc_iso(),
        "logs_path": str(Path(logs).resolve()),
        "iocs_path": str(Path(iocs).resolve()),
        "min_severity": min_severity,
        "rule_set_version": "v1",
    }

    written: list[Path] = []
    if "md" in formats:
        md_path = output_dir / f"guardintent_report_{stamp}.md"
        written.append(write_markdown_report(md_path, incidents, run_meta))
    if "json" in formats:
        json_path = output_dir / f"guardintent_report_{stamp}.json"
        written.append(write_json_report(json_path, incidents, run_meta))

    console.print(f"[green]Incidents generated:[/green] {len(incidents)}")
    for incident in incidents:
        console.print(f"- {incident.severity.upper()} ({incident.score}) {incident.title}")

    console.print("[bold]Reports:[/bold]")
    for path in written:
        console.print(f"- {path}")


if __name__ == "__main__":
    app()
