"""Report formatters — text, JSON, HTML, SARIF."""
from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from raksha.models import ScanReport, Severity

SEVERITY_COLORS = {
    "CRITICAL": "bright_red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "white",
}


def render_text(report: ScanReport, console: Console | None = None) -> None:
    """Pretty terminal output."""
    console = console or Console()

    console.print()
    console.rule("[bold cyan]raksha-iac · scan complete[/bold cyan]")
    console.print(
        f"  rules: [bold]{', '.join(report.rules_used)}[/bold]   "
        f"files: [bold]{report.files_scanned}[/bold]   "
        f"resources: [bold]{report.resources_scanned}[/bold]"
    )
    console.rule()

    if not report.findings:
        console.print("[bold green]✓ No findings — clean scan![/bold green]")
        return

    for f in report.findings:
        color = SEVERITY_COLORS[f.severity.value]
        console.print(
            f"[{color}]✗ {f.severity.value:<9}[/{color}] "
            f"[bold]{f.rule_id:<11}[/bold] {f.description}"
        )
        console.print(
            f"            [dim]{f.resource.file}:{f.resource.line or '?'}   "
            f'resource "{f.resource.address}"[/dim]'
        )
        if f.reference:
            console.print(f"            [italic dim]{f.reference}[/italic dim]")
        if f.ai_remediation:
            console.print(f"            [cyan]→ {f.ai_remediation}[/cyan]")
        console.print()

    # Summary
    bs = report.by_severity
    summary_parts = [
        f"[bold]{bs['CRITICAL']}[/bold] [bright_red]critical[/bright_red]",
        f"[bold]{bs['HIGH']}[/bold] [red]high[/red]",
        f"[bold]{bs['MEDIUM']}[/bold] [yellow]medium[/yellow]",
        f"[bold]{bs['LOW']}[/bold] [blue]low[/blue]",
    ]
    console.rule()
    console.print(
        f"[bold]Summary:[/bold]  {len(report.findings)} findings   "
        + " · ".join(summary_parts)
    )


def render_json(report: ScanReport) -> str:
    return report.model_dump_json(indent=2)


def render_sarif(report: ScanReport) -> str:
    """SARIF 2.1.0 output for GitHub Code Scanning, Azure DevOps, etc."""
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in report.findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.description},
                "fullDescription": {"text": f.description},
                "helpUri": f.reference or "",
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(f.severity),
                },
            }
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _severity_to_sarif_level(f.severity),
                "message": {"text": f.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.resource.file},
                            "region": {"startLine": f.resource.line or 1},
                        }
                    }
                ],
            }
        )

    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "raksha-iac",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/umadayal/raksha-iac",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def render_html(report: ScanReport) -> str:
    """Minimal embedded-CSS HTML report — looks professional, no dependencies."""
    rows = ""
    for f in report.findings:
        rows += f"""
        <tr class="sev-{f.severity.value.lower()}">
          <td><span class="badge sev-{f.severity.value.lower()}">{f.severity.value}</span></td>
          <td><code>{f.rule_id}</code></td>
          <td>{f.description}</td>
          <td><code>{f.resource.address}</code><br><span class="loc">{f.resource.file}:{f.resource.line or '?'}</span></td>
          <td>{f.reference or ''}</td>
        </tr>
        """

    bs = report.by_severity
    return _HTML_TEMPLATE.format(
        rules=", ".join(report.rules_used),
        files=report.files_scanned,
        resources=report.resources_scanned,
        total=len(report.findings),
        critical=bs["CRITICAL"],
        high=bs["HIGH"],
        medium=bs["MEDIUM"],
        low=bs["LOW"],
        rows=rows,
    )


def _severity_to_sarif_level(s: Severity) -> str:
    return {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }[s.value]


_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>raksha-iac scan report</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; background: #f7f8fb; color: #111; margin: 0; padding: 0; }}
  header {{ background: #1f3864; color: white; padding: 24px 40px; }}
  header h1 {{ margin: 0; font-weight: 700; }}
  header .subtitle {{ opacity: 0.85; font-size: 14px; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 24px 40px; }}
  .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
  .card {{ background: white; padding: 16px 20px; border-radius: 6px; flex: 1; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }}
  .card .num {{ font-size: 28px; font-weight: 700; }}
  .card .label {{ color: #666; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }}
  table {{ width: 100%; background: white; border-collapse: collapse; box-shadow: 0 1px 2px rgba(0,0,0,0.05); border-radius: 6px; overflow: hidden; }}
  th {{ background: #1f3864; color: white; padding: 12px; text-align: left; font-weight: 600; font-size: 12px; letter-spacing: 0.5px; text-transform: uppercase; }}
  td {{ padding: 14px 12px; border-bottom: 1px solid #eee; font-size: 14px; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  code {{ background: #f1f3f5; padding: 2px 6px; border-radius: 3px; font-family: ui-monospace, "SF Mono", monospace; font-size: 12px; }}
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; letter-spacing: 0.5px; color: white; }}
  .sev-critical {{ background: #c00; }}
  .sev-high {{ background: #e44; }}
  .sev-medium {{ background: #d80; }}
  .sev-low {{ background: #28b; }}
  .loc {{ color: #888; font-size: 11px; }}
  .num.critical {{ color: #c00; }}
  .num.high {{ color: #e44; }}
  .num.medium {{ color: #d80; }}
  .num.low {{ color: #28b; }}
  footer {{ margin-top: 40px; padding: 24px 40px; color: #777; font-size: 12px; text-align: center; }}
</style>
</head>
<body>
<header>
  <h1>raksha-iac · scan report</h1>
  <div class="subtitle">rules: {rules}  ·  files: {files}  ·  resources: {resources}</div>
</header>
<div class="container">
  <div class="summary">
    <div class="card"><div class="num">{total}</div><div class="label">Total findings</div></div>
    <div class="card"><div class="num critical">{critical}</div><div class="label">Critical</div></div>
    <div class="card"><div class="num high">{high}</div><div class="label">High</div></div>
    <div class="card"><div class="num medium">{medium}</div><div class="label">Medium</div></div>
    <div class="card"><div class="num low">{low}</div><div class="label">Low</div></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Rule ID</th>
        <th>Description</th>
        <th>Resource</th>
        <th>Reference</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
</div>
<footer>
  Generated by <strong>raksha-iac</strong> · github.com/umadayal/raksha-iac
</footer>
</body>
</html>
"""


def write_report(report: ScanReport, fmt: str, out: Path | None = None) -> None:
    """Render a report and write to file (or stdout)."""
    if fmt == "text":
        render_text(report)
        return
    if fmt == "json":
        content = render_json(report)
    elif fmt == "sarif":
        content = render_sarif(report)
    elif fmt == "html":
        content = render_html(report)
    else:
        raise ValueError(f"Unknown format: {fmt}")

    if out:
        out.write_text(content)
    else:
        print(content)
