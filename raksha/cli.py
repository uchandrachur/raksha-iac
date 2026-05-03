"""raksha-iac CLI — `raksha scan ...`"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from raksha.models import Severity
from raksha.reporter import write_report
from raksha.scanner import Scanner

app = typer.Typer(
    name="raksha",
    help="Terraform security scanner with India-specific compliance rules.",
    no_args_is_help=True,
    add_completion=False,
)


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Path to .tf file or directory")],
    rules: Annotated[
        str,
        typer.Option(
            "--rules",
            help="Comma-separated rule packs: generic, dpdpa, rbi",
        ),
    ] = "generic,dpdpa",
    fmt: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: text, json, html, sarif",
        ),
    ] = "text",
    out: Annotated[
        Path | None,
        typer.Option(
            "--out",
            "-o",
            help="Write report to file instead of stdout (ignored for text)",
        ),
    ] = None,
    severity_threshold: Annotated[
        str,
        typer.Option(
            "--severity-threshold",
            help="Exit non-zero if any finding at or above this severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)",
        ),
    ] = "HIGH",
    remediate: Annotated[
        bool,
        typer.Option(
            "--remediate",
            help="Generate AI remediation suggestions (requires ANTHROPIC_API_KEY or OPENAI_API_KEY)",
        ),
    ] = False,
    llm_provider: Annotated[
        str,
        typer.Option(
            "--llm-provider",
            help="LLM provider for remediation: anthropic | openai",
        ),
    ] = "anthropic",
) -> None:
    """Scan Terraform files for security and compliance issues."""
    console = Console()

    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] path not found: {path}")
        raise typer.Exit(2)

    try:
        rule_packs = [r.strip() for r in rules.split(",") if r.strip()]
        scanner = Scanner(rule_packs=rule_packs)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(2) from e

    report = scanner.scan(path)

    if remediate and report.findings:
        console.print("[dim]→ Generating AI remediation...[/dim]")
        from raksha.llm import add_ai_remediation
        add_ai_remediation(report.findings, provider=llm_provider)

    write_report(report, fmt=fmt, out=out)

    # Exit code based on severity threshold
    try:
        threshold = Severity(severity_threshold.upper())
    except ValueError:
        console.print(f"[bold red]Error:[/bold red] invalid severity: {severity_threshold}")
        raise typer.Exit(2) from None

    if report.has_findings_at(threshold):
        sys.exit(1)
    sys.exit(0)


@app.command(name="list-rules")
def list_rules(
    pack: Annotated[
        str | None,
        typer.Option("--pack", help="Filter by pack: generic, dpdpa, rbi"),
    ] = None,
) -> None:
    """List all available rules."""
    from raksha.rules import PACKS

    console = Console()
    packs = [pack] if pack else list(PACKS.keys())
    for p in packs:
        if p not in PACKS:
            console.print(f"[red]Unknown pack: {p}[/red]")
            continue
        console.rule(f"[bold cyan]{p}[/bold cyan]")
        for rule_cls in PACKS[p]:
            console.print(
                f"  [bold]{rule_cls.id}[/bold]  [{rule_cls.severity.value}]  "
                f"{rule_cls.description}"
            )


if __name__ == "__main__":  # pragma: no cover
    app()
