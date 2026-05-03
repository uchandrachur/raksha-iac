"""Main scanner — orchestrates parsing and rule evaluation."""
from __future__ import annotations

from pathlib import Path

from raksha.models import Finding, ScanReport
from raksha.parser import parse_path
from raksha.rules import load_rules


class Scanner:
    """Orchestrates Terraform parsing + rule evaluation."""

    def __init__(self, rule_packs: list[str]) -> None:
        self.rule_packs = rule_packs
        self.rules = load_rules(rule_packs)

    def scan(self, path: str | Path) -> ScanReport:
        resources = parse_path(path)
        findings: list[Finding] = []

        files = {r.file for r in resources}

        for resource in resources:
            for rule in self.rules:
                if not rule.applies_to(resource):
                    continue
                try:
                    if rule.evaluate(resource):
                        findings.append(rule.to_finding(resource))
                except Exception as e:  # pragma: no cover
                    # A rule should never crash the whole scan
                    print(f"[warn] rule {rule.id} crashed on {resource.address}: {e}")

        return ScanReport(
            findings=findings,
            files_scanned=len(files),
            resources_scanned=len(resources),
            rules_used=self.rule_packs,
        )
