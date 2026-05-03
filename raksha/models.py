"""Core data models — Resource, Finding, Severity."""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels — ordered for threshold comparison."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def at_or_above(self, threshold: "Severity") -> bool:
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        return order.index(self.value) >= order.index(threshold.value)


class Resource(BaseModel):
    """A single Terraform resource block parsed from .tf files."""

    type: str = Field(..., description="Resource type, e.g. aws_s3_bucket")
    name: str = Field(..., description="Resource local name, e.g. user_data")
    config: dict[str, Any] = Field(default_factory=dict, description="Resource attributes")
    file: str = Field(..., description="Source file path")
    line: int | None = Field(default=None, description="Source line if known")

    @property
    def address(self) -> str:
        """Terraform-style address: aws_s3_bucket.user_data"""
        return f"{self.type}.{self.name}"


class Finding(BaseModel):
    """A single rule violation found in a resource."""

    rule_id: str
    rule_pack: str = Field(..., description="generic | dpdpa | rbi")
    severity: Severity
    description: str
    resource: Resource
    reference: str | None = Field(
        default=None,
        description="Regulatory citation, e.g. 'DPDPA §8(5)'",
    )
    remediation: str | None = Field(default=None, description="Suggested fix")
    ai_remediation: str | None = Field(default=None, description="LLM-generated explanation")

    def short(self) -> str:
        loc = f"{self.resource.file}:{self.resource.line or '?'}"
        return f"{self.severity.value:9} {self.rule_id:11} {self.description}\n            {loc}   resource \"{self.resource.address}\""


class ScanReport(BaseModel):
    """Aggregate of all findings from one scan."""

    findings: list[Finding] = Field(default_factory=list)
    files_scanned: int = 0
    resources_scanned: int = 0
    rules_used: list[str] = Field(default_factory=list)

    @property
    def by_severity(self) -> dict[str, int]:
        result = dict.fromkeys([s.value for s in Severity], 0)
        for f in self.findings:
            result[f.severity.value] += 1
        return result

    def has_findings_at(self, threshold: Severity) -> bool:
        return any(f.severity.at_or_above(threshold) for f in self.findings)
