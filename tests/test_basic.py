"""Basic smoke tests — verify scanner detects expected violations."""
from __future__ import annotations

from pathlib import Path

import pytest

from raksha.models import Severity
from raksha.scanner import Scanner

EXAMPLES = Path(__file__).parent.parent / "examples"


def test_bad_tf_has_findings():
    scanner = Scanner(rule_packs=["generic", "dpdpa", "rbi"])
    report = scanner.scan(EXAMPLES / "bad.tf")
    assert len(report.findings) > 0
    rule_ids = {f.rule_id for f in report.findings}
    # Expected violations
    assert "GEN-001" in rule_ids  # public access block
    assert "GEN-005" in rule_ids  # SG open SSH
    assert "DPDPA-002" in rule_ids  # encryption missing
    assert "DPDPA-005" in rule_ids  # classification tag missing
    assert "CERTIN-001" in rule_ids  # log retention < 180


def test_good_tf_has_few_findings():
    """Good tf should have minimal findings — if any, only low severity."""
    scanner = Scanner(rule_packs=["generic", "dpdpa", "rbi"])
    report = scanner.scan(EXAMPLES / "good.tf")
    # The good.tf is well-tagged; it may still have minor findings depending on
    # heuristic rules (e.g. VPC flow log lint). Critical/high should be zero.
    high_findings = [f for f in report.findings if f.severity.at_or_above(Severity.HIGH)]
    assert len(high_findings) == 0, f"Expected 0 high+ findings, got: {[f.rule_id for f in high_findings]}"


def test_only_generic_pack():
    scanner = Scanner(rule_packs=["generic"])
    report = scanner.scan(EXAMPLES / "bad.tf")
    rule_ids = {f.rule_id for f in report.findings}
    # Only generic rules fire; no DPDPA-* or RBI-* / CERTIN-*
    assert all(rid.startswith("GEN-") for rid in rule_ids)


def test_severity_threshold():
    scanner = Scanner(rule_packs=["generic", "dpdpa"])
    report = scanner.scan(EXAMPLES / "bad.tf")
    assert report.has_findings_at(Severity.HIGH)
    assert report.has_findings_at(Severity.CRITICAL)


def test_unknown_pack_rejected():
    with pytest.raises(ValueError):
        Scanner(rule_packs=["unknown_pack"])
