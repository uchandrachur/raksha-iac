"""RBI / CERT-In compliance rules for regulated financial entities.

These rules apply to resources tagged with `regulated_entity = "rbi"` and check
data residency, encryption, and audit-log retention against RBI Cyber Security
Framework + CERT-In Directive (April 2022) requirements.
"""
from __future__ import annotations

from raksha.models import Resource, Severity
from raksha.rules.base import Rule, has_tag, tag_value
from raksha.rules.dpdpa import INDIAN_REGIONS


def _is_rbi_regulated(r: Resource) -> bool:
    return (tag_value(r.config, "regulated_entity") or "").lower() == "rbi"


class RbiDataResidency(Rule):
    id = "RBI-001"
    pack = "rbi"
    severity = Severity.CRITICAL
    description = "RBI-regulated resource provisioned outside Indian regions"
    reference = "RBI IT Outsourcing Guidelines · Data Localization"
    remediation = "Move resource to ap-south-1, ap-south-2, asia-south1, asia-south2, or Indian Azure regions"
    resource_types: list[str] = []

    def applies_to(self, resource: Resource) -> bool:
        return _is_rbi_regulated(resource)

    def evaluate(self, r: Resource) -> bool:
        region = r.config.get("region") or r.config.get("location")
        if isinstance(region, list) and region:
            region = str(region[0])
        if not region:
            return False
        return str(region).lower() not in INDIAN_REGIONS


class RbiEncryptionStrength(Rule):
    id = "RBI-002"
    pack = "rbi"
    severity = Severity.HIGH
    description = "RBI-regulated resource missing AES-256 / TLS 1.2+ encryption indicator"
    reference = "RBI Cyber Security Framework · Encryption Standards"
    remediation = (
        "Set min_tls_version = \"TLS1_2\" (or higher) where applicable, "
        "and ensure KMS-backed AES-256 encryption at rest"
    )
    resource_types: list[str] = []

    def applies_to(self, resource: Resource) -> bool:
        return _is_rbi_regulated(resource)

    def evaluate(self, r: Resource) -> bool:
        cfg = r.config
        # Heuristic check on common attributes
        tls = cfg.get("min_tls_version") or cfg.get("minimum_tls_version")
        if tls and str(tls).lower() not in ("tls1_2", "tls1.2", "tls12", "tls1_3", "tls1.3"):
            return True
        # If encryption key absent on a resource that should have one
        if r.type in ("aws_db_instance", "aws_rds_cluster") and not cfg.get("kms_key_id"):
            return True
        return False


class RbiAuditLogRetention(Rule):
    id = "RBI-003"
    pack = "rbi"
    severity = Severity.HIGH
    description = "RBI-regulated audit log retention < 7 years"
    reference = "RBI Cyber Security Framework · Log Retention"
    remediation = "Set audit log retention to 2555 days (7 years) minimum on CloudTrail/log groups"
    resource_types = ["aws_cloudwatch_log_group", "aws_s3_bucket_lifecycle_configuration"]

    def evaluate(self, r: Resource) -> bool:
        if not _is_rbi_regulated(r):
            return False
        if r.type == "aws_cloudwatch_log_group":
            ret = r.config.get("retention_in_days")
            if isinstance(ret, int) and ret < 2555:
                return True
        return False


class CertInLogRetention180(Rule):
    id = "CERTIN-001"
    pack = "rbi"
    severity = Severity.HIGH
    description = "CERT-In Directive: log retention < 180 days"
    reference = "CERT-In Directive · 28-04-2022 · §3 (Log retention)"
    remediation = "Set retention_in_days >= 180 on aws_cloudwatch_log_group"
    resource_types = ["aws_cloudwatch_log_group"]

    def evaluate(self, r: Resource) -> bool:
        ret = r.config.get("retention_in_days")
        if not isinstance(ret, int):
            return False
        return ret < 180


class CertInNtpServer(Rule):
    id = "CERTIN-002"
    pack = "rbi"
    severity = Severity.MEDIUM
    description = "EC2 launch template references non-NIC NTP server (CERT-In requires NIC time sync)"
    reference = "CERT-In Directive · 28-04-2022 · §2 (Time synchronization)"
    remediation = (
        "Configure systems to sync to time.nplindia.org or nic NTP servers. "
        "Tag launch templates with ntp_source = \"nic\" once configured."
    )
    resource_types = ["aws_launch_template", "aws_instance"]

    def evaluate(self, r: Resource) -> bool:
        # Heuristic — fires if no ntp_source tag is set on instance/launch template
        return not has_tag(r.config, "ntp_source")


RBI_RULES: list[type[Rule]] = [
    RbiDataResidency,
    RbiEncryptionStrength,
    RbiAuditLogRetention,
    CertInLogRetention180,
    CertInNtpServer,
]
