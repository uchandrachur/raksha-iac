"""DPDPA (India Digital Personal Data Protection Act, 2023) compliance rules.

These rules detect Terraform configurations that are likely to violate the DPDPA
when handling personal data of Indian Data Principals. The rules use resource
tagging to identify "personal data resources" — any resource tagged with
`data_classification = "personal"` or `"sensitive_personal"`.

Disclaimer: this is a working interpretation of public regulatory text and not
a substitute for a Data Protection Officer review.
"""
from __future__ import annotations

from raksha.models import Resource, Severity
from raksha.rules.base import Rule, has_tag, tag_value

# Resource types that commonly hold personal data
PERSONAL_DATA_RESOURCE_TYPES = {
    "aws_s3_bucket",
    "aws_dynamodb_table",
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_efs_file_system",
    "aws_elasticsearch_domain",
    "aws_opensearch_domain",
    "azurerm_storage_account",
    "azurerm_cosmosdb_account",
    "azurerm_postgresql_server",
    "azurerm_mysql_server",
    "google_storage_bucket",
    "google_bigquery_dataset",
    "google_sql_database_instance",
}

# DPDPA Section 16: data transfer permitted only to countries notified by the Government
# As of late 2025, no countries are formally restricted; this rule guards against
# common patterns where data is replicated to obviously-non-Indian regions for
# resources tagged as personal.
INDIAN_REGIONS = {
    "ap-south-1", "ap-south-2",            # AWS Mumbai, Hyderabad
    "centralindia", "southindia", "westindia", "jioindiacentral", "jioindiawest",  # Azure
    "asia-south1", "asia-south2",          # GCP Mumbai, Delhi
}


def _is_personal_data_resource(r: Resource) -> bool:
    """Resource is in scope if explicitly tagged personal/sensitive_personal."""
    if r.type not in PERSONAL_DATA_RESOURCE_TYPES:
        return False
    classification = tag_value(r.config, "data_classification") or ""
    return classification.lower() in ("personal", "sensitive_personal")


class DpdpaConsentTagMissing(Rule):
    id = "DPDPA-001"
    pack = "dpdpa"
    severity = Severity.MEDIUM
    description = "Personal data resource missing consent_basis tag"
    reference = "DPDPA §6, §7 — Notice & Consent"
    remediation = (
        "Add tag consent_basis = \"explicit\" | \"legitimate_use\" | \"legal_obligation\" "
        "to document the lawful basis for processing"
    )
    resource_types: list[str] = []  # checked dynamically

    def applies_to(self, resource: Resource) -> bool:
        return _is_personal_data_resource(resource)

    def evaluate(self, r: Resource) -> bool:
        return not has_tag(r.config, "consent_basis")


class DpdpaEncryptionAtRestMissing(Rule):
    id = "DPDPA-002"
    pack = "dpdpa"
    severity = Severity.HIGH
    description = "Personal data resource missing encryption-at-rest configuration"
    reference = "DPDPA §8(5) — Reasonable security safeguards"
    remediation = "Enable provider-native encryption (KMS-backed) for the resource"
    resource_types: list[str] = []

    def applies_to(self, resource: Resource) -> bool:
        return _is_personal_data_resource(resource)

    def evaluate(self, r: Resource) -> bool:
        cfg = r.config
        # Encryption signals vary by resource type
        if r.type == "aws_s3_bucket":
            return cfg.get("server_side_encryption_configuration") is None
        if r.type in ("aws_db_instance", "aws_rds_cluster"):
            return cfg.get("storage_encrypted") is not True
        if r.type == "aws_dynamodb_table":
            return not cfg.get("server_side_encryption")
        if r.type == "aws_efs_file_system":
            return cfg.get("encrypted") is not True
        if r.type == "azurerm_storage_account":
            return cfg.get("enable_https_traffic_only") is False
        if r.type in ("google_storage_bucket", "google_bigquery_dataset"):
            return cfg.get("encryption") is None and cfg.get("default_kms_key_name") is None
        return False


class DpdpaCrossBorderTransfer(Rule):
    id = "DPDPA-003"
    pack = "dpdpa"
    severity = Severity.HIGH
    description = "Personal data resource provisioned in non-Indian region without explicit transfer approval tag"
    reference = "DPDPA §16 — Transfer of personal data outside India"
    remediation = (
        "Either provision in an Indian region (ap-south-1, ap-south-2, asia-south1, "
        "centralindia, southindia) OR add tag cross_border_transfer_approved = \"true\" "
        "with documented basis"
    )
    resource_types: list[str] = []

    def applies_to(self, resource: Resource) -> bool:
        return _is_personal_data_resource(resource)

    def evaluate(self, r: Resource) -> bool:
        # Region is sometimes on the resource itself; usually inherited from provider.
        # Check explicit region/location attribute if present.
        region = (
            r.config.get("region")
            or r.config.get("location")
            or r.config.get("availability_zones")
        )
        if isinstance(region, list) and region:
            region = str(region[0])
        if not region:
            return False  # cannot determine; don't false-positive
        if str(region).lower() in INDIAN_REGIONS:
            return False
        approved = tag_value(r.config, "cross_border_transfer_approved")
        return approved is None or approved.lower() != "true"


class DpdpaRetentionPolicyMissing(Rule):
    id = "DPDPA-004"
    pack = "dpdpa"
    severity = Severity.MEDIUM
    description = "Personal data resource has no lifecycle / retention policy"
    reference = "DPDPA §8(7) — Erasure of personal data"
    remediation = (
        "Define a lifecycle_rule (S3) or TTL (DynamoDB / Cosmos / BigQuery) "
        "aligned with the data retention period documented in the privacy notice"
    )
    resource_types: list[str] = []

    def applies_to(self, resource: Resource) -> bool:
        return _is_personal_data_resource(resource)

    def evaluate(self, r: Resource) -> bool:
        cfg = r.config
        if r.type == "aws_s3_bucket":
            return cfg.get("lifecycle_rule") is None
        if r.type == "aws_dynamodb_table":
            return not cfg.get("ttl")
        if r.type == "google_bigquery_dataset":
            return cfg.get("default_table_expiration_ms") is None
        # For databases, retention is typically external (backup policy); skip
        return False


class DpdpaClassificationTagMissing(Rule):
    id = "DPDPA-005"
    pack = "dpdpa"
    severity = Severity.HIGH
    description = "Data-store resource missing data_classification tag"
    reference = "DPDPA §8(8) — Reasonable security safeguards (governance)"
    remediation = (
        "Add tag data_classification = \"personal\" | \"sensitive_personal\" | "
        "\"non_personal\" | \"public\" so downstream policy can be applied consistently"
    )
    resource_types = list(PERSONAL_DATA_RESOURCE_TYPES)

    def evaluate(self, r: Resource) -> bool:
        return not has_tag(r.config, "data_classification")


class DpdpaAuditLoggingMissing(Rule):
    id = "DPDPA-006"
    pack = "dpdpa"
    severity = Severity.MEDIUM
    description = "Personal data resource has no audit logging tag (data access not provably audited)"
    reference = "DPDPA §8(8) + CERT-In Directive 2022"
    remediation = (
        "Add tag audit_logging = \"enabled\" and ensure CloudTrail data events / "
        "S3 access logs / DB audit policy is configured for this resource"
    )
    resource_types: list[str] = []

    def applies_to(self, resource: Resource) -> bool:
        return _is_personal_data_resource(resource)

    def evaluate(self, r: Resource) -> bool:
        return tag_value(r.config, "audit_logging") != "enabled"


class DpdpaSdfDpiaMissing(Rule):
    id = "DPDPA-007"
    pack = "dpdpa"
    severity = Severity.MEDIUM
    description = "Significant Data Fiduciary (SDF) resource missing dpia_completed tag"
    reference = "DPDPA §10 — Significant Data Fiduciary obligations"
    remediation = (
        "If your organization is a Significant Data Fiduciary, every personal-data "
        "resource must have dpia_completed = \"<YYYY-MM-DD>\" tag indicating last DPIA review"
    )
    resource_types: list[str] = []

    def applies_to(self, resource: Resource) -> bool:
        # Only fires on resources tagged sensitive_personal — proxy for SDF scope
        if resource.type not in PERSONAL_DATA_RESOURCE_TYPES:
            return False
        return (tag_value(resource.config, "data_classification") or "").lower() == "sensitive_personal"

    def evaluate(self, r: Resource) -> bool:
        return not has_tag(r.config, "dpia_completed")


DPDPA_RULES: list[type[Rule]] = [
    DpdpaConsentTagMissing,
    DpdpaEncryptionAtRestMissing,
    DpdpaCrossBorderTransfer,
    DpdpaRetentionPolicyMissing,
    DpdpaClassificationTagMissing,
    DpdpaAuditLoggingMissing,
    DpdpaSdfDpiaMissing,
]
