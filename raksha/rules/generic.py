"""Generic cloud security rules — multi-cloud baseline."""
from __future__ import annotations

from raksha.models import Resource, Severity
from raksha.rules.base import Rule, get_nested


class S3PublicAccessBlock(Rule):
    id = "GEN-001"
    pack = "generic"
    severity = Severity.CRITICAL
    description = "S3 bucket public access block has at least one setting disabled"
    reference = "AWS Foundational Security Best Practices · S3.8"
    remediation = "Set block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets all to true"
    resource_types = ["aws_s3_bucket_public_access_block"]

    def evaluate(self, r: Resource) -> bool:
        for k in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"):
            if r.config.get(k) is False:
                return True
        return False


class S3BucketAclPublic(Rule):
    id = "GEN-002"
    pack = "generic"
    severity = Severity.CRITICAL
    description = "S3 bucket ACL set to public-read or public-read-write"
    reference = "CIS AWS Foundations 2.1.5"
    remediation = "Use 'private' ACL and bucket policy / IAM for access control"
    resource_types = ["aws_s3_bucket_acl", "aws_s3_bucket"]

    def evaluate(self, r: Resource) -> bool:
        acl = r.config.get("acl")
        return acl in ("public-read", "public-read-write")


class S3EncryptionMissing(Rule):
    id = "GEN-003"
    pack = "generic"
    severity = Severity.HIGH
    description = "S3 bucket missing server-side encryption configuration"
    reference = "CIS AWS Foundations 2.1.1"
    remediation = "Add aws_s3_bucket_server_side_encryption_configuration with SSE-KMS"
    resource_types = ["aws_s3_bucket"]

    def evaluate(self, r: Resource) -> bool:
        return r.config.get("server_side_encryption_configuration") is None


class EbsVolumeUnencrypted(Rule):
    id = "GEN-004"
    pack = "generic"
    severity = Severity.HIGH
    description = "EBS volume is not encrypted"
    reference = "CIS AWS Foundations 2.2.1"
    remediation = "Set encrypted = true and reference a kms_key_id"
    resource_types = ["aws_ebs_volume"]

    def evaluate(self, r: Resource) -> bool:
        return r.config.get("encrypted") is not True


class SecurityGroupOpenIngress(Rule):
    id = "GEN-005"
    pack = "generic"
    severity = Severity.HIGH
    description = "Security group allows 0.0.0.0/0 ingress on a sensitive port (22, 3389, 3306, 5432, 27017)"
    reference = "CIS AWS Foundations 4.1, 4.2"
    remediation = "Restrict cidr_blocks to specific IP ranges; use bastion or SSM Session Manager for SSH"
    resource_types = ["aws_security_group"]

    SENSITIVE_PORTS = {22, 3389, 3306, 5432, 27017, 1433}

    def evaluate(self, r: Resource) -> bool:
        ingress = r.config.get("ingress") or []
        if isinstance(ingress, dict):
            ingress = [ingress]
        for rule in ingress:
            if not isinstance(rule, dict):
                continue
            cidrs = rule.get("cidr_blocks") or []
            if "0.0.0.0/0" not in cidrs:
                continue
            from_port = rule.get("from_port")
            to_port = rule.get("to_port")
            if isinstance(from_port, int) and isinstance(to_port, int):
                if any(p for p in self.SENSITIVE_PORTS if from_port <= p <= to_port):
                    return True
        return False


class RdsStorageUnencrypted(Rule):
    id = "GEN-006"
    pack = "generic"
    severity = Severity.HIGH
    description = "RDS instance storage is not encrypted at rest"
    reference = "CIS AWS Foundations 2.3.1"
    remediation = "Set storage_encrypted = true and reference a kms_key_id"
    resource_types = ["aws_db_instance", "aws_rds_cluster"]

    def evaluate(self, r: Resource) -> bool:
        return r.config.get("storage_encrypted") is not True


class CloudtrailNotMultiRegion(Rule):
    id = "GEN-007"
    pack = "generic"
    severity = Severity.MEDIUM
    description = "CloudTrail is not configured as multi-region"
    reference = "CIS AWS Foundations 3.1"
    remediation = "Set is_multi_region_trail = true"
    resource_types = ["aws_cloudtrail"]

    def evaluate(self, r: Resource) -> bool:
        return r.config.get("is_multi_region_trail") is not True


class KmsKeyRotationDisabled(Rule):
    id = "GEN-008"
    pack = "generic"
    severity = Severity.MEDIUM
    description = "KMS key does not have automatic rotation enabled"
    reference = "CIS AWS Foundations 3.7"
    remediation = "Set enable_key_rotation = true"
    resource_types = ["aws_kms_key"]

    def evaluate(self, r: Resource) -> bool:
        return r.config.get("enable_key_rotation") is not True


class IamPolicyWildcardAction(Rule):
    id = "GEN-009"
    pack = "generic"
    severity = Severity.HIGH
    description = "IAM policy contains wildcard action (\"*\") with broad scope"
    reference = "AWS IAM least-privilege principle"
    remediation = "Replace Action: \"*\" with explicit action list scoped to required operations"
    resource_types = ["aws_iam_policy", "aws_iam_role_policy"]

    def evaluate(self, r: Resource) -> bool:
        policy = r.config.get("policy")
        if isinstance(policy, str):
            # Heuristic: detect "Action": "*" pattern
            return '"Action": "*"' in policy or '"Action":"*"' in policy
        return False


class VpcFlowLogsDisabled(Rule):
    id = "GEN-010"
    pack = "generic"
    severity = Severity.MEDIUM
    description = "VPC has no flow logs configuration in this module"
    reference = "CIS AWS Foundations 3.9"
    remediation = "Add aws_flow_log resource attached to the VPC"
    resource_types = ["aws_vpc"]

    def evaluate(self, r: Resource) -> bool:
        # Heuristic: a vpc resource without an explicit comment-tag flagging flow logs nearby.
        # In practice, this is a lint warning since flow logs are a separate resource.
        return r.config.get("__has_flow_logs") is not True  # always fires unless annotated


class AzureStorageHttpsOnly(Rule):
    id = "GEN-011"
    pack = "generic"
    severity = Severity.HIGH
    description = "Azure storage account does not enforce HTTPS-only traffic"
    reference = "Azure Security Benchmark · Storage 3.1"
    remediation = "Set enable_https_traffic_only = true"
    resource_types = ["azurerm_storage_account"]

    def evaluate(self, r: Resource) -> bool:
        # Default in newer provider versions is true, but explicit false is a violation
        return r.config.get("enable_https_traffic_only") is False


class GcpBucketUniformAccessDisabled(Rule):
    id = "GEN-012"
    pack = "generic"
    severity = Severity.MEDIUM
    description = "GCP Storage bucket has uniform_bucket_level_access disabled"
    reference = "GCP Best Practices · Storage Security"
    remediation = "Set uniform_bucket_level_access = true to enforce IAM-only access"
    resource_types = ["google_storage_bucket"]

    def evaluate(self, r: Resource) -> bool:
        return r.config.get("uniform_bucket_level_access") is not True


GENERIC_RULES: list[type[Rule]] = [
    S3PublicAccessBlock,
    S3BucketAclPublic,
    S3EncryptionMissing,
    EbsVolumeUnencrypted,
    SecurityGroupOpenIngress,
    RdsStorageUnencrypted,
    CloudtrailNotMultiRegion,
    KmsKeyRotationDisabled,
    IamPolicyWildcardAction,
    AzureStorageHttpsOnly,
    GcpBucketUniformAccessDisabled,
]
