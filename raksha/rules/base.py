"""Base Rule class — every rule subclasses this and overrides evaluate()."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from raksha.models import Finding, Resource, Severity


class Rule(ABC):
    """Abstract base for all rules.

    Subclasses define class-level metadata and implement `evaluate`. A rule fires
    when `evaluate` returns True for a given resource.
    """

    id: str = "BASE-000"
    pack: str = "generic"
    severity: Severity = Severity.MEDIUM
    description: str = ""
    reference: str | None = None
    remediation: str | None = None
    resource_types: list[str] = []  # subclass overrides; empty = applies to all

    def applies_to(self, resource: Resource) -> bool:
        """True if this rule should evaluate the given resource."""
        if not self.resource_types:
            return True
        return resource.type in self.resource_types

    @abstractmethod
    def evaluate(self, resource: Resource) -> bool:
        """Return True if the resource VIOLATES the rule (i.e. emit a finding)."""
        ...

    def to_finding(self, resource: Resource) -> Finding:
        return Finding(
            rule_id=self.id,
            rule_pack=self.pack,
            severity=self.severity,
            description=self.description,
            resource=resource,
            reference=self.reference,
            remediation=self.remediation,
        )


# --- helper utilities used across rule files -------------------------------

def get_nested(cfg: dict[str, Any], *path: str, default: Any = None) -> Any:
    """Safely traverse nested dicts. get_nested(cfg, 'a', 'b') == cfg.get('a',{}).get('b')."""
    value: Any = cfg
    for key in path:
        if not isinstance(value, dict):
            return default
        value = value.get(key, default)
        if value is default:
            return default
    return value


def has_tag(cfg: dict[str, Any], tag_key: str) -> bool:
    """Check if Terraform resource has a tag with the given key (case-insensitive)."""
    tags = cfg.get("tags") or {}
    if isinstance(tags, list) and tags:
        tags = tags[0] if isinstance(tags[0], dict) else {}
    if not isinstance(tags, dict):
        return False
    return any(k.lower() == tag_key.lower() for k in tags)


def tag_value(cfg: dict[str, Any], tag_key: str) -> str | None:
    tags = cfg.get("tags") or {}
    if isinstance(tags, list) and tags:
        tags = tags[0] if isinstance(tags[0], dict) else {}
    if not isinstance(tags, dict):
        return None
    for k, v in tags.items():
        if k.lower() == tag_key.lower():
            return str(v) if v is not None else None
    return None
