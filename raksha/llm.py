"""LLM-augmented remediation — Claude or OpenAI generate explanations and fixes.

This module is opt-in: only invoked if --remediate flag is set on CLI and the
appropriate API key is in environment. No network calls happen otherwise.
"""
from __future__ import annotations

import os

from raksha.models import Finding

_PROMPT_TEMPLATE = """You are a senior cloud security architect helping engineers fix Terraform misconfigurations.

A scanner detected this issue:

Rule ID: {rule_id}
Severity: {severity}
Description: {description}
Regulatory reference: {reference}
Resource: {resource_type}.{resource_name}
Resource configuration:
```hcl
{config}
```

Provide a concise remediation in this exact format (no preamble):

1. ROOT CAUSE (one sentence): why this is a problem.
2. FIX: corrected Terraform snippet (only the changed attributes, in HCL).
3. VERIFICATION: one terraform / awscli command to verify the fix in production.

Keep total response under 150 words. Be specific and actionable."""


def _format_config_for_llm(cfg: dict, max_chars: int = 800) -> str:
    """Render a Terraform-like preview of the config dict, truncated."""
    import json
    s = json.dumps(cfg, indent=2, default=str)
    if len(s) > max_chars:
        s = s[:max_chars] + "\n... (truncated)"
    return s


def remediate_with_anthropic(finding: Finding, model: str = "claude-haiku-4-5") -> str:
    """Generate AI remediation using Anthropic Claude."""
    try:
        import anthropic
    except ImportError as e:
        raise RuntimeError(
            "anthropic package not installed. Run: pip install raksha-iac[llm]"
        ) from e

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not set in environment")

    client = anthropic.Anthropic(api_key=api_key)
    prompt = _PROMPT_TEMPLATE.format(
        rule_id=finding.rule_id,
        severity=finding.severity.value,
        description=finding.description,
        reference=finding.reference or "n/a",
        resource_type=finding.resource.type,
        resource_name=finding.resource.name,
        config=_format_config_for_llm(finding.resource.config),
    )

    message = client.messages.create(
        model=model,
        max_tokens=400,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text.strip()


def remediate_with_openai(finding: Finding, model: str = "gpt-4o-mini") -> str:
    """Generate AI remediation using OpenAI."""
    try:
        from openai import OpenAI
    except ImportError as e:
        raise RuntimeError(
            "openai package not installed. Run: pip install raksha-iac[llm]"
        ) from e

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set in environment")

    client = OpenAI(api_key=api_key)
    prompt = _PROMPT_TEMPLATE.format(
        rule_id=finding.rule_id,
        severity=finding.severity.value,
        description=finding.description,
        reference=finding.reference or "n/a",
        resource_type=finding.resource.type,
        resource_name=finding.resource.name,
        config=_format_config_for_llm(finding.resource.config),
    )

    response = client.chat.completions.create(
        model=model,
        max_tokens=400,
        messages=[{"role": "user", "content": prompt}],
    )
    return (response.choices[0].message.content or "").strip()


def add_ai_remediation(findings: list[Finding], provider: str = "anthropic") -> None:
    """Mutate findings in-place, adding AI remediation text. Best-effort."""
    fn = remediate_with_anthropic if provider == "anthropic" else remediate_with_openai
    for f in findings:
        try:
            f.ai_remediation = fn(f)
        except Exception as e:  # pragma: no cover
            f.ai_remediation = f"[remediation unavailable: {e}]"
