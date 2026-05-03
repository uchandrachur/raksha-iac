"""Terraform HCL parser — emits Resource objects for the rule engine."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import hcl2

from raksha.models import Resource


def parse_file(path: str | Path) -> list[Resource]:
    """Parse a single .tf file and return all resource blocks as Resource models."""
    path = Path(path)
    with path.open() as f:
        try:
            data = hcl2.load(f)
        except Exception as e:  # pragma: no cover
            raise ValueError(f"Failed to parse HCL in {path}: {e}") from e

    resources: list[Resource] = []
    for block in data.get("resource", []):
        # hcl2 returns each resource block as: {"<type>": {"<name>": {...config...}}}
        for rtype, named_blocks in block.items():
            rtype_clean = _unquote_str(rtype)
            for rname, cfg in named_blocks.items():
                rname_clean = _unquote_str(rname)
                normalized = _normalize(cfg)
                resources.append(
                    Resource(
                        type=rtype_clean,
                        name=rname_clean,
                        config=normalized,
                        file=str(path),
                    )
                )
    return resources


def parse_path(path: str | Path) -> list[Resource]:
    """Parse a single file or recursively scan a directory for .tf files."""
    path = Path(path)
    if path.is_file():
        return parse_file(path)
    if path.is_dir():
        all_resources: list[Resource] = []
        for tf_file in sorted(path.rglob("*.tf")):
            if ".terraform" in tf_file.parts:
                continue
            all_resources.extend(parse_file(tf_file))
        return all_resources
    raise FileNotFoundError(f"No such file or directory: {path}")


def _unquote_str(value: str) -> str:
    """Strip surrounding double-quotes left by python-hcl2 on string literals."""
    if isinstance(value, str) and len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _normalize(value: Any) -> Any:
    """Recursively unwrap single-element lists AND strip surrounding quotes from strings.

    python-hcl2 wraps scalars/maps in single-element lists and keeps the source
    quote characters on string values — both must be normalised before rules
    can compare values reliably.
    """
    if isinstance(value, list):
        if len(value) == 1:
            return _normalize(value[0])
        return [_normalize(v) for v in value]
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items()}
    if isinstance(value, str):
        return _unquote_str(value)
    return value
