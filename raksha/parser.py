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
            for rname, cfg in named_blocks.items():
                # python-hcl2 wraps single values in lists; flatten one level
                normalized = _flatten_hcl_lists(cfg)
                resources.append(
                    Resource(
                        type=rtype,
                        name=rname,
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
            # Skip provider files and modules' own .terraform dirs
            if ".terraform" in tf_file.parts:
                continue
            all_resources.extend(parse_file(tf_file))
        return all_resources
    raise FileNotFoundError(f"No such file or directory: {path}")


def _flatten_hcl_lists(value: Any) -> Any:
    """python-hcl2 wraps scalars/maps in single-element lists; unwrap them."""
    if isinstance(value, list):
        if len(value) == 1:
            return _flatten_hcl_lists(value[0])
        return [_flatten_hcl_lists(v) for v in value]
    if isinstance(value, dict):
        return {k: _flatten_hcl_lists(v) for k, v in value.items()}
    return value
