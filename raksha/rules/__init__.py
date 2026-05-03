"""Rule packs — generic, dpdpa, rbi."""
from __future__ import annotations

from raksha.rules.base import Rule
from raksha.rules.dpdpa import DPDPA_RULES
from raksha.rules.generic import GENERIC_RULES
from raksha.rules.rbi import RBI_RULES

PACKS: dict[str, list[type[Rule]]] = {
    "generic": GENERIC_RULES,
    "dpdpa": DPDPA_RULES,
    "rbi": RBI_RULES,
}


def load_rules(pack_names: list[str]) -> list[Rule]:
    """Instantiate all rules for the given pack names."""
    rules: list[Rule] = []
    for pack in pack_names:
        if pack not in PACKS:
            raise ValueError(
                f"Unknown rule pack '{pack}'. Available: {list(PACKS.keys())}"
            )
        rules.extend(rule_cls() for rule_cls in PACKS[pack])
    return rules


__all__ = ["PACKS", "Rule", "load_rules"]
