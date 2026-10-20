"""Rule package: importing the modules registers every rule."""

from __future__ import annotations

from claude_sentinel.rules import account, behavior, client, identity, network, stability
from claude_sentinel.rules.registry import RuleMeta, RuleResult, all_rules, evaluate, rule

__all__ = [
    "RuleMeta",
    "RuleResult",
    "all_rules",
    "evaluate",
    "rule",
    "account",
    "behavior",
    "client",
    "identity",
    "network",
    "stability",
]
