"""Dockerfile security rules registry."""

from __future__ import annotations

from prithvi.dockerfile.rules.add_remote import AddRemoteUrlRule
from prithvi.dockerfile.rules.apt import AptBestPracticesRule
from prithvi.dockerfile.rules.base import BaseRule
from prithvi.dockerfile.rules.copy import NoBroadCopyRule
from prithvi.dockerfile.rules.curl_pipe import CurlPipeShellRule
from prithvi.dockerfile.rules.healthcheck import HealthcheckRule
from prithvi.dockerfile.rules.pip import PipNoCacheDirRule
from prithvi.dockerfile.rules.ports import PrivilegedPortRule
from prithvi.dockerfile.rules.secrets import NoSecretsInEnvRule
from prithvi.dockerfile.rules.sudo import SudoInRunRule
from prithvi.dockerfile.rules.tags import PinnedTagRule
from prithvi.dockerfile.rules.upgrade import AptGetUpgradeRule
from prithvi.dockerfile.rules.user import NoRootUserRule
from prithvi.dockerfile.rules.workdir import (
    MissingWorkdirRule,
    RelativeWorkdirRule,
)

_RULES: list[BaseRule] = [
    NoRootUserRule(),
    PinnedTagRule(),
    NoSecretsInEnvRule(),
    PrivilegedPortRule(),
    AptBestPracticesRule(),
    NoBroadCopyRule(),
    HealthcheckRule(),
    AddRemoteUrlRule(),
    PipNoCacheDirRule(),
    RelativeWorkdirRule(),
    CurlPipeShellRule(),
    MissingWorkdirRule(),
    SudoInRunRule(),
    AptGetUpgradeRule(),
]


def get_all_rules() -> list[BaseRule]:
    """Return all registered Dockerfile security rules."""
    return list(_RULES)


def get_rule_by_id(rule_id: str) -> BaseRule | None:
    """Look up a rule by its ID."""
    for rule in _RULES:
        if rule.rule_id == rule_id:
            return rule
    return None
