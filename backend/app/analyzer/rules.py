"""Explainable, statement-scoped IAM policy checks; this is not an IAM evaluator."""

from __future__ import annotations

import re
from typing import Any

SENSITIVE = {"iam:attachrolepolicy", "iam:putrolepolicy", "iam:createpolicyversion", "iam:setdefaultpolicyversion", "iam:createaccesskey", "iam:passrole"}
RESTRICTIVE_CONDITION_KEYS = {"aws:sourcevpce", "aws:sourceip", "aws:principalarn", "aws:userid", "aws:principalorgid", "aws:requestedregion"}

RULES = [
    ("IAM-001", "Full wildcard Action permission", "Critical"),
    ("IAM-002", "Sensitive IAM actions with broad resource scope", "High"),
    ("IAM-003", "Broad iam:PassRole permission", "Critical"),
    ("IAM-004", "Dangerous policy version management", "Critical"),
    ("IAM-005", "Broad role policy modification", "High"),
    ("IAM-006", "Broad access key creation", "High"),
    ("IAM-007", "Sensitive actions without restrictive conditions", "Medium"),
    ("IAM-008", "Wildcard action prefix", "High"),
    ("IAM-009", "Allow statement uses NotAction or NotResource", "Medium"),
    ("IAM-010", "Unsupported policy construct", "Informational"),
]


def _broad_resources(statement: dict[str, Any]) -> bool:
    return "NotResource" in statement or "Resource" not in statement or any(resource == "*" for resource in statement.get("Resource", []))


def _restrictive_condition(statement: dict[str, Any]) -> bool:
    condition = statement.get("Condition", {})
    return any(key.lower() in RESTRICTIVE_CONDITION_KEYS for values in condition.values() if isinstance(values, dict) for key in values)


def finding(rule_id: str, title: str, severity: str, index: int, statement: dict[str, Any], matched: list[str], description: str, remediation: str, heuristic: bool = False) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "description": description,
        "explanation": description,
        "evidence": {"actions": matched, "resources": statement.get("Resource", statement.get("NotResource", ["Implicit or NotResource"])), "condition": statement.get("Condition")},
        "statement_index": index,
        "statement_sid": statement.get("Sid"),
        "matched_actions": matched,
        "affected_resources": statement.get("Resource", statement.get("NotResource", ["Implicit or NotResource"])),
        "recommendation": remediation,
        "confidence": "Heuristic" if heuristic else "Exact match",
        "heuristic": heuristic,
    }


def _pattern(action: str) -> re.Pattern[str]:
    """Compile an IAM action pattern: case-insensitive, `*` = any run of characters, `?` = one character."""
    escaped = re.escape(action.lower()).replace(r"\*", ".*").replace(r"\?", ".")
    return re.compile(rf"^{escaped}$")


def _covering(actions: list[str], targets: set[str]) -> list[str]:
    """Return the granted action patterns that grant at least one of the target actions.

    `iam:Pass*`, `iam:*`, `*` and `iam:passrole` all cover `iam:PassRole`, matching how IAM evaluates
    wildcards in the Action element.
    """
    return [action for action in actions if any(_pattern(action).match(target) for target in targets)]


def _is_full_wildcard(action: str) -> bool:
    return action.strip() in {"*", "*:*"}


def evaluate(statements: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for index, statement in enumerate(statements):
        if statement["Effect"] != "Allow":
            continue
        actions = statement.get("Action", [])
        broad = _broad_resources(statement)
        full = [a for a in actions if _is_full_wildcard(a)]
        if full:
            findings.append(
                finding(
                    "IAM-001",
                    "Full wildcard Action permission",
                    "Critical",
                    index,
                    statement,
                    full,
                    "This allow statement permits every AWS action within its effective resource scope.",
                    "Replace * with the minimum required actions and scope resources to specific ARNs.",
                )
            )
        prefixes = [a for a in actions if a.endswith(":*") and not _is_full_wildcard(a)]
        if prefixes:
            findings.append(
                finding(
                    "IAM-008",
                    "Wildcard action prefix",
                    "High",
                    index,
                    statement,
                    prefixes,
                    "Service-wide wildcard actions grant all current and future actions for a service.",
                    "List only required actions; constrain resources and add suitable conditions.",
                    True,
                )
            )
        sensitive = _covering(actions, SENSITIVE)
        passrole = _covering(actions, {"iam:passrole"})
        if sensitive and broad:
            severity = "Critical" if passrole else "High"
            findings.append(
                finding(
                    "IAM-002",
                    "Sensitive IAM actions with broad resource scope",
                    severity,
                    index,
                    statement,
                    sensitive,
                    "Sensitive IAM permission(s) are allowed with an unrestricted or negated resource scope.",
                    "Restrict IAM actions to exact role, user, or policy ARNs and apply contextual conditions.",
                    True,
                )
            )
        if passrole and broad:
            findings.append(
                finding(
                    "IAM-003",
                    "Broad iam:PassRole permission",
                    "Critical",
                    index,
                    statement,
                    passrole,
                    "Broad role passing can enable privilege escalation when a caller can pass a more privileged role to a service.",
                    "Allow PassRole only for named roles and use iam:PassedToService conditions.",
                )
            )
        create_version = _covering(actions, {"iam:createpolicyversion"})
        set_default = _covering(actions, {"iam:setdefaultpolicyversion"})
        if create_version and set_default:
            matched = list(dict.fromkeys(create_version + set_default))
            findings.append(
                finding(
                    "IAM-004",
                    "Dangerous policy version management",
                    "Critical",
                    index,
                    statement,
                    matched,
                    "Creating and selecting a policy version can make newly created permissions effective; impact depends on policy scope.",
                    "Separate version management duties and restrict policy ARNs.",
                    True,
                )
            )
        modifications = _covering(actions, {"iam:attachrolepolicy", "iam:putrolepolicy"})
        if modifications and broad:
            findings.append(
                finding(
                    "IAM-005",
                    "Broad role policy modification",
                    "High",
                    index,
                    statement,
                    modifications,
                    "This statement can modify role policies broadly, which can change role privileges.",
                    "Limit modifications to approved role/policy ARNs and separate administrative duties.",
                    True,
                )
            )
        keys = _covering(actions, {"iam:createaccesskey"})
        if keys and broad:
            findings.append(
                finding(
                    "IAM-006",
                    "Broad access key creation",
                    "High",
                    index,
                    statement,
                    keys,
                    "This statement can create long-lived access keys for broadly scoped principals.",
                    "Restrict to named users where unavoidable; prefer temporary credentials.",
                    True,
                )
            )
        if sensitive and not _restrictive_condition(statement):
            findings.append(
                finding(
                    "IAM-007",
                    "Sensitive actions without restrictive conditions",
                    "Medium",
                    index,
                    statement,
                    sensitive,
                    "Sensitive IAM actions have no recognised network, principal, organisation, or region restriction. This is a heuristic, not a full condition evaluation.",
                    "Add applicable least-privilege conditions and validate the effective policy in AWS IAM Access Analyzer.",
                    True,
                )
            )
        if "NotAction" in statement or "NotResource" in statement:
            findings.append(
                finding(
                    "IAM-009",
                    "Allow statement uses NotAction or NotResource",
                    "Medium",
                    index,
                    statement,
                    statement.get("NotAction", []) + statement.get("NotResource", []),
                    "Negated allow constructs can create unintuitive effective permissions and are not fully evaluated by this tool.",
                    "Prefer explicit Action and Resource lists where practical.",
                    True,
                )
            )
        unsupported = statement.get("_unsupported_keys", [])
        if unsupported or "Principal" in statement or "NotPrincipal" in statement:
            items = unsupported + [key for key in ("Principal", "NotPrincipal") if key in statement]
            findings.append(
                finding(
                    "IAM-010",
                    "Unsupported policy construct",
                    "Informational",
                    index,
                    statement,
                    items,
                    f"CloudDoctor cannot confidently evaluate: {', '.join(items)}.",
                    "Review this construct manually with AWS IAM policy simulation tools.",
                    True,
                )
            )
    return findings
