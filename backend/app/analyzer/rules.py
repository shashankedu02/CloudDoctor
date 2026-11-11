"""Explainable, statement-scoped IAM policy checks; this is not an IAM evaluator."""
from __future__ import annotations

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
    return {"rule_id": rule_id, "title": title, "severity": severity, "description": description,
            "explanation": description, "evidence": {"actions": matched, "resources": statement.get("Resource", statement.get("NotResource", ["Implicit or NotResource"])), "condition": statement.get("Condition")},
            "statement_index": index, "statement_sid": statement.get("Sid"), "matched_actions": matched,
            "affected_resources": statement.get("Resource", statement.get("NotResource", ["Implicit or NotResource"])),
            "recommendation": remediation, "confidence": "Heuristic" if heuristic else "Exact match", "heuristic": heuristic}


def evaluate(statements: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for index, statement in enumerate(statements):
        if statement["Effect"] != "Allow":
            continue
        actions = statement.get("Action", [])
        lower = [action.lower() for action in actions]
        broad = _broad_resources(statement)
        sid = statement.get("Sid", "this statement")
        if "*" in actions:
            findings.append(finding("IAM-001", "Full wildcard Action permission", "Critical", index, statement, ["*"], "This allow statement permits every AWS action within its effective resource scope.", "Replace * with the minimum required actions and scope resources to specific ARNs."))
        prefixes = [a for a in actions if a.endswith(":*") and a != "*"]
        if prefixes:
            findings.append(finding("IAM-008", "Wildcard action prefix", "High", index, statement, prefixes, "Service-wide wildcard actions grant all current and future actions for a service.", "List only required actions; constrain resources and add suitable conditions.", True))
        sensitive = [action for action, lowered in zip(actions, lower) if lowered in SENSITIVE or lowered == "iam:*"]
        if sensitive and broad:
            severity = "Critical" if any(a.lower() in {"iam:passrole", "iam:*"} for a in sensitive) else "High"
            findings.append(finding("IAM-002", "Sensitive IAM actions with broad resource scope", severity, index, statement, sensitive, "Sensitive IAM permission(s) are allowed with an unrestricted or negated resource scope.", "Restrict IAM actions to exact role, user, or policy ARNs and apply contextual conditions.", True))
        if any(a.lower() in {"iam:passrole", "iam:*"} for a in actions) and broad:
            findings.append(finding("IAM-003", "Broad iam:PassRole permission", "Critical", index, statement, [a for a in actions if a.lower() in {"iam:passrole", "iam:*"}], "Broad role passing can enable privilege escalation when a caller can pass a more privileged role to a service.", "Allow PassRole only for named roles and use iam:PassedToService conditions."))
        version_actions = {a.lower() for a in actions}
        if {"iam:createpolicyversion", "iam:setdefaultpolicyversion"}.issubset(version_actions) or "iam:*" in version_actions:
            findings.append(finding("IAM-004", "Dangerous policy version management", "Critical", index, statement, [a for a in actions if a.lower() in {"iam:createpolicyversion", "iam:setdefaultpolicyversion", "iam:*"}], "Creating and selecting a policy version can make newly created permissions effective; impact depends on policy scope.", "Separate version management duties and restrict policy ARNs.", True))
        modifications = [a for a in actions if a.lower() in {"iam:attachrolepolicy", "iam:putrolepolicy", "iam:*"}]
        if modifications and broad:
            findings.append(finding("IAM-005", "Broad role policy modification", "High", index, statement, modifications, "This statement can modify role policies broadly, which can change role privileges.", "Limit modifications to approved role/policy ARNs and separate administrative duties.", True))
        keys = [a for a in actions if a.lower() in {"iam:createaccesskey", "iam:*"}]
        if keys and broad:
            findings.append(finding("IAM-006", "Broad access key creation", "High", index, statement, keys, "This statement can create long-lived access keys for broadly scoped principals.", "Restrict to named users where unavoidable; prefer temporary credentials.", True))
        if sensitive and not _restrictive_condition(statement):
            findings.append(finding("IAM-007", "Sensitive actions without restrictive conditions", "Medium", index, statement, sensitive, "Sensitive IAM actions have no recognised network, principal, organisation, or region restriction. This is a heuristic, not a full condition evaluation.", "Add applicable least-privilege conditions and validate the effective policy in AWS IAM Access Analyzer.", True))
        if "NotAction" in statement or "NotResource" in statement:
            findings.append(finding("IAM-009", "Allow statement uses NotAction or NotResource", "Medium", index, statement, statement.get("NotAction", []) + statement.get("NotResource", []), "Negated allow constructs can create unintuitive effective permissions and are not fully evaluated by this tool.", "Prefer explicit Action and Resource lists where practical.", True))
        unsupported = statement.get("_unsupported_keys", [])
        if unsupported or "Principal" in statement or "NotPrincipal" in statement:
            items = unsupported + [key for key in ("Principal", "NotPrincipal") if key in statement]
            findings.append(finding("IAM-010", "Unsupported policy construct", "Informational", index, statement, items, f"CloudSentinel cannot confidently evaluate: {', '.join(items)}.", "Review this construct manually with AWS IAM policy simulation tools.", True))
    return findings
