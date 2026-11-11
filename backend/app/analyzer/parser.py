"""Strict, non-evaluating parser for IAM policy JSON documents."""
from __future__ import annotations

import json
from typing import Any

SUPPORTED_KEYS = {"Sid", "Effect", "Action", "NotAction", "Resource", "NotResource", "Condition", "Principal", "NotPrincipal"}


class PolicyValidationError(ValueError):
    pass


def _string_or_list(value: Any, field: str, index: int) -> list[str]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        values = value
    else:
        raise PolicyValidationError(f"Statement {index}: {field} must be a string or an array of strings.")
    if not values or any(not item.strip() for item in values):
        raise PolicyValidationError(f"Statement {index}: {field} cannot be empty.")
    return values


def parse_policy(policy: dict[str, Any] | str) -> dict[str, Any]:
    """Normalize and validate an IAM policy; it never interprets or executes input."""
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError as exc:
            raise PolicyValidationError(f"Invalid JSON: {exc.msg}.") from exc
    if not isinstance(policy, dict) or not policy:
        raise PolicyValidationError("Policy must be a non-empty JSON object.")
    statements = policy.get("Statement")
    if statements is None:
        raise PolicyValidationError("Policy requires a Statement field.")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        raise PolicyValidationError("Statement must be a non-empty object or array.")
    normalized: list[dict[str, Any]] = []
    for index, statement in enumerate(statements):
        if not isinstance(statement, dict):
            raise PolicyValidationError(f"Statement {index} must be an object.")
        effect = statement.get("Effect")
        if effect not in {"Allow", "Deny"}:
            raise PolicyValidationError(f"Statement {index}: Effect must be Allow or Deny.")
        if "Action" not in statement and "NotAction" not in statement:
            raise PolicyValidationError(f"Statement {index}: requires Action or NotAction.")
        if "Action" in statement and "NotAction" in statement:
            raise PolicyValidationError(f"Statement {index}: cannot contain both Action and NotAction.")
        if "Resource" in statement and "NotResource" in statement:
            raise PolicyValidationError(f"Statement {index}: cannot contain both Resource and NotResource.")
        result = dict(statement)
        for field in ("Action", "NotAction", "Resource", "NotResource"):
            if field in statement:
                result[field] = _string_or_list(statement[field], field, index)
        if "Sid" in statement and not isinstance(statement["Sid"], str):
            raise PolicyValidationError(f"Statement {index}: Sid must be a string.")
        if "Condition" in statement and not isinstance(statement["Condition"], dict):
            raise PolicyValidationError(f"Statement {index}: Condition must be an object.")
        result["_unsupported_keys"] = sorted(set(statement) - SUPPORTED_KEYS)
        normalized.append(result)
    return {"Version": policy.get("Version"), "Statement": normalized}
