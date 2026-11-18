import pytest

from app.analyzer.engine import analyze_policy
from app.analyzer.parser import PolicyValidationError


def policy(actions, resource="*"):
    return {"Statement": {"Effect":"Allow", "Action": actions, "Resource": resource}}

@pytest.mark.parametrize(("actions", "rule"), [
    ("*", "IAM-001"), ("iam:PassRole", "IAM-003"), (["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"], "IAM-004"),
    (["iam:AttachRolePolicy", "iam:PutRolePolicy"], "IAM-005"), ("iam:CreateAccessKey", "IAM-006"), ("s3:*", "IAM-008")])
def test_rules(actions, rule):
    assert rule in analyze_policy(policy(actions))["rules_triggered"]

def test_sensitive_without_condition_and_not_action():
    result = analyze_policy({"Statement":{"Effect":"Allow","NotAction":"iam:DeleteUser","NotResource":"arn:aws:iam::1:user/admin"}})
    assert "IAM-009" in result["rules_triggered"]

def test_deny_is_not_vulnerability():
    result = analyze_policy({"Statement":{"Effect":"Deny", "Action":"*", "Resource":"*"}})
    assert result["findings"] == []

def test_safe_policy_no_critical():
    result = analyze_policy(policy("s3:GetObject", "arn:aws:s3:::bucket/*"))
    assert result["risk_level"] == "Low" and not result["findings"]

@pytest.mark.parametrize("bad", [{}, {"Statement":{}}, {"Statement":{"Effect":"Maybe","Action":"x"}}, {"Statement":{"Effect":"Allow","Action":3}}])
def test_invalid_policies(bad):
    with pytest.raises(PolicyValidationError): analyze_policy(bad)


@pytest.mark.parametrize("action", ["iam:Pass*", "iam:*Role*", "IAM:PASSROLE", "iam:PassRol?", "iam:*", "*", "*:*"])
def test_wildcards_that_grant_passrole_are_detected(action):
    assert "IAM-003" in analyze_policy(policy(action))["rules_triggered"]


@pytest.mark.parametrize("action", ["*", "*:*"])
def test_full_admin_policy_is_critical(action):
    result = analyze_policy(policy(action))
    assert result["risk_level"] == "Critical"
    assert "IAM-001" in result["rules_triggered"]


def test_version_wildcard_covers_both_version_actions():
    assert "IAM-004" in analyze_policy(policy("iam:*PolicyVersion"))["rules_triggered"]


@pytest.mark.parametrize("action", ["ec2:Describe*", "s3:Get*", "iam:Get*", "iam:List*"])
def test_read_only_wildcards_are_not_flagged_as_sensitive(action):
    assert analyze_policy(policy(action))["findings"] == []


def test_wildcard_characters_are_not_regex():
    # "[" and "." have no special meaning in IAM action patterns.
    assert analyze_policy(policy("iam:[Pp]assRole"))["findings"] == []
    assert analyze_policy(policy("iam:Pass.ole"))["findings"] == []


def test_passrole_scoped_to_named_role_is_not_broad():
    rules = analyze_policy(policy("iam:PassRole", "arn:aws:iam::123456789012:role/AppRole"))["rules_triggered"]
    assert "IAM-003" not in rules and "IAM-002" not in rules
    assert "IAM-007" in rules


def test_restrictive_condition_suppresses_iam_007():
    statement = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*", "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}}
    assert "IAM-007" not in analyze_policy({"Statement": statement})["rules_triggered"]


def test_principal_is_reported_as_unsupported():
    statement = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}
    finding = analyze_policy({"Statement": statement})["findings"][0]
    assert finding["rule_id"] == "IAM-010" and "CloudDoctor" in finding["description"]


def test_score_is_capped_at_100():
    statements = [{"Effect": "Allow", "Action": "*", "Resource": "*"}, {"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]
    assert analyze_policy({"Statement": statements})["risk_score"] == 100
