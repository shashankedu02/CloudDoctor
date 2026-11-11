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
