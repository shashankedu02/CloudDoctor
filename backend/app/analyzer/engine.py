from collections import Counter
from .parser import parse_policy
from .rules import evaluate
from .scoring import score_findings


def analyze_policy(policy: dict | str) -> dict:
    parsed = parse_policy(policy)
    findings = evaluate(parsed["Statement"])
    score, level = score_findings(findings)
    counts = dict(Counter(f["severity"] for f in findings))
    return {"parsed_policy": parsed, "risk_score": score, "risk_level": level, "summary": {"total_findings": len(findings), "severity_counts": counts, "risk_explanation": "Deterministic heuristic priority score; it is not AWS-certified and does not prove exploitability."}, "findings": findings, "analysed_statement_count": len(parsed["Statement"]), "rules_triggered": sorted({f["rule_id"] for f in findings})}
