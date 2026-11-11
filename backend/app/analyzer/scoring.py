SEVERITY_POINTS = {"Critical": 30, "High": 20, "Medium": 10, "Low": 5, "Informational": 0}


def score_findings(findings: list[dict]) -> tuple[int, str]:
    score = min(100, sum(SEVERITY_POINTS[finding["severity"]] for finding in findings))
    level = "Low" if score < 20 else "Moderate" if score < 40 else "High" if score < 70 else "Critical"
    return score, level
