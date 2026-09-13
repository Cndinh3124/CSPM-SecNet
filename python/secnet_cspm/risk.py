from datetime import datetime, timezone

SEVERITY_WEIGHT = {"CRITICAL": 100, "HIGH": 80, "MEDIUM": 55, "LOW": 25, "INFO": 5}

def risk_score(severity, resource_public=False, age_hours=0):
    base = SEVERITY_WEIGHT.get(str(severity).upper(), 25)
    exposure = 10 if resource_public else 0
    age = min(15, max(0, int(age_hours // 24)) * 2)
    return min(100, base + exposure + age)

def risk_level(score):
    if score >= 90: return "CRITICAL"
    if score >= 70: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"

def enrich_finding(finding):
    score = risk_score(finding.get("severity","MEDIUM"), finding.get("public_exposure", False), finding.get("age_hours", 0))
    out = dict(finding)
    out["risk_score"] = score
    out["risk_level"] = risk_level(score)
    return out
