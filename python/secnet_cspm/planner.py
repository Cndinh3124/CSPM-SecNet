from .config import load_registry
from .scope import ScopeValidator

def build_plan(scan, region="ap-southeast-1"):
    registry = load_registry()
    validator = ScopeValidator(registry, region)
    items = []
    for f in scan.get("findings", []):
        if f.get("status") != "FAILED":
            continue
        decision = validator.validate(f.get("resource"), f.get("resource_type"))
        control = next((c for c in registry.get("controls", []) if c["id"] == f.get("control")), {})
        items.append({
            "control": f.get("control"),
            "resource": f.get("resource"),
            "resource_type": f.get("resource_type"),
            "severity": f.get("severity"),
            "risk_level": f.get("risk_level"),
            "risk_score": f.get("risk_score"),
            "action": control.get("remediation"),
            "allowed": decision.allowed,
            "reason": decision.reason,
            "tags": decision.tags,
        })
    return {
        "version": "2",
        "region": region,
        "items": items,
        "allowed": sum(1 for x in items if x["allowed"]),
        "skipped": sum(1 for x in items if not x["allowed"]),
    }
