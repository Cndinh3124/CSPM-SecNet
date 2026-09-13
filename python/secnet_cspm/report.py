from .finding_store import save_json
from datetime import datetime, timezone

def save_report(scan):
    ts=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    scan["scan"]["timestamp"]=datetime.now(timezone.utc).isoformat()
    return save_json(f"cspm-scan-{ts}.json", scan)
