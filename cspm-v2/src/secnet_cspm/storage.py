import json
from pathlib import Path
from datetime import datetime, timezone
ROOT=Path(__file__).resolve().parents[2]
DATA_ROOT=ROOT/"data/scans"
REPORT_ROOT=ROOT/"reports"
def new_scan_id(): return datetime.now(timezone.utc).strftime("scan-%Y%m%d-%H%M%S")
def scan_dir(scan_id):
 p=DATA_ROOT/scan_id
 for n in ("prowler", "normalized", "ai", "remediation"): (p/n).mkdir(parents=True,exist_ok=True)
 (REPORT_ROOT/scan_id).mkdir(parents=True,exist_ok=True)
 return p
def write_json(path,value):
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(value,indent=2,ensure_ascii=False,default=str),encoding="utf-8")
