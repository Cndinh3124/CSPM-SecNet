import argparse
from .pipeline import run_scan
def main():
 p=argparse.ArgumentParser(prog="cspm"); s=p.add_subparsers(dest="command",required=True)
 x=s.add_parser("scan"); x.add_argument("--region",default="ap-southeast-1"); x.add_argument("--limit",type=int,default=20)
 a=p.parse_args()
 if a.command=="scan":
  r=run_scan(a.region,a.limit); print("Scan completed:",r["scan_id"]); print("Failed findings:",r["total_failed_findings"]); print("AI analyzed:",r["ai_analyzed"])
  for k,v in r["reports"].items(): print(f"{k}: {v}")
