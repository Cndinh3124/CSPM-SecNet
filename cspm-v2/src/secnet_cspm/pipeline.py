from . import prowler,parser,gemini,reporting,storage
from .risk import priority
def run_scan(region,limit=20):
 sid=storage.new_scan_id(); root=storage.scan_dir(sid); out=root/"prowler"
 prowler.run(region,out)
 findings=parser.parse_directory(out,sid,region)
 normalized=[]
 for f in findings: f["priority"]=priority(f); normalized.append(f)
 storage.write_json(root/"normalized/findings.json",normalized)
 analyzed=[]
 for f in normalized[:limit]:
  try: f.update(gemini.analyze(f)); f["ai_status"]="OK"
  except Exception as e: f["ai_status"]="ERROR"; f["ai_error"]=str(e)
  analyzed.append(f)
 storage.write_json(root/"ai/analysis.json",analyzed)
 rd=storage.REPORT_ROOT/sid
 reporting.write_csv(rd/"findings.csv",analyzed); reporting.write_xlsx(rd/"findings.xlsx",analyzed); reporting.write_html(rd/"report.html",analyzed)
 result={"scan_id":sid,"region":region,"total_failed_findings":len(normalized),"ai_analyzed":len(analyzed),"reports":{"csv":str(rd/"findings.csv"),"xlsx":str(rd/"findings.xlsx"),"html":str(rd/"report.html"),"json":str(root/"ai/analysis.json")}}
 storage.write_json(root/"metadata.json",result); return result
