import csv,json
def _get(x,*keys,default=""):
 for k in keys:
  if k in x and x[k] not in (None,""): return x[k]
 return default
def parse_file(path,scan_id,region):
 if path.suffix.lower()==".json":
  data=json.loads(path.read_text(encoding="utf-8"))
  if isinstance(data,dict): data=data.get("findings") or data.get("data") or data.get("results") or [data]
 elif path.suffix.lower()==".csv":
  with path.open(newline="",encoding="utf-8-sig") as f: data=list(csv.DictReader(f))
 else: return []
 if not isinstance(data,list): return []
 out=[]
 for x in data:
  if not isinstance(x,dict) or str(_get(x,"status","Status","status_code")).upper() not in ("FAIL","FAILED"): continue
  out.append({"scan_id":scan_id,"control_id":str(_get(x,"check_id","CheckID","control_id","control")),"status":"FAIL","severity":str(_get(x,"severity","Severity",default="UNKNOWN")).upper(),"title":str(_get(x,"finding_info","title","FindingTitle","check_title")),"resource_id":str(_get(x,"resource_id","ResourceId","resource_uid")),"region":str(_get(x,"region","Region",default=region)),"service":str(_get(x,"service_name","ServiceName","service")),"description":str(_get(x,"description","Description")),"raw":x})
 return out
def parse_directory(directory,scan_id,region):
 out=[]
 for p in directory.rglob("*"):
  if p.suffix.lower() in (".json",".csv"):
   try: out.extend(parse_file(p,scan_id,region))
   except (json.JSONDecodeError,UnicodeDecodeError): pass
 return out
