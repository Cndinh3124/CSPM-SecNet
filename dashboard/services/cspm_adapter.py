
import pandas as pd
from datetime import datetime, timezone

def items(v):
    if v is None: return []
    if isinstance(v,list): return v
    if isinstance(v,dict):
        for k in ("items","resources","findings"):
            if isinstance(v.get(k),list): return v[k]
        if "count" in v:
            try:return list(range(int(v["count"])))
            except:return []
        return list(v.values())
    if isinstance(v,(int,float)): return list(range(int(v)))
    return []

def rid(r):
    if isinstance(r,str): return r
    if isinstance(r,dict):
        return r.get("resource_id") or r.get("id") or r.get("resource") or r.get("arn") or "UNKNOWN"
    return str(r)

def rtype(r):
    if not isinstance(r,dict): return ""
    return r.get("resource_type") or r.get("type") or r.get("resourceType") or ""

def reason(r):
    if not isinstance(r,dict): return ""
    return r.get("reason") or r.get("description") or r.get("message") or r.get("finding") or ""

def raw_config(r):
    if not isinstance(r,dict): return r
    for k in ("configuration","config","configuration_json","details","resource_details"):
        if k in r:return r[k]
    return {k:v for k,v in r.items() if k not in {"resource_id","id","resource","arn","resource_type","type","reason","description","message"}}

def risk(control, r):
    if isinstance(r,dict):
        x=str(r.get("severity") or r.get("risk") or r.get("risk_level") or "").lower()
        if "critical" in x:return "Critical"
        if "high" in x or "cao" in x:return "Cao"
        if "medium" in x or "trung" in x:return "Trung bình"
        if "low" in x or "thấp" in x:return "Thấp"
    if str(control).startswith(("EC2.6","EC2.53")): return "Cao"
    return "Trung bình"

def service_group(resource_type, control):
    s=(resource_type or control or "").lower()
    if "ec2" in s or "securitygroup" in s or "vpc" in s:return "EC2"
    if "s3" in s or str(control).upper().startswith("S3"):return "S3"
    if "iam" in s or str(control).upper().startswith("IAM"):return "IAM"
    if "rds" in s or str(control).upper().startswith("RDS"):return "RDS"
    if "cloudtrail" in s or str(control).lower().startswith("cloudtrail"):return "CloudTrail"
    return "Other"

def build_model(scan):
    controls=[]; resources=[]; all_resources=[]
    for c in scan.get("controls",[]) or []:
        cid=c.get("control_id") or c.get("id") or c.get("control") or "UNKNOWN"
        status=str(c.get("status") or c.get("compliance") or "UNKNOWN").upper()
        passed=items(c.get("passed",c.get("passed_resources")))
        failed=items(c.get("failed",c.get("failed_resources")))
        unknown=items(c.get("unknown",c.get("unknown_resources")))
        p,f,u=len(passed),len(failed),len(unknown); total=p+f+u
        pct=p/total*100 if total else (100 if status=="PASSED" else 0)
        controls.append({"Control":cid,"Status":status,"Passed":p,"Failed":f,"Unknown":u,"Compliance":pct})
        for r in passed:
            all_resources.append({"Control":cid,"Resource":rid(r),"Type":rtype(r),"Status":"PASSED","Risk":"-","Reason":"","Service":service_group(rtype(r),cid),"Config":raw_config(r)})
        for r in failed:
            all_resources.append({"Control":cid,"Resource":rid(r),"Type":rtype(r),"Status":"FAILED","Risk":risk(cid,r),"Reason":reason(r),"Service":service_group(rtype(r),cid),"Config":raw_config(r)})
            resources.append(all_resources[-1])
        for r in unknown:
            all_resources.append({"Control":cid,"Resource":rid(r),"Type":rtype(r),"Status":"UNKNOWN","Risk":"-","Reason":reason(r),"Service":service_group(rtype(r),cid),"Config":raw_config(r)})
    cdf=pd.DataFrame(controls,columns=["Control","Status","Passed","Failed","Unknown","Compliance"])
    rdf=pd.DataFrame(resources,columns=["Control","Resource","Type","Status","Risk","Reason","Service","Config"])
    rs=scan.get("resource_summary",{}) or {}
    def n(x,d=0):
        try:return int(x)
        except:return d
    active=n(rs.get("active",rs.get("active_resources",len(all_resources))))
    # The scan's resource summary is authoritative when present.
    passed_r=n(rs.get("passed",rs.get("passed_resources",0)))
    failed_r=n(rs.get("failed",rs.get("failed_resources",len(resources))))
    stale_r=n(rs.get("stale",rs.get("stale_resources",0)))
    unknown_r=n(rs.get("unknown",rs.get("unknown_resources",0)))
    return {
        "scan":scan,"controls":cdf,"resources":pd.DataFrame(all_resources),
        "failed_table":rdf[rdf.Status=="FAILED"].copy(),
        "control_total":len(cdf),
        "passed_controls":int((cdf.Status=="PASSED").sum()) if not cdf.empty else 0,
        "failed_controls":int((cdf.Status=="FAILED").sum()) if not cdf.empty else 0,
        "unknown_controls":int((~cdf.Status.isin(["PASSED","FAILED"])).sum()) if not cdf.empty else 0,
        "compliance":((cdf.Status=="PASSED").sum()/len(cdf)*100) if len(cdf) else 0,
        "active_resources":active,"passed_resources":passed_r,"failed_resources":failed_r,
        "stale_resources":stale_r,"unknown_resources":unknown_r,
        "region":scan.get("region","ap-southeast-1"),"engine":scan.get("engine","CSPM Engine v3.1"),
        "generated_at":scan.get("generated_at") or scan.get("timestamp") or "",
        "resource_all":pd.DataFrame(all_resources)
    }
