SCORES={"CRITICAL":100,"HIGH":75,"MEDIUM":50,"LOW":25,"INFO":10,"UNKNOWN":0}
def score(f):
 base=SCORES.get(str(f.get("severity","UNKNOWN")).upper(),0)
 title=str(f.get("title","")).lower()
 return min(base+(15 if any(x in title for x in ("public","internet","unrestricted")) else 0),100)
def priority(f):
 s=score(f)
 return "P1" if s>=90 else "P2" if s>=70 else "P3" if s>=40 else "P4"
