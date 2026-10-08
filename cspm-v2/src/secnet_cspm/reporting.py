import csv,html
from openpyxl import Workbook
FIELDS=["scan_id","control_id","status","severity","priority","title","resource_id","region","service","summary","root_cause","recommended_remediation","auto_remediation","confidence","verification_steps"]
def _value(x,k): return " | ".join(x.get(k,[])) if k=="verification_steps" else x.get(k,"")
def write_csv(path,items):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open("w",newline="",encoding="utf-8-sig") as f:
  w=csv.writer(f); w.writerow(FIELDS)
  for x in items: w.writerow([_value(x,k) for k in FIELDS])
def write_xlsx(path,items):
 wb=Workbook(); ws=wb.active; ws.title="Findings"; ws.append(FIELDS)
 for x in items: ws.append([_value(x,k) for k in FIELDS])
 ws.freeze_panes="A2"; ws.auto_filter.ref=ws.dimensions
 path.parent.mkdir(parents=True,exist_ok=True); wb.save(path)
def write_html(path,items):
 path.parent.mkdir(parents=True,exist_ok=True)
 th="".join(f"<th>{html.escape(k)}</th>" for k in FIELDS)
 rows=["<tr>"+"".join(f"<td>{html.escape(str(_value(x,k)))}</td>" for k in FIELDS)+"</tr>" for x in items]
 doc=f"<!doctype html><html><head><meta charset='utf-8'><title>SecNet CSPM</title><style>body{{font-family:system-ui;margin:24px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:7px;vertical-align:top}}th{{background:#eee}}</style></head><body><h1>SecNet CSPM Findings</h1><table><tr>{th}</tr>{''.join(rows)}</table></body></html>"
 path.write_text(doc,encoding="utf-8")
