import csv
import html

from openpyxl import Workbook


FIELDS = [
    "scan_id", "finding_uid", "fingerprint", "control_id", "status", "severity",
    "priority", "title", "account_id", "region", "service", "resource_id",
    "resource_type", "resource_arn", "description", "message", "risk_details",
    "remediation", "summary", "root_cause", "recommended_remediation",
    "auto_remediation", "confidence", "ai_status", "verification_steps",
]


def _value(item, key):
    value = item.get(key, "")
    if isinstance(value, (list, tuple)):
        return " | ".join(str(part) for part in value)
    if isinstance(value, dict):
        return str(value)
    return value


def write_csv(path, items):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(FIELDS)
        for item in items:
            writer.writerow([_value(item, key) for key in FIELDS])


def write_xlsx(path, items):
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Findings"
    sheet.append(FIELDS)
    for item in items:
        sheet.append([_value(item, key) for key in FIELDS])
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = sheet.dimensions
    path.parent.mkdir(parents=True, exist_ok=True)
    workbook.save(path)


def write_html(path, items):
    path.parent.mkdir(parents=True, exist_ok=True)
    headers = "".join(f"<th>{html.escape(key)}</th>" for key in FIELDS)
    rows = [
        "<tr>" + "".join(
            f"<td>{html.escape(str(_value(item, key)))}</td>" for key in FIELDS
        ) + "</tr>"
        for item in items
    ]
    document = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>SecNet CSPM</title>"
        "<style>body{font-family:system-ui;margin:24px}"
        "table{border-collapse:collapse;width:100%}"
        "td,th{border:1px solid #ddd;padding:7px;vertical-align:top}"
        "th{background:#eee}</style></head><body>"
        "<h1>SecNet CSPM Findings</h1><table><tr>"
        f"{headers}</tr>{''.join(rows)}</table></body></html>"
    )
    path.write_text(document, encoding="utf-8")
