
import glob,json
from pathlib import Path
import streamlit as st
from services.report_loader import load_latest_report
from services.cspm_adapter import build_model
from components.ui import inject_css, sidebar_brand
st.set_page_config(page_title="SecNet CSPM · Remediation",page_icon="🛡️",layout="wide")
inject_css(); scan,path,demo=load_latest_report(); m=build_model(scan); sidebar_brand(m,demo,path)
st.markdown('<div class="sn-breadcrumb">SECNET / KHẮC PHỤC (REMEDIATION)</div><div class="sn-greeting">Remediation</div><div class="sn-subtitle">Theo dõi kế hoạch và bằng chứng thực thi. Dashboard ở chế độ read-only.</div>',unsafe_allow_html=True)
root=Path(__file__).resolve().parents[2]; out=root/"tests"/"outputs"
plans=sorted(glob.glob(str(out/"cspm-remediation-plan*.json")),key=lambda x:Path(x).stat().st_mtime,reverse=True)
logs=sorted(glob.glob(str(out/"cspm-execution-log*.json")),key=lambda x:Path(x).stat().st_mtime,reverse=True)
a,b,c=st.columns(3); a.metric("Finding cần xử lý",m["failed_resources"]); b.metric("Remediation plans",len(plans)); c.metric("Execution logs",len(logs))
if plans: st.markdown('<div class="sn-card-title">Kế hoạch gần nhất</div>',unsafe_allow_html=True); st.json(json.loads(Path(plans[0]).read_text(encoding="utf8")))
else: st.info("Chưa tìm thấy Remediation Plan JSON.")
if logs: st.markdown('<div class="sn-card-title">Execution log gần nhất</div>',unsafe_allow_html=True); st.json(json.loads(Path(logs[0]).read_text(encoding="utf8")))
else: st.info("Chưa tìm thấy Execution Log JSON.")
