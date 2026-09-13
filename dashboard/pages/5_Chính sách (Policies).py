
import json
from pathlib import Path
import streamlit as st
from services.report_loader import load_latest_report
from services.cspm_adapter import build_model
from components.ui import inject_css, sidebar_brand
st.set_page_config(page_title="SecNet CSPM · Policies",page_icon="🛡️",layout="wide")
inject_css(); scan,path,demo=load_latest_report(); m=build_model(scan); sidebar_brand(m,demo,path)
st.markdown('<div class="sn-breadcrumb">SECNET / CHÍNH SÁCH (POLICIES)</div><div class="sn-greeting">Chính sách bảo mật</div><div class="sn-subtitle">Policy Registry, phạm vi kiểm tra và quy tắc bảo vệ remediation.</div>',unsafe_allow_html=True)
p=Path(__file__).resolve().parents[2]/"docs"/"cspm-policy-registry.json"
if p.exists(): st.json(json.loads(p.read_text(encoding="utf8")))
else: st.warning("Không tìm thấy Policy Registry.")
