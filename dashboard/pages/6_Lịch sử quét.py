
import pandas as pd
import streamlit as st
from services.report_loader import load_latest_report,load_history
from services.cspm_adapter import build_model
from components.ui import inject_css, sidebar_brand
st.set_page_config(page_title="SecNet CSPM · Lịch sử quét",page_icon="🛡️",layout="wide")
inject_css(); scan,path,demo=load_latest_report(); m=build_model(scan); sidebar_brand(m,demo,path)
st.markdown('<div class="sn-breadcrumb">SECNET / LỊCH SỬ QUÉT</div><div class="sn-greeting">Lịch sử Scan</div><div class="sn-subtitle">Theo dõi xu hướng Compliance qua các lần quét do CSPM Engine tạo.</div>',unsafe_allow_html=True)
rows=[]
for p,s in load_history():
    x=build_model(s); rows.append({"Report":p.split("\\")[-1].split("/")[-1],"Generated":s.get("generated_at") or s.get("timestamp",""),"Compliance":x["compliance"],"Controls đạt":x["passed_controls"],"Controls lỗi":x["failed_controls"],"Resource rủi ro":x["failed_resources"]})
if rows:
    df=pd.DataFrame(rows); st.dataframe(df,use_container_width=True,hide_index=True,column_config={"Compliance":st.column_config.ProgressColumn("Compliance",min_value=0,max_value=100,format="%.1f%%")})
else: st.info("Chưa có lịch sử Scan.")
