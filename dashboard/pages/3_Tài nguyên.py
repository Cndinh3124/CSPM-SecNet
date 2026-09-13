
import streamlit as st
from services.report_loader import load_latest_report
from services.cspm_adapter import build_model
from components.ui import inject_css, sidebar_brand
st.set_page_config(page_title="SecNet CSPM · Tài nguyên",page_icon="🛡️",layout="wide")
inject_css(); scan,path,demo=load_latest_report(); m=build_model(scan); sidebar_brand(m,demo,path)
st.markdown('<div class="sn-breadcrumb">SECNET / TÀI NGUYÊN</div><div class="sn-greeting">Tài nguyên Cloud</div><div class="sn-subtitle">Danh mục resource nằm trong phạm vi kiểm tra của CSPM.</div>',unsafe_allow_html=True)
a,b,c,d=st.columns(4); a.metric("Đang hoạt động",m["active_resources"]); b.metric("Đạt",m["passed_resources"]); c.metric("Lỗi",m["failed_resources"]); d.metric("Stale",m["stale_resources"])
df=m["resource_all"]
if df.empty: st.info("Report không có resource chi tiết.")
else:
    st.dataframe(df[["Control","Resource","Type","Service","Status","Risk","Reason"]],use_container_width=True,hide_index=True)
