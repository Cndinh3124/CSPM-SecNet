
import json
import streamlit as st
from services.report_loader import load_latest_report
from services.cspm_adapter import build_model
from components.ui import inject_css, sidebar_brand

st.set_page_config(page_title="SecNet CSPM · Sự cố",page_icon="🛡️",layout="wide")
inject_css(); scan,path,demo=load_latest_report(); m=build_model(scan); sidebar_brand(m,demo,path)

st.markdown('<div class="sn-breadcrumb">SECNET / DANH SÁCH SỰ CỐ</div><div class="sn-greeting">Danh sách sự cố bảo mật</div><div class="sn-subtitle">Tập trung các Finding cần ưu tiên xử lý và cung cấp bằng chứng cấu hình.</div>',unsafe_allow_html=True)
a,b,c=st.columns(3)
a.metric("Finding đang mở",len(m["failed_table"])); b.metric("Control bị ảnh hưởng",m["failed_table"]["Control"].nunique() if not m["failed_table"].empty else 0); c.metric("Tài nguyên rủi ro",m["failed_resources"])
ft=m["failed_table"].copy()
if ft.empty:
    st.success("Không phát hiện Resource FAILED.")
else:
    left,right=st.columns([1.55,.9])
    with left:
        display=ft[["Control","Resource","Type","Risk","Status"]].copy()
        display.columns=["Control","Tài nguyên","Loại","Mức độ rủi ro","Trạng thái"]
        event=st.dataframe(display,use_container_width=True,hide_index=True,height=520,on_select="rerun",selection_mode="single-row",key="findings_v4")
        rows=event.selection.rows if hasattr(event,"selection") else []
        idx=rows[0] if rows else 0
    with right:
        row=ft.iloc[idx]; cfg=row.get("Config") or {}
        if not isinstance(cfg,dict): cfg={"value":cfg}
        st.markdown(f'<div class="sn-detail"><div class="sn-detail-head"><span class="sn-pill sn-failed">FAILED</span> <span class="sn-pill {"sn-high" if row["Risk"]=="Cao" else "sn-medium"}">{row["Risk"]}</span><div class="sn-detail-title" style="margin-top:10px">{row["Control"]} · {row["Resource"]}</div><div class="sn-detail-desc">{row["Reason"] or "Không có mô tả trong report."}</div></div><div class="sn-detail-body"><div class="sn-row"><div class="sn-label">Control</div><div class="sn-val">{row["Control"]}</div></div><div class="sn-row"><div class="sn-label">Resource</div><div class="sn-val">{row["Resource"]}</div></div><div class="sn-row"><div class="sn-label">Type</div><div class="sn-val">{row["Type"] or "Unknown"}</div></div><div class="sn-row"><div class="sn-label">Nguồn</div><div class="sn-val">CSPM Engine / Security Hub</div></div><div class="sn-rem-title">Cấu hình hiện tại (JSON)</div><div class="sn-code">{json.dumps(cfg,ensure_ascii=False,indent=2)}</div></div></div>',unsafe_allow_html=True)
