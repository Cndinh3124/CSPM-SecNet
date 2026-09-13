
import streamlit as st
import plotly.express as px
from services.report_loader import load_latest_report
from services.cspm_adapter import build_model
from components.ui import inject_css, sidebar_brand
st.set_page_config(page_title="SecNet CSPM · Tuân thủ CIS",page_icon="🛡️",layout="wide")
inject_css(); scan,path,demo=load_latest_report(); m=build_model(scan); sidebar_brand(m,demo,path)
st.markdown('<div class="sn-breadcrumb">SECNET / TUÂN THỦ (CIS)</div><div class="sn-greeting">Tuân thủ CIS</div><div class="sn-subtitle">Ma trận đánh giá Control và mức độ tuân thủ của từng nhóm kiểm soát.</div>',unsafe_allow_html=True)
a,b,c=st.columns(3); a.metric("Compliance",f'{m["compliance"]:.1f}%'); b.metric("Control đạt",m["passed_controls"]); c.metric("Control không đạt",m["failed_controls"])
df=m["controls"]
fig=px.bar(df.sort_values("Compliance"),x="Compliance",y="Control",orientation="h",color="Status",range_x=[0,100],text="Compliance",color_discrete_map={"PASSED":"#13a36f","FAILED":"#e63d55","UNKNOWN":"#a8b2bf"})
fig.update_traces(texttemplate="%{text:.0f}%",textposition="outside")
fig.update_layout(height=420,margin=dict(l=0,r=30,t=5,b=0),paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",font=dict(color="#536983"),legend_title=None,xaxis_title=None,yaxis_title=None)
st.plotly_chart(fig,use_container_width=True,config={"displayModeBar":False})
st.dataframe(df,use_container_width=True,hide_index=True,column_config={"Compliance":st.column_config.ProgressColumn("Compliance",min_value=0,max_value=100,format="%.0f%%")})
