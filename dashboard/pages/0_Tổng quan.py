import json
import html
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

from services.report_loader import load_latest_report
from services.cspm_adapter import build_model


st.set_page_config(
    page_title="SecNet CSPM · Security Posture",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------
st.markdown(
    """
<style>
:root {
    --bg: #f5f7fa;
    --surface: #ffffff;
    --border: #e5eaf0;
    --text: #172b4d;
    --muted: #6b778c;
    --green: #0f9d72;
    --red: #d83a52;
    --amber: #d99000;
    --blue: #1769aa;
}
.stApp { background: var(--bg); color: var(--text); }
.block-container { padding: 28px 34px 42px; max-width: 1500px; }
[data-testid="stSidebar"] {
    background: #101827;
    border-right: 1px solid #1f2a3d;
}
[data-testid="stSidebar"] * { color: #dce5f0; }
[data-testid="stSidebar"] .stButton button {
    border: 1px solid #2b3950;
    background: #172235;
    color: #dce5f0;
}
[data-testid="stSidebar"] .stButton button:hover {
    border-color: #4d6687;
    color: white;
}
.sn-eyebrow {
    color: #718096;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: .12em;
    text-transform: uppercase;
    margin-bottom: 7px;
}
.sn-title {
    color: #172b4d;
    font-size: 31px;
    line-height: 1.15;
    font-weight: 750;
    margin: 0;
}
.sn-subtitle {
    color: #6b778c;
    font-size: 14px;
    margin-top: 8px;
}
.sn-status {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 7px 11px;
    border-radius: 999px;
    background: #edf8f4;
    color: #087653;
    font-size: 12px;
    font-weight: 700;
}
.sn-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #13a36f;
}
.sn-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 1px 2px rgba(16,24,40,.03);
}
.sn-kpi {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px 20px;
    min-height: 142px;
}
.sn-kpi-label {
    color: #6b778c;
    font-size: 13px;
    font-weight: 650;
    margin-bottom: 12px;
}
.sn-kpi-value {
    color: #172b4d;
    font-size: 34px;
    font-weight: 760;
    line-height: 1;
}
.sn-kpi-meta {
    color: #8793a5;
    font-size: 12px;
    margin-top: 13px;
}
.sn-section {
    color: #172b4d;
    font-size: 18px;
    font-weight: 720;
    margin: 0 0 3px;
}
.sn-section-sub {
    color: #7a869a;
    font-size: 12px;
    margin-bottom: 15px;
}
.sn-finding {
    border: 1px solid #e5eaf0;
    border-radius: 9px;
    padding: 13px 14px;
    margin-bottom: 9px;
    background: #fff;
}
.sn-finding-title {
    color: #172b4d;
    font-size: 14px;
    font-weight: 700;
}
.sn-finding-resource {
    color: #6b778c;
    font-size: 12px;
    margin-top: 5px;
    word-break: break-all;
}
.sn-pill {
    display: inline-block;
    border-radius: 999px;
    padding: 4px 9px;
    font-size: 10px;
    font-weight: 750;
}
.sn-high { background:#fdecef; color:#b4233c; }
.sn-medium { background:#fff5dc; color:#946200; }
.sn-failed { background:#fdecef; color:#b4233c; }
.sn-passed { background:#eaf8f3; color:#087653; }
.sn-muted { color:#8793a5; font-size:12px; }
div[data-testid="stMetric"] {
    background: transparent;
}
button[kind="secondary"] {
    border-radius: 8px;
}
</style>
""",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------
try:
    scan, source_path, demo = load_latest_report()
    model = build_model(scan)
except Exception as exc:
    st.error(f"Không thể tải dữ liệu CSPM: {exc}")
    st.stop()

# ---------------------------------------------------------------------
# Sidebar — primary navigation
# ---------------------------------------------------------------------
with st.sidebar:
    st.markdown(
        """
        <div style="font-size:22px;font-weight:800;color:#fff;">🛡️ SecNet</div>
        <div style="font-size:12px;color:#8fa2bb;margin-top:2px;">Cloud Security Posture Management</div>
        <hr style="border:0;border-top:1px solid #273449;margin:18px 0;">
        """,
        unsafe_allow_html=True,
    )

    st.page_link("pages/0_Tổng quan.py", label="▣  Tổng quan")
    st.page_link("pages/1_Danh sách sự cố.py", label="⚠  Findings")
    st.page_link("pages/2_Tuân thủ (CIS).py", label="✓  Compliance")
    st.page_link("pages/3_Tài nguyên.py", label="◇  Resources")
    st.page_link("pages/4_Khắc phục (Remediation).py", label="↻  Remediation")
    st.page_link("pages/5_Chính sách (Policies).py", label="⚙  Policies")
    st.page_link("pages/6_Lịch sử quét.py", label="◷  Scan History")

    st.markdown(
        """
        <hr style="border:0;border-top:1px solid #273449;margin:20px 0 14px;">
        <div style="font-size:11px;color:#7f91aa;text-transform:uppercase;letter-spacing:.08em;">Environment</div>
        <div style="font-size:13px;color:#dce5f0;margin-top:7px;">AWS · ap-southeast-1</div>
        <div style="font-size:12px;color:#8192a9;margin-top:3px;">Scope: LAB</div>
        """,
        unsafe_allow_html=True,
    )

    if st.button("↻  Làm mới dữ liệu", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

# ---------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------
top_left, top_right = st.columns([4.2, 1.3])

with top_left:
    st.markdown('<div class="sn-eyebrow">SECNET / SECURITY POSTURE</div>', unsafe_allow_html=True)
    st.markdown('<div class="sn-title">Security Posture Overview</div>', unsafe_allow_html=True)
    st.markdown(
        "Tổng quan rủi ro và mức độ tuân thủ của hạ tầng AWS trong phạm vi giám sát.",
        unsafe_allow_html=True,
    )

with top_right:
    st.markdown(
        '<div style="text-align:right;margin-top:8px;"><span class="sn-status"><span class="sn-dot"></span>Monitoring active</span></div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        f'<div style="text-align:right;color:#7a869a;font-size:11px;margin-top:8px;">Last scan<br><b style="color:#52627a;">{html.escape(str(model["generated_at"] or "N/A"))}</b></div>',
        unsafe_allow_html=True,
    )

st.write("")

# ---------------------------------------------------------------------
# KPIs — deliberately limited to security essentials
# ---------------------------------------------------------------------
kpi_cols = st.columns(4)

kpis = [
    ("Security Score", f'{model["compliance"]:.1f}%', "Control compliance"),
    ("Passed Controls", f'{model["passed_controls"]}', f'of {model["control_total"]} controls'),
    ("Failed Controls", f'{model["failed_controls"]}', "Require attention"),
    ("At Risk Resources", f'{model["failed_resources"]}', "Resources with findings"),
]

for col, (label, value, meta) in zip(kpi_cols, kpis):
    with col:
        st.markdown(
            f"""
            <div class="sn-kpi">
                <div class="sn-kpi-label">{label}</div>
                <div class="sn-kpi-value">{html.escape(value)}</div>
                <div class="sn-kpi-meta">{html.escape(meta)}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

st.write("")

# ---------------------------------------------------------------------
# Compliance + risk distribution
# ---------------------------------------------------------------------
left, right = st.columns([1.55, 1], gap="medium")

with left:
    st.markdown('<div class="sn-card">', unsafe_allow_html=True)
    st.markdown('<div class="sn-section">Compliance by service</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sn-section-sub">Tỷ lệ Passed / Failed / Unknown theo nhóm kiểm soát.</div>',
        unsafe_allow_html=True,
    )

    grouped = {}
    for _, row in model["controls"].iterrows():
        cid = str(row["Control"])
        if cid.startswith("EC2"):
            service = "EC2"
        elif cid.startswith("S3"):
            service = "S3"
        elif cid.upper().startswith("IAM"):
            service = "IAM"
        elif cid.upper().startswith("RDS"):
            service = "RDS"
        elif cid.lower().startswith("cloudtrail"):
            service = "CloudTrail"
        else:
            service = "Other"

        grouped.setdefault(service, {"Passed": 0, "Failed": 0, "Unknown": 0})
        grouped[service]["Passed"] += int(row["Passed"])
        grouped[service]["Failed"] += int(row["Failed"])
        grouped[service]["Unknown"] += int(row["Unknown"])

    chart_rows = []
    for service, values in grouped.items():
        total = max(sum(values.values()), 1)
        chart_rows.extend(
            [
                {"Service": service, "Status": "Passed", "Percent": values["Passed"] / total * 100},
                {"Service": service, "Status": "Failed", "Percent": values["Failed"] / total * 100},
                {"Service": service, "Status": "Unknown", "Percent": values["Unknown"] / total * 100},
            ]
        )

    if chart_rows:
        fig = px.bar(
            chart_rows,
            x="Service",
            y="Percent",
            color="Status",
            barmode="stack",
            range_y=[0, 100],
            color_discrete_map={
                "Passed": "#0f9d72",
                "Failed": "#d83a52",
                "Unknown": "#a8b2bf",
            },
        )
        fig.update_layout(
            height=310,
            margin=dict(l=10, r=10, t=5, b=5),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#52627a", size=12),
            legend=dict(orientation="h", y=-0.18),
            xaxis_title=None,
            yaxis_title=None,
        )
        fig.update_yaxes(ticksuffix="%", gridcolor="#edf0f4")
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    else:
        st.info("Chưa có dữ liệu compliance.")

    st.markdown("</div>", unsafe_allow_html=True)

with right:
    st.markdown('<div class="sn-card">', unsafe_allow_html=True)
    st.markdown('<div class="sn-section">Risk distribution</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sn-section-sub">Phân bố trạng thái của tài nguyên đã được phát hiện.</div>',
        unsafe_allow_html=True,
    )

    values = [
        int(model["passed_resources"]),
        int(model["failed_resources"]),
        int(model["unknown_resources"]),
    ]

    fig = go.Figure(
        go.Pie(
            labels=["Passed", "At Risk", "Unknown"],
            values=values,
            hole=0.68,
            textinfo="none",
            marker=dict(colors=["#0f9d72", "#d83a52", "#a8b2bf"]),
        )
    )
    fig.add_annotation(
        text=f'<b>{model["active_resources"]}</b><br><span style="font-size:11px">Resources</span>',
        x=.5,
        y=.5,
        showarrow=False,
        font=dict(size=24, color="#172b4d"),
    )
    fig.update_layout(
        height=310,
        margin=dict(l=0, r=0, t=0, b=0),
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#52627a", size=12),
        legend=dict(orientation="v", x=.96, y=.5, xanchor="left"),
    )
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    st.markdown("</div>", unsafe_allow_html=True)

st.write("")

# ---------------------------------------------------------------------
# Top findings — real navigation buttons
# ---------------------------------------------------------------------
st.markdown('<div class="sn-section">Top security findings</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sn-section-sub">Các finding có mức độ rủi ro cao nhất trong lần quét gần nhất.</div>',
    unsafe_allow_html=True,
)

findings = model["failed_table"].copy()

if findings.empty:
    st.success("Không có finding FAILED trong scan hiện tại.")
else:
    findings["RiskOrder"] = findings["Risk"].map(
        {"Critical": 4, "Cao": 3, "High": 3, "Trung bình": 2, "Medium": 2, "Thấp": 1, "Low": 1}
    ).fillna(0)
    findings = findings.sort_values(["RiskOrder", "Control"], ascending=[False, True]).head(5)

    for idx, (_, finding) in enumerate(findings.iterrows()):
        resource = str(finding.get("Resource", "UNKNOWN"))
        control = str(finding.get("Control", "UNKNOWN"))
        risk_label = str(finding.get("Risk", "Medium"))
        reason = str(finding.get("Reason", "") or "Resource không đáp ứng yêu cầu bảo mật.")

        risk_class = "sn-high" if risk_label in {"Critical", "Cao", "High"} else "sn-medium"

        c1, c2, c3, c4 = st.columns([1.0, 1.7, 3.5, 1.15])

        with c1:
            st.markdown(
                f'<span class="sn-pill {risk_class}">{html.escape(risk_label.upper())}</span>',
                unsafe_allow_html=True,
            )

        with c2:
            st.markdown(
                f'<div class="sn-finding-title">{html.escape(control)}</div>',
                unsafe_allow_html=True,
            )

        with c3:
            st.markdown(
                f'<div class="sn-finding-title">{html.escape(resource)}</div>'
                f'<div class="sn-finding-resource">{html.escape(reason[:120])}</div>',
                unsafe_allow_html=True,
            )

        with c4:
            # This button is intentionally functional: it stores the selected
            # finding and routes to the Findings page.
            if st.button("View finding →", key=f"view_finding_{idx}", use_container_width=True):
                st.session_state["selected_finding_resource"] = resource
                st.session_state["selected_finding_control"] = control
                st.switch_page("pages/1_Danh sách sự cố.py")

        st.markdown(
            '<div style="height:1px;background:#e9edf2;margin:7px 0 10px;"></div>',
            unsafe_allow_html=True,
        )

# ---------------------------------------------------------------------
# Footer status
# ---------------------------------------------------------------------
st.write("")
footer_left, footer_right = st.columns([3, 1])
with footer_left:
    st.markdown(
        f'<span class="sn-muted">Source: {html.escape(str(source_path or "CSPM API"))}</span>',
        unsafe_allow_html=True,
    )
with footer_right:
    st.markdown(
        '<div style="text-align:right;"><span class="sn-muted">Read-only security overview</span></div>',
        unsafe_allow_html=True,
    )
