
import streamlit as st

def inject_css():
    st.markdown("""
<style>
:root{
 --sn-navy:#07182e; --sn-navy2:#0c2442; --sn-blue:#1677f2;
 --sn-blue2:#eaf3ff; --sn-bg:#f5f8fc; --sn-card:#fff;
 --sn-text:#142640; --sn-muted:#687b95; --sn-border:#e1e8f1;
 --sn-green:#13a36f; --sn-red:#e63d55; --sn-amber:#e9a51b;
}
.stApp{background:var(--sn-bg)!important;color:var(--sn-text)!important}
.block-container{max-width:1500px;padding:22px 26px 50px!important}
[data-testid="stHeader"]{background:transparent!important}
[data-testid="stToolbar"]{visibility:hidden}
h1,h2,h3,h4{color:var(--sn-text)!important;letter-spacing:-.025em!important}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#07172c,#091b33)!important}
[data-testid="stSidebar"]>div{background:transparent!important}
[data-testid="stSidebarNav"]{padding:18px 10px 10px!important}
[data-testid="stSidebarNav"] ul{gap:4px!important}
[data-testid="stSidebarNav"] a{color:#dbe7f5!important;border-radius:9px!important;padding:9px 12px!important;font-weight:700!important}
[data-testid="stSidebarNav"] a:hover{background:#102d50!important;color:#fff!important}
[data-testid="stSidebarNav"] a[aria-current="page"]{background:#1557a2!important;color:#fff!important;box-shadow:inset 3px 0 #55a8ff!important}
[data-testid="stSidebarNav"] a p,[data-testid="stSidebarNav"] a span{color:inherit!important}
.sn-brand{padding:7px 16px 10px}
.sn-brand-row{display:flex;align-items:center;gap:10px}
.sn-shield{width:34px;height:38px;display:flex;align-items:center;justify-content:center;color:#fff;font-size:29px}
.sn-logo{font-size:25px;font-weight:900;letter-spacing:.03em;color:#fff}.sn-logo span{color:#48a8ff}
.sn-brand-sub{color:#9fb5cf;font-size:10px;margin-left:44px;margin-top:-5px}
.sn-section{color:#7895b5;font-size:9px;font-weight:900;letter-spacing:.16em;margin:20px 16px 7px}
.sn-side-info{margin:0 16px;padding:10px 0;border-top:1px solid #1a304a}
.sn-side-label{color:#7e9bb9;font-size:9px;font-weight:800;text-transform:uppercase;letter-spacing:.1em}
.sn-side-value{color:#f5f8fc;font-size:12px;font-weight:700;margin-top:4px;line-height:1.4}
.sn-side-quote{color:#a9bfd7;font-size:11px;font-style:italic;line-height:1.5;padding:16px}
.sn-topbar{display:flex;align-items:center;gap:12px;margin-bottom:20px}
.sn-search{flex:1;background:#fff;border:1px solid var(--sn-border);border-radius:9px;padding:10px 15px;color:#71829a;font-size:12px}
.sn-shortcut{float:right;border:1px solid #e0e6ee;border-radius:6px;padding:2px 7px;color:#8b99aa}
.sn-user{display:flex;align-items:center;gap:9px;padding-left:8px}
.sn-avatar{width:34px;height:34px;border-radius:50%;background:#1475e8;color:#fff;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:11px}
.sn-user-name{font-size:12px;font-weight:800}.sn-user-sub{font-size:9px;color:var(--sn-muted);margin-top:1px}
.sn-env{background:#fff;border:1px solid var(--sn-border);border-radius:999px;padding:7px 11px;font-size:10px;font-weight:800;color:#40546c;white-space:nowrap}
.sn-dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:#19a875;margin-right:6px}
.sn-breadcrumb{color:#6b7e96;font-size:10px;font-weight:900;letter-spacing:.12em;text-transform:uppercase;margin-bottom:9px}
.sn-greeting{font-size:24px;font-weight:850;margin:0}.sn-subtitle{color:#6c7d94;font-size:13px;margin-top:4px}
.sn-runbar{display:flex;justify-content:flex-end;align-items:center;gap:10px}
.sn-last{font-size:9px;color:#72849b}.sn-last strong{display:block;color:#19304d;font-size:11px;margin-top:2px}
.sn-success{background:#dff7ed;color:#15956a;border-radius:999px;padding:6px 12px;font-size:10px;font-weight:800}
.sn-primary{background:#126bea!important;color:#fff!important;border:0!important;border-radius:8px!important;font-weight:800!important}
.sn-tabs{display:flex;gap:28px;border-bottom:1px solid var(--sn-border);margin:17px 0 15px}
.sn-tab{padding:0 0 11px;color:#627691;font-size:12px;font-weight:800}
.sn-tab.active{color:#1470e8;border-bottom:2px solid #1470e8}
.sn-kpi{background:#fff;border:1px solid var(--sn-border);border-radius:11px;padding:16px 15px;min-height:122px;box-shadow:0 3px 13px rgba(27,54,88,.045)}
.sn-kpi-head{display:flex;justify-content:space-between;align-items:center;color:#536983;font-size:10px;font-weight:800}
.sn-kpi-icon{font-size:21px}.sn-kpi-value{font-size:25px;font-weight:900;margin-top:8px}.sn-kpi-sub{font-size:9px;color:#71839a;margin-top:3px}
.sn-progress{height:5px;background:#e8eef5;border-radius:99px;margin-top:11px;overflow:hidden}.sn-progress>span{display:block;height:100%;border-radius:99px;background:#17a875}
.sn-trend{font-size:9px;color:#13a36f;font-weight:800;margin-top:5px}
.sn-card{background:#fff;border:1px solid var(--sn-border);border-radius:11px;padding:18px;box-shadow:0 3px 13px rgba(27,54,88,.04)}
.sn-card-title{font-size:16px;font-weight:850}.sn-card-sub{font-size:10px;color:#73849a;margin-top:3px}
.sn-finding-title{font-size:16px;font-weight:850}.sn-link{color:#0969df;font-size:10px;font-weight:800}
.sn-table-wrap{border:1px solid var(--sn-border);border-radius:9px;overflow:hidden;background:#fff}
.sn-table{width:100%;border-collapse:collapse;font-size:10px}.sn-table th{background:#f8fafc;color:#72839a;text-align:left;padding:10px 9px;font-weight:800;border-bottom:1px solid var(--sn-border)}
.sn-table td{padding:10px 9px;border-bottom:1px solid #edf1f5;color:#263b56;vertical-align:middle}.sn-table tr:last-child td{border-bottom:0}.sn-table tr:hover td{background:#f4f8ff}
.sn-id{color:#0567d9;font-weight:800}.sn-pill{display:inline-block;border-radius:999px;padding:4px 8px;font-size:9px;font-weight:900}.sn-failed{background:#ffe4e8;color:#d8324b}.sn-high{background:#ffdce2;color:#d8324b}.sn-medium{background:#fff0d2;color:#ad7100}.sn-pass{background:#dff7ed;color:#148a62}
.sn-detail{background:#fff;border:1px solid var(--sn-border);border-radius:11px;overflow:hidden;box-shadow:0 4px 18px rgba(22,45,76,.06)}
.sn-detail-head{padding:15px 16px;border-bottom:1px solid var(--sn-border)}.sn-detail-title{font-size:15px;font-weight:900}.sn-detail-desc{font-size:10px;color:#687b94;line-height:1.5;margin-top:7px}
.sn-detail-tabs{display:flex;gap:20px;padding:0 16px;border-bottom:1px solid var(--sn-border)}.sn-detail-tab{padding:10px 0;color:#627691;font-size:9px;font-weight:800}.sn-detail-tab.active{color:#1470e8;border-bottom:2px solid #1470e8}
.sn-detail-body{padding:13px 16px}.sn-row{display:grid;grid-template-columns:115px 1fr;gap:8px;padding:7px 0;border-bottom:1px solid #f0f3f7}.sn-row:last-child{border-bottom:0}.sn-label{color:#75869a;font-size:9px}.sn-val{color:#27405d;font-size:10px;font-weight:650;word-break:break-word}.sn-code{background:#10233d;color:#d8e7f7;border-radius:8px;padding:12px;font-family:Consolas,monospace;font-size:9px;line-height:1.5;overflow:auto;white-space:pre-wrap}
.sn-rem-title{font-size:13px;font-weight:850;margin:12px 0 7px}.sn-rem-tabs{display:flex;gap:20px;border-bottom:1px solid var(--sn-border)}.sn-rem-tab{padding:8px 0;font-size:9px;color:#647894;font-weight:800}.sn-rem-tab.active{color:#1470e8;border-bottom:2px solid #1470e8}
div[data-testid="stDataFrame"]{border:1px solid var(--sn-border)!important;border-radius:9px!important;overflow:hidden}
.stButton button{border-radius:8px!important;font-weight:800!important}
@media(max-width:1000px){.block-container{padding:18px!important}.sn-user-name,.sn-user-sub{display:none}}
</style>
""", unsafe_allow_html=True)

def sidebar_brand(model, is_demo=False, source_path=None):
    st.sidebar.markdown("""
<div class="sn-brand"><div class="sn-brand-row"><div class="sn-shield">⬢</div><div class="sn-logo">SEC<span>NET</span></div></div>
<div class="sn-brand-sub">Cloud Security Posture Management</div></div>
""", unsafe_allow_html=True)
    st.sidebar.markdown('<div class="sn-section">THÔNG TIN DỰ ÁN</div>', unsafe_allow_html=True)
    for label,value in [
        ("Project","SecNet CSPM"),("Mô tả","Hệ thống quản lý và kiểm soát bảo mật hạ tầng Cloud"),
        ("Tác giả / Project Owner","Nguyễn Công Định"),("Vai trò","CSPM Developer / Cloud Security"),
        ("Trường Cao đẳng","Công nghệ Thủ Đức")]:
        st.sidebar.markdown(f'<div class="sn-side-info"><div class="sn-side-label">{label}</div><div class="sn-side-value">{value}</div></div>',unsafe_allow_html=True)
    st.sidebar.markdown('<div class="sn-section">LIÊN HỆ</div>',unsafe_allow_html=True)
    for label,value in [("Điện thoại","0962 633 364"),("Email","dinhlabs.tech@gmail.com")]:
        st.sidebar.markdown(f'<div class="sn-side-info"><div class="sn-side-label">{label}</div><div class="sn-side-value">{value}</div></div>',unsafe_allow_html=True)
    st.sidebar.markdown('<div class="sn-section">MÔI TRƯỜNG</div>',unsafe_allow_html=True)
    for label,value in [("Nền tảng","AWS"),("Region",model.get("region","ap-southeast-1")),("Engine",model.get("engine","CSPM Engine v3.1"))]:
        st.sidebar.markdown(f'<div class="sn-side-info"><div class="sn-side-label">{label}</div><div class="sn-side-value">{value}</div></div>',unsafe_allow_html=True)
    st.sidebar.markdown('<div class="sn-side-quote">“Build a safer cloud,<br>for a better tomorrow.”<br><br>— SecNet</div>',unsafe_allow_html=True)

def topbar(model, title, breadcrumb):
    left,mid,right=st.columns([1.45,.45,.5])
    with left:
        st.markdown(f'<div class="sn-breadcrumb">{breadcrumb}</div><div class="sn-greeting" style="font-size:22px">{title}</div>',unsafe_allow_html=True)
    with mid:
        st.markdown(f'<div class="sn-env"><span class="sn-dot"></span> AWS · {model.get("region","ap-southeast-1")}</div>',unsafe_allow_html=True)
    with right:
        q=st.text_input("Tìm kiếm",placeholder="Tìm tài nguyên, control, sự cố...",label_visibility="collapsed")
        if q:
            st.session_state["global_search"]=q

