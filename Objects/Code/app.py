#!/usr/bin/env python3
# app.py — Streamlit Cloud–ready (repo-relative data path) with optional category analysis
from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Any, List

import streamlit as st
from streamlit.components.v1 import html
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# ---------------- Third-party libs ----------------
try:
    import networkx as nx
except Exception as e:
    st.error(f"networkx import failed: {e}")
    raise

try:
    from pyvis.network import Network
    _PYVIS_AVAILABLE = True
except Exception:
    _PYVIS_AVAILABLE = False

# ---- Optional category runners (guarded) ----
_CATEGORY_AVAILABLE = True
try:
    from cat_1 import run_category1
    from cat_2 import run_category2
    from cat_3 import run_category3
    from cat_4 import run_category4
    from cat_6 import run_category6
    from cat_7 import run_category7
    from cat_9 import run_category9
    from cat_10 import run_category10
    from cat_12 import run_category12
    from cat_13 import run_category13
except Exception:
    _CATEGORY_AVAILABLE = False

# ==================== CONFIG: DATA PATH ====================
# This file lives at: trustscope/Objects/Code/app.py
# Your JSON lives at:  trustscope/Objects/Domain Data/
OBJECTS_DIR = Path(__file__).resolve().parents[1]  # .../Objects
CANDIDATE_DIRS = [
    OBJECTS_DIR / "Domain Data",   # canonical
    OBJECTS_DIR / "DomainData",    # fallbacks
    OBJECTS_DIR / "domain data",
]
INPUT_DIR = next((p for p in CANDIDATE_DIRS if p.exists()), OBJECTS_DIR / "data")

FILES = {
    "ous":        "nexora.local_ous.json",
    "users":      "nexora.local_users.json",
    "groups":     "nexora.local_groups.json",
    "computers":  "nexora.local_computers.json",
    "domains":    "nexora.local_domains.json",
    "gpos":       "nexora.local_gpos.json",
    "containers": "nexora.local_containers.json",
}

# ==================== PAGE SETUP ====================
st.set_page_config(page_title="Trust Scope Risk Assessment", layout="wide")

st.markdown(
    """
    # 💂🏻‍♂️ TrustScope – Trust into verified security  

    Welcome to the **TrustScope Dashboard** – think of this as your **X-ray vision for Active Directory**.  
    We scan **domains, users, groups, OUs, and trust paths** inside `nexora.local`.  

    What you’ll find here:  
    - 🌐 **Domain Map** – A family tree of your AD  
    - ⚠️ **Risk Meter** – sidebar gauge (computed when analysis is enabled)  
    - 📊 **Category Insights** – optional (toggle in sidebar)  
    - 💡 **What-if Scenarios** – optional (toggle in sidebar)
    """
)

# ==================== HELPERS ====================
def load_json_list(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig") as f:
        obj = json.load(f)
    if isinstance(obj, dict) and isinstance(obj.get("data"), list):
        return obj["data"]
    if isinstance(obj, list):
        return obj
    return []

def prop(o: Dict[str, Any], key: str, default=None):
    return (o.get("Properties") or {}).get(key, default)

def dn_parent(dn: str) -> str:
    if not dn or "," not in dn:
        return ""
    return dn.split(",", 1)[1]

def _shorten(s: str, n: int = 22) -> str:
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"

# ==================== DOMAIN NAME ====================
domains_file = INPUT_DIR / FILES["domains"]
domain_name = "Unknown Domain"
if domains_file.exists():
    domains_data = load_json_list(domains_file)
    if domains_data:
        domain_name = (
            domains_data[0].get("Properties", {}).get("name")
            or domains_data[0].get("Properties", {}).get("dnsroot")
            or domain_name
        )
st.title(f"DOMAIN – {domain_name.upper()}")

# ==================== SIDEBAR ====================
st.sidebar.header("Configuration")

# Toggle to enable/disable category analysis (off by default)
enable_analysis = st.sidebar.checkbox(
    "Enable category analysis",
    value=False,
    help="Run category checks and render risk charts. Leave off for fast/graph-only view."
)

# Reserve a single sidebar slot for the gauge; we’ll update it later
gauge_slot = st.sidebar.empty()

# Node toggles
st.sidebar.subheader("Node Types")
show_domain    = st.sidebar.checkbox("Domain", True)
show_ou        = st.sidebar.checkbox("OU", True)
show_container = st.sidebar.checkbox("Container", False)
show_user      = st.sidebar.checkbox("User", False)
show_group     = st.sidebar.checkbox("Group", False)
show_computer  = st.sidebar.checkbox("Computer", True)
show_gpo       = st.sidebar.checkbox("GPO", True)

# Graph layout
st.sidebar.subheader("Graph Layout")
use_physics  = st.sidebar.checkbox("Free-Form", True)
hierarchical = st.sidebar.checkbox("Hierarchical", False)
level_sep    = st.sidebar.slider("Level separation", 100, 500, 220)
node_dist    = st.sidebar.slider("Node distance", 50, 400, 180)
search_text  = st.sidebar.text_input("Highlight nodes containing...", "")
build_btn    = st.sidebar.button("Build / Refresh graph")

# Mobile chart mode toggle
mobile_mode = st.sidebar.checkbox("📱 Mobile-friendly charts", value=True)

# ==================== LOAD ALL DATA ====================
def load_all(dir_path: Path):
    base = Path(dir_path)
    data = {}
    for k, fname in FILES.items():
        data[k] = load_json_list(base / fname)
    return data

if build_btn or "graph_built" not in st.session_state:
    st.session_state["data"] = load_all(INPUT_DIR)
    st.session_state["graph_built"] = True

data = st.session_state["data"]
ous, users, groups = data["ous"], data["users"], data["groups"]
computers, domains, gpos, containers = data["computers"], data["domains"], data["gpos"], data["containers"]

# ==================== OVERVIEW KPI CARDS ====================
st.markdown("## 📊 Overview")

if "toggles" not in st.session_state:
    st.session_state.toggles = {
        "Domains": False,
        "Users": False,
        "Groups": False,
        "Computers": False,
        "OUs": False,
        "GPOs": False,
    }

def kpi_card(col, icon, label, value, items, key_name="name"):
    with col:
        if st.button(f"{icon}\n{value}\n{label}", key=f"btn_{label}", use_container_width=True):
            st.session_state.toggles[label] = not st.session_state.toggles[label]
        if st.session_state.toggles[label]:
            clean_list = [(obj.get("Properties") or {}).get(key_name, str(obj)) for obj in items]
            list_html = "".join(
                f"<div style='padding:2px 0; white-space:normal; word-wrap:break-word;' title='{val}'>{val}</div>"
                for val in clean_list
            )
            st.markdown(
                f"""
                <div style='background:#1e293b;color:#f1f5f9;padding:10px;border-radius:10px;margin-top:8px;
                            text-align:left;font-size:13px;line-height:1.4;'>
                    {list_html}
                </div>
                """,
                unsafe_allow_html=True,
            )

col1, col2, col3, col4, col5, col6 = st.columns(6)
kpi_card(col1, "🌐", "Domains",   len(domains),   domains)
kpi_card(col2, "👥", "Users",     len(users),     users)
kpi_card(col3, "📂", "Groups",    len(groups),    groups)
kpi_card(col4, "🖥️", "Computers", len(computers), computers)
kpi_card(col5, "🏢", "OUs",       len(ous),       ous)
kpi_card(col6, "📜", "GPOs",      len(gpos),      gpos)

# ==================== BUILD GRAPH ====================
G = nx.DiGraph()

def add_node_from_obj(obj, ntype: str):
    dn   = prop(obj, "distinguishedname")
    name = prop(obj, "name") or dn or ntype
    if not dn:
        return None
    if dn not in G:
        G.add_node(dn, label=name, type=ntype)
    return dn

# Nodes
for d in domains:     add_node_from_obj(d, "Domain")
for ou in ous:        add_node_from_obj(ou, "OU")
for ct in containers: add_node_from_obj(ct, "Container")
for u in users:       add_node_from_obj(u, "User")
for g in groups:      add_node_from_obj(g, "Group")
for gp in gpos:       add_node_from_obj(gp, "GPO")
for c in computers:
    dn   = prop(c, "distinguishedname")
    name = prop(c, "name") or dn or "Computer"
    ntype = "DC" if dn and "OU=Domain Controllers" in dn else "Computer"
    if dn and dn not in G:
        G.add_node(dn, label=name, type=ntype)

# Containment edges
def add_containment_edges(coll):
    for obj in coll:
        child_dn = prop(obj, "distinguishedname")
        if not child_dn or child_dn not in G:
            continue
        parent_dn = dn_parent(child_dn)
        if parent_dn:
            if parent_dn not in G:
                G.add_node(parent_dn, label=parent_dn, type="Container")
            G.add_edge(parent_dn, child_dn, relationship="contains")

for coll in (domains, ous, containers, users, groups, gpos, computers):
    add_containment_edges(coll)

# Group memberships
for g in groups:
    g_dn = prop(g, "distinguishedname")
    members = (g.get("Properties") or {}).get("member", [])
    if isinstance(members, str):
        members = [members]
    for m in members:
        if g_dn and m in G:
            G.add_edge(g_dn, m, relationship="member")

# GPO links (OU ↔ GPO)
for ou in ous:
    ou_dn = prop(ou, "distinguishedname")
    gplink = (ou.get("Properties") or {}).get("gplink", "")
    if gplink and ou_dn:
        for gp in gpos:
            gp_dn = prop(gp, "distinguishedname")
            gp_name = prop(gp, "name")
            if gp_name and gp_name in gplink and gp_dn in G:
                G.add_edge(ou_dn, gp_dn, relationship="gplink")

# Domain trusts
domain_names = {prop(d, "name"): prop(d, "distinguishedname") for d in domains}
for d in domains:
    d_dn = prop(d, "distinguishedname")
    trust_partner = (d.get("Properties") or {}).get("trustpartner")
    if d_dn and trust_partner and trust_partner in domain_names:
        G.add_edge(d_dn, domain_names[trust_partner], relationship="trust")

# Filter by toggles
allowed_types = set()
if show_domain:    allowed_types.add("Domain")
if show_ou:        allowed_types.add("OU")
if show_container: allowed_types.add("Container")
if show_user:      allowed_types.add("User")
if show_group:     allowed_types.add("Group")
if show_computer:  allowed_types.update(["Computer", "DC"])
if show_gpo:       allowed_types.add("GPO")

nodes_to_keep = [n for n, a in G.nodes(data=True) if a.get("type") in allowed_types]
SG = G.subgraph(nodes_to_keep).copy()

# ==================== VISUALISE GRAPH ====================
st.markdown("## 🌐 Domain Map")
st.caption("Drag nodes • Zoom with mouse wheel • Use sidebar filters to refine view")

if _PYVIS_AVAILABLE:
    net = Network(
        height="780px",
        width="100%",
        bgcolor="#0d1117",
        font_color="#e6edf3",
        notebook=False,
        directed=True
    )
    options = {
        "nodes": {"shape": "dot", "size": 18, "font": {"size": 14}},
        "edges": {"arrows": {"to": {"enabled": True}}, "smooth": {"type": "dynamic"}},
        "physics": {"enabled": use_physics, "barnesHut": {"springLength": node_dist}},
        "layout": {"hierarchical": {"enabled": hierarchical, "levelSeparation": level_sep, "direction": "LR"}},
        "interaction": {"hover": True, "dragNodes": True, "navigationButtons": True, "keyboard": True}
    }
    net.set_options(json.dumps(options))

    color_map = {
        "Domain":   "#3b82f6",
        "OU":       "#22c55e",
        "Container":"#14b8a6",
        "User":     "#ef4444",
        "Group":    "#f59e0b",
        "Computer": "#8b5cf6",
        "DC":       "#a855f7",
        "GPO":      "#ec4899",
    }

    for n, a in SG.nodes(data=True):
        ntype = a.get("type", "Node")
        label = a.get("label", n)
        title = f"""
        <div style='padding:4px;font-size:13px;color:#f1f5f9;'>
            <b>{label}</b><br>
            <span style='color:#cbd5e1;'>Type:</span> {ntype}<br>
            <span style='color:#94a3b8;'>DN:</span> {n[:200]}{'...' if len(n)>200 else ''}
        </div>
        """
        if search_text and search_text.lower() in label.lower():
            color = {"background": "#facc15","border": "#fef08a",
                     "highlight": {"background": "#fde047", "border": "#facc15"}}
            size = 28
        else:
            base = color_map.get(ntype, "#94a3b8")
            color = {"background": base,"border": "#e2e8f0",
                     "highlight": {"background": base, "border": "#f9fafb"}}
            size = 20
        net.add_node(n, label=label, title=title, color=color, size=size, borderWidth=2)

    for u, v, a in SG.edges(data=True):
        net.add_edge(u, v, title=a.get("relationship", "rel"))

    html(net.generate_html(notebook=False), height=800, scrolling=True)
else:
    st.warning("PyVis not available. Install `pyvis` for interactive graph. Showing edges table instead.")
    st.dataframe(
        pd.DataFrame([{"from": u, "to": v, "rel": a.get("relationship", "rel")} for u, v, a in SG.edges(data=True)]),
        use_container_width=True,
    )

# ==================== RISK METER + (OPTIONAL) RISK DASHBOARD ====================
# Default values (no analysis yet)
overall_pct = 0.0
gauge_title = "Overall Risk"
gauge_suffix = "%"
gauge_range = [0, 100]

df_summary = None
reports = []

if enable_analysis:
    if not _CATEGORY_AVAILABLE:
        st.warning("Category analysis requested, but the category modules (cat_*) were not found in this environment.")
    else:
        # ---- Run categories safely and collect summaries ----
        error_rows = []
        summaries = []
        category_specs = [
            (run_category1,  "Password & Account Policy Checks"),
            (run_category2,  "Optional Feature & Domain Configuration"),
            (run_category3,  "Privileged Accounts & Group Membership"),
            (run_category4,  "Administrator Account Restrictions – Workstations & Member Servers"),
            (run_category6,  "Enterprise Admins Group Restrictions"),
            (run_category7,  "Domain Controller & Service Health"),
            (run_category9,  "Account & Audit Monitoring"),
            (run_category10, "Group Policy & Security Settings"),
            (run_category12, "Computer & Domain Management"),
            (run_category13, "Privilege & Trust Management"),
        ]

        for cat_func, title in category_specs:
            try:
                returned = cat_func(INPUT_DIR)
                if not (isinstance(returned, tuple) and len(returned) == 2):
                    raise ValueError("Category did not return (report_text, summary_dict) tuple")
                report_text, summary = returned
            except Exception as e:
                msg = f"{e.__class__.__name__}: {e}"
                report_text, summary = f"Error in {title}: {msg}", {"Category": title, "RiskScore": 0, "TotalFails": 0}
                error_rows.append({"Category": title, "Error": msg})

            reports.append((title, (report_text or "").strip()))

            base = {"Category": title, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0,
                    "TotalFails": 0, "RiskScore": 0, "MaxScore": 0}
            if isinstance(summary, dict):
                for k in base.keys():
                    if k in summary:
                        base[k] = summary[k]
            summaries.append(base)

        if summaries:
            df_summary = pd.DataFrame(summaries)
            for col in ["High", "Medium", "Low", "Unknown", "TotalFails", "RiskScore", "MaxScore"]:
                df_summary[col] = pd.to_numeric(df_summary[col], errors="coerce").fillna(0)

            EXPECTED_TOTAL_CHECKS = 120
            total_fails     = int(df_summary["TotalFails"].sum())
            total_unknowns  = int(df_summary["Unknown"].sum())
            overall_risk_sum = float(df_summary["RiskScore"].sum())
            total_max_score = float(df_summary["MaxScore"].sum())
            has_maxscore_col = total_max_score > 0

            if has_maxscore_col:
                overall_pct = round((overall_risk_sum / max(1.0, total_max_score)) * 100, 2)
                gauge_title = "Overall Weighted Risk (0–100%)"
            else:
                failure_rate = (total_fails + total_unknowns) / max(1, EXPECTED_TOTAL_CHECKS)
                overall_pct = round(failure_rate * 100, 2)
                gauge_title = "Overall Failure Rate (0–100%)"

# ---- Compact sidebar gauge (fits the side tab) ----
compact_gauge = go.Figure(go.Indicator(
    mode="gauge+number",
    value=float(overall_pct),
    number={"suffix": gauge_suffix, "font": {"size": 16}},         # compact number
    title={"text": gauge_title, "font": {"size": 12}},             # compact title
    gauge={
        "axis": {"range": gauge_range},
        "bar": {"color": "red"},
        "steps": [
            {"range": [0, 30], "color": "green"},
            {"range": [30, 70], "color": "yellow"},
            {"range": [70, 100], "color": "red"},
        ],
    }
))
compact_gauge.update_layout(margin=dict(l=6, r=6, t=24, b=6), height=160)
gauge_slot.plotly_chart(compact_gauge, use_container_width=True)

# ---- Risk Assessment visuals (only when analysis is enabled & df_summary exists) ----
if enable_analysis and isinstance(df_summary, pd.DataFrame) and not df_summary.empty:
    st.markdown("---")
    st.title("⚠️ Risk Assessment")

    # Category summaries table
    st.subheader("📈 Category Summaries")
    st.dataframe(df_summary, use_container_width=True)

    # KPIs + most critical
    EXPECTED_TOTAL_CHECKS = 120
    total_fails    = int(df_summary["TotalFails"].sum())
    total_unknowns = int(df_summary["Unknown"].sum())
    overall_risk_sum = float(df_summary["RiskScore"].sum())
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total Checks (ref.)", EXPECTED_TOTAL_CHECKS)
    k2.metric("Total Failures", total_fails)
    k3.metric("Overall Risk (%)", f"{overall_pct}%")
    if (df_summary["RiskScore"] > 0).any():
        critical_row = df_summary.loc[df_summary["RiskScore"].idxmax()]
        critical_cat = str(critical_row["Category"])
        critical_score = float(critical_row["RiskScore"])
    else:
        critical_cat, critical_score = "N/A", 0.0
    k4.metric("Most Critical Category", critical_cat, f"Score {int(critical_score)}")

    # What-if scenarios
    st.subheader("💡 What-if Scenarios")
    total_max_score = float(df_summary["MaxScore"].sum())
    has_maxscore_col = total_max_score > 0
    new_overall = overall_pct
    narratives = []
    df_sorted = df_summary.sort_values("RiskScore", ascending=False).head(3).copy()
    for _, row in df_sorted.iterrows():
        cat = row["Category"]
        score = float(row["RiskScore"])
        if has_maxscore_col:
            reduction_pct = round((score / max(1.0, total_max_score)) * 100, 2)
        else:
            fail_count = int(row["TotalFails"])
            reduction_pct = round((fail_count / max(1, EXPECTED_TOTAL_CHECKS)) * 100, 2)
        new_overall = max(0, round(new_overall - reduction_pct, 2))
        narratives.append(
            f"- **{cat}** remediation could reduce risk by ~{reduction_pct}% → **{new_overall}%**."
        )
    if narratives:
        st.markdown("\n".join(narratives))
        st.info("Prioritise fixes in order of the biggest projected drop.")

    st.markdown("---")

    # Radar
    st.subheader("🕸️ Category Comparison")
    if (df_summary["RiskScore"] > 0).any():
        radar_fig = go.Figure()
        radar_fig.add_trace(go.Scatterpolar(
            r=df_summary["RiskScore"],
            theta=df_summary["Category"],
            fill="toself",
            name="Risk Score"
        ))
        max_r = max(10.0, float(df_summary["RiskScore"].max()) + 20.0)
        radar_fig.update_layout(
            polar=dict(radialaxis=dict(visible=True, range=[0, max_r])),
            showlegend=False,
            title="Risk Score by Category"
        )
        st.plotly_chart(radar_fig, use_container_width=True, key="radar_chart_main")
    else:
        st.info("Radar chart omitted because RiskScore values are all zero.")

    # Severity Breakdown (mobile-friendly)
    st.subheader("📊 Severity Breakdown")
    available_sev = [c for c in ["High", "Medium", "Low"] if c in df_summary.columns]
    if available_sev:
        df_melt = df_summary.melt(
            id_vars="Category",
            value_vars=available_sev,
            var_name="Severity",
            value_name="Count"
        ).copy()
        df_melt["CategoryShort"] = df_melt["Category"].apply(_shorten)

        if mobile_mode:
            cat_count = df_melt["Category"].nunique()
            height = max(380, 26 * cat_count + 160)
            fig = px.bar(
                df_melt,
                y="CategoryShort",
                x="Count",
                color="Severity",
                orientation="h",
                text="Count",
                title="Failed Checks by Category & Severity"
            )
            fig.update_layout(
                height=height,
                margin=dict(l=10, r=10, t=50, b=10),
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
                yaxis=dict(automargin=True, title=None),
                xaxis=dict(title=None, tickfont=dict(size=10)),
                uniformtext_minsize=10, uniformtext_mode="hide"
            )
            fig.update_traces(
                textposition="outside",
                cliponaxis=False,
                hovertemplate="<b>%{customdata[0]}</b><br>Severity: %{customdata[1]}<br>Count: %{x}<extra></extra>",
                customdata=df_melt[["Category", "Severity"]].to_numpy()
            )
        else:
            fig = px.bar(
                df_melt,
                x="CategoryShort",
                y="Count",
                color="Severity",
                barmode="group",
                text="Count",
                title="Failed Checks by Category & Severity"
            )
            fig.update_layout(
                xaxis_tickangle=-30,
                margin=dict(l=10, r=10, t=50, b=10),
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
                xaxis_title=None,
                yaxis_title=None,
                uniformtext_minsize=10, uniformtext_mode="hide"
            )
            fig.update_traces(
                textposition="outside",
                cliponaxis=False,
                hovertemplate="<b>%{customdata[0]}</b><br>Severity: %{customdata[1]}<br>Count: %{y}<extra></extra>",
                customdata=df_melt[["Category", "Severity"]].to_numpy()
            )
        st.plotly_chart(fig, use_container_width=True, config={"responsive": True, "displayModeBar": False})
    else:
        st.info("No severity columns to chart.")

    # Table
    st.subheader("📈 Threat Posture Briefing")
    cols = [c for c in ["Category", "High", "Medium", "Low", "Unknown", "TotalFails", "RiskScore"] if c in df_summary.columns]
    st.dataframe(df_summary[cols], use_container_width=True, key="threat_posture_table_main")

    # Detailed reports
    st.subheader("📂 Detailed Reports")
    st.caption("Each section shows the checks behind the score for that category.")
    for title, text in reports:
        with st.expander(title, expanded=False):
            st.code(text or "(no details)", language="text")
else:
    # Soft note when analysis is off
    st.sidebar.caption("Risk Meter shows a placeholder until category analysis is enabled.")
