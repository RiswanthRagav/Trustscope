#!/usr/bin/env python3
# app.py — Streamlit Cloud–ready (repo-relative data path + robust charts)

from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Any, List

import streamlit as st
from streamlit.components.v1 import html
import pandas as pd

# ---- Third-party libs ----
# Expect these in requirements.txt: streamlit, pandas, networkx, pyvis, plotly
import plotly.express as px
import plotly.graph_objects as go

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

# ---- Import category runners (these must be in the same folder as app.py) ----
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
    - ⚠️ **Risk Scores** – Quantified misconfigurations  
    - 📊 **Category Insights** – Spot the troublemakers  
    - 💡 **What-if Scenarios** – Simulate remediation impact  
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

# Risk meter placeholder; updated later
gauge_fig_sidebar = go.Figure(go.Indicator(
    mode="gauge+number", value=0,
    number={"suffix": "%"},
    title={"text": "Overall Risk (0–100%)"},
    gauge={
        "axis": {"range": [0, 100]},
        "bar": {"color": "red"},
        "steps": [
            {"range": [0, 30], "color": "green"},
            {"range": [30, 70], "color": "yellow"},
            {"range": [70, 100], "color": "red"},
        ],
    }
))
gauge_fig_sidebar.update_layout(margin=dict(l=5, r=5, t=20, b=5), height=220)
st.sidebar.plotly_chart(gauge_fig_sidebar, use_container_width=True)

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
        size = 28 if (search_text and search_text.lower() in label.lower()) else 20
        net.add_node(n, label=label, color=color_map.get(ntype, "#94a3b8"), size=size)
    for u, v, a in SG.edges(data=True):
        net.add_edge(u, v, title=a.get("relationship", "rel"))
    # physics options
    options = {
        "nodes": {"shape": "dot", "font": {"size": 14}},
        "edges": {"arrows": {"to": {"enabled": True}}, "smooth": {"type": "dynamic"}},
        "physics": {"enabled": use_physics, "barnesHut": {"springLength": node_dist}},
        "layout": {"hierarchical": {"enabled": hierarchical, "levelSeparation": level_sep, "direction": "LR"}},
        "interaction": {"hover": True, "dragNodes": True, "navigationButtons": True, "keyboard": True}
    }
    net.set_options(json.dumps(options))
    html(net.generate_html(notebook=False), height=800, scrolling=True)
else:
    st.warning("PyVis not available. Install `pyvis` for interactive graph. Showing edges table instead.")
    st.dataframe(
        pd.DataFrame([{"from": u, "to": v, "rel": a.get("relationship", "rel")} for u, v, a in SG.edges(data=True)]),
        use_container_width=True,
    )

# ==================== RISK DASHBOARD ====================
st.markdown("---")
st.title("⚠️ Risk Assessment")

# Run categories safely and collect
error_rows = []
reports, summaries = [], []
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
        report_text, summary = cat_func(INPUT_DIR)  # expect category functions to use input_dir
    except Exception as e:
        msg = f"{e.__class__.__name__}: {e}"
        report_text, summary = f"Error in {title}: {msg}", {"Category": title, "RiskScore": 0, "TotalFails": 0}
        error_rows.append({"Category": title, "Error": msg})
    reports.append((title, report_text))
    # normalize summary to stable columns
    base_summary = {
        "Category": title, "High": 0, "Medium": 0, "Low": 0,
        "Unknown": 0, "TotalFails": 0, "RiskScore": 0
    }
    if isinstance(summary, dict):
        base_summary.update(summary)
    summaries.append(base_summary)

if error_rows:
    with st.expander("❗ Category errors (open for details)"):
        st.dataframe(pd.DataFrame(error_rows), use_container_width=True)

if summaries:
    df_summary = pd.DataFrame(summaries)

    # Ensure columns exist & are numeric
    for col in ["High", "Medium", "Low", "Unknown", "TotalFails", "RiskScore", "MaxScore"]:
        if col not in df_summary.columns:
            df_summary[col] = 0
        df_summary[col] = pd.to_numeric(df_summary[col], errors="coerce").fillna(0)

    st.subheader("📈 Category Summaries")
    st.dataframe(df_summary, use_container_width=True)

    # KPIs
    EXPECTED_TOTAL_CHECKS = 120  # fallback if MaxScore is not provided by categories
    total_fails = int(df_summary["TotalFails"].sum())
    total_unknowns = int(df_summary["Unknown"].sum())
    overall_risk_raw = float(df_summary["RiskScore"].sum())

    has_maxscore_col = (df_summary["MaxScore"].fillna(0).sum() > 0)
    if has_maxscore_col:
        total_max_score = float(df_summary["MaxScore"].fillna(0).sum())
        overall_score_pct = round((overall_risk_raw / max(1.0, total_max_score)) * 100, 2)
        gauge_title = "Overall Weighted Risk (0–100%)"
    else:
        failure_rate = (total_fails + total_unknowns) / max(1, EXPECTED_TOTAL_CHECKS)
        overall_score_pct = round(failure_rate * 100, 2)
        gauge_title = "Overall Failure Rate (0–100%)"

    if len(df_summary):
        critical_row = df_summary.loc[df_summary["RiskScore"].idxmax()]
        critical_cat = str(critical_row["Category"])
        critical_score = float(critical_row["RiskScore"])
    else:
        critical_cat, critical_score = "N/A", 0

    st.subheader("📊 Global Overview Metrics")
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric("Total Checks (ref.)", EXPECTED_TOTAL_CHECKS)
    kpi2.metric("Total Failures", total_fails)
    kpi3.metric("Overall Risk Score", f"{overall_score_pct}%")
    kpi4.metric("Most Critical Category", critical_cat, f"Score {int(critical_score)}")

    # Update sidebar gauge with the computed value
    with st.sidebar:
        gauge_fig_sidebar = go.Figure(go.Indicator(
            mode="gauge+number",
            value=overall_score_pct,
            number={"suffix": "%"},
            title={"text": gauge_title},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": "red"},
                "steps": [
                    {"range": [0, 30], "color": "green"},
                    {"range": [30, 70], "color": "yellow"},
                    {"range": [70, 100], "color": "red"},
                ],
            }
        ))
        gauge_fig_sidebar.update_layout(margin=dict(l=5, r=5, t=20, b=5), height=220)
        st.plotly_chart(gauge_fig_sidebar, use_container_width=True)

    # What-if scenarios
    st.subheader("💡 What-if Scenarios")
    df_sorted = df_summary.sort_values("RiskScore", ascending=False).head(3).copy()
    narratives, new_overall = [], overall_score_pct
    for _, row in df_sorted.iterrows():
        cat = row["Category"]
        score = float(row["RiskScore"])
        fail_count = int(row["TotalFails"])
        high_count = int(row.get("High", 0))
        if has_maxscore_col:
            total_max_score = float(df_summary["MaxScore"].fillna(0).sum())
            reduction_pct = round((score / max(1.0, total_max_score)) * 100, 2)
        else:
            reduction_pct = round((fail_count / max(1, EXPECTED_TOTAL_CHECKS)) * 100, 2)
        new_overall = max(0, round(new_overall - reduction_pct, 2))
        narratives.append(
            f"- **{cat}** has {fail_count} failed checks "
            f"({high_count} high). Remediation could drop overall risk by ~{reduction_pct}% "
            f"to **{new_overall}%**."
        )
    if narratives:
        st.markdown("\n".join(narratives))
        st.info("Prioritise fixes in order of biggest projected drop.")

    st.markdown("---")

    # Radar (Threat Posture)
    st.subheader("🕸️ Threat Posture (Radar)")
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
        st.success("All category risk scores are zero — radar omitted.")

    # Severity Breakdown (Bar)
    st.subheader("📊 Severity Breakdown")
    available_sev = [c for c in ["High", "Medium", "Low"] if c in df_summary.columns]
    if available_sev:
        df_melt = df_summary.melt(
            id_vars="Category", value_vars=available_sev,
            var_name="Severity", value_name="Count"
        )
        fig = px.bar(
            df_melt, x="Category", y="Count", color="Severity",
            barmode="group", text="Count", title="Failed Checks by Category & Severity"
        )
        fig.update_layout(xaxis_tickangle=-30)
        st.plotly_chart(fig, use_container_width=True, key="severity_chart_main")
    else:
        st.info("No severity columns to chart.")

    # Threat Posture Table
    st.subheader("📈 Threat Posture Briefing")
    cols = [c for c in ["Category", "High", "Medium", "Low", "Unknown", "TotalFails", "RiskScore"] if c in df_summary.columns]
    st.dataframe(df_summary[cols], use_container_width=True, key="threat_posture_table_main")

    # Detailed Reports
    st.subheader("📂 Detailed Reports")
    st.caption("Each section shows the checks behind the score for that category.")
    for title, text in reports:
        with st.expander(title, expanded=False):
            st.code(text or "(no details)", language="text")

else:
    st.warning("No summary data found — check JSONs under 'Objects/Domain Data' and category functions.")
