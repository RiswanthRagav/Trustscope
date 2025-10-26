# app.py
import json
from pathlib import Path
from typing import Dict, Any, List

import streamlit as st
from streamlit.components.v1 import html
import pandas as pd
df_summary = pd.DataFrame()

from pyvis.network import Network
import plotly.express as px
import plotly.graph_objects as go   

# ---- Import your category runners ----
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

# ---- CONFIG ----
INPUT_DIR = r"C:\Users\LENOVO\OneDrive\Desktop\dissertation\Nexora.local"
FILES = {
    "ous":        "nexora.local_ous.json",
    "users":      "nexora.local_users.json",
    "groups":     "nexora.local_groups.json",
    "computers":  "nexora.local_computers.json",
    "domains":    "nexora.local_domains.json",
    "gpos":       "nexora.local_gpos.json",
    "containers": "nexora.local_containers.json",
}

st.set_page_config(page_title="Trust Scope Risk Assessment", layout="wide")

st.markdown(
    """
    # 💂🏻‍♂️ TrustScope – Trust into verified security  

    Welcome to the **TrustScope Dashboard** – think of this as your **X-ray vision for Active Directory**.  
    we’re here to scan **domains, users, groups, OUs, and trust paths** inside `nexora.local`.  

    What you’ll find here:  
    - 🌐 **Domain Map** – A family tree of your AD, except with way more secrets.  
    - ⚠️ **Risk Scores** – Because "everything’s fine" is never a real security report.  
    - 📊 **Category Insights** – Spot the troublemakers (looking at you, overpopulated Admin groups 👀).  
    - 💡 **What-if Scenarios** – See how much safer life gets if you actually fix stuff.  

    Use this dashboard to **hunt misconfigurations, expose attack paths, and keep attackers from having a field day**.  
    Basically: *your AD’s dirty laundry, neatly folded and color-coded*. 🧺  
    """
)


# -------------------- domain name --------------------
domains_file = Path(INPUT_DIR) / "nexora.local_domains.json"
domain_name = "Unknown Domain"
if domains_file.exists():
    with open(domains_file, "r", encoding="utf-8") as f:
        domains_data = json.load(f)
    if isinstance(domains_data, dict) and "data" in domains_data:
        domains_data = domains_data["data"]
    if isinstance(domains_data, list) and len(domains_data) > 0:
        domain_name = (domains_data[0].get("Properties", {}).get("name")
                       or domains_data[0].get("Properties", {}).get("dnsroot")
                       or domain_name)

st.title(f"DOMAIN – {domain_name.upper()}")

# -------------------- helpers --------------------
def load_json_list(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
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

# -------------------- sidebar --------------------
st.sidebar.header("Configuration")
data_dir = INPUT_DIR
# -------------------- Pre-calculate Overall Risk (for Sidebar Gauge) --------------------
overall_score_pct = 0
gauge_title = "Overall Risk (0–100%)"

if "df_summary" not in st.session_state:
    st.session_state["df_summary"] = pd.DataFrame()

reports, summaries = [], []
for cat_func, title in [
    (run_category1, "Password & Account Policy Checks"),
    (run_category2, "Optional Feature & Domain Configuration"),
    (run_category3, "Privileged Accounts & Group Membership"),
    (run_category4, "Administrator Account Restrictions – Workstations & Member Servers"),
    (run_category6, "Enterprise Admins Group Restrictions"),
    (run_category7, "Domain Controller & Service Health"),
    (run_category9, "Account & Audit Monitoring"),
    (run_category10, "Group Policy & Security Settings"),
    (run_category12, "Computer & Domain Management"),
    (run_category13, "Privilege & Trust Management"),
]:
    try:
        report_text, summary = cat_func(INPUT_DIR)
    except Exception as e:
        report_text, summary = f"Error in {title}: {e}", {"Category": title, "RiskScore": 0, "TotalFails": 0}
    reports.append((f"Category: {title}", report_text))
    summaries.append({"Category": title, **summary})

if summaries:
    df_summary = pd.DataFrame(summaries)
    st.session_state["df_summary"] = df_summary

    overall_risk_raw = float(df_summary["RiskScore"].sum())
    if "MaxScore" in df_summary.columns and df_summary["MaxScore"].fillna(0).sum() > 0:
        total_max_score = float(df_summary["MaxScore"].fillna(0).sum())
        overall_score_pct = round((overall_risk_raw / total_max_score) * 100, 2)
        gauge_title = "Overall Weighted Risk (0–100%)"
    else:
        EXPECTED_TOTAL_CHECKS = 120
        total_fails = int(df_summary["TotalFails"].sum())
        total_unknowns = int(df_summary["Unknown"].sum()) if "Unknown" in df_summary else 0
        failure_rate = (total_fails + total_unknowns) / max(1, EXPECTED_TOTAL_CHECKS)
        overall_score_pct = round(failure_rate * 100, 2)
        gauge_title = "Always Mind the Gap"
with st.sidebar:
    st.subheader("Risk Meter")
    gauge_fig_sidebar = go.Figure(go.Indicator(
        mode="gauge+number",
        value=overall_score_pct,
        number={"suffix": "👎"},
        title={"text": "Always Mind the Gap"},
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
    gauge_fig_sidebar.update_layout(
        margin=dict(l=5, r=5, t=20, b=5),
        height=220
    )
    st.plotly_chart(gauge_fig_sidebar, use_container_width=True)

# Node type toggles
st.sidebar.subheader("Node Types")
show_domain    = st.sidebar.checkbox("Domain", True)
show_ou        = st.sidebar.checkbox("OU", True)
show_container = st.sidebar.checkbox("Container", False)
show_user      = st.sidebar.checkbox("User", False)
show_group     = st.sidebar.checkbox("Group", False)
show_computer  = st.sidebar.checkbox("Computer", True)
show_gpo       = st.sidebar.checkbox("GPO", True)

# Layout toggles
st.sidebar.subheader("Graph Layout")
use_physics       = st.sidebar.checkbox("Free-Form", True)
hierarchical      = st.sidebar.checkbox("Hierarchical", False)
level_sep         = st.sidebar.slider("Level separation", 100, 500, 220)
node_dist         = st.sidebar.slider("Node distance", 50, 400, 180)
search_text       = st.sidebar.text_input("Highlight nodes containing...", "")

build_btn = st.sidebar.button("Build / Refresh graph")

# -------------------- load data --------------------
def load_all(dir_path: str):
    base = Path(dir_path)
    data = {}
    for k, fname in FILES.items():
        data[k] = load_json_list(base / fname)
    return data

if build_btn or "graph_built" not in st.session_state:
    st.session_state["data"] = load_all(data_dir)
    st.session_state["graph_built"] = True

data = st.session_state["data"]
ous, users, groups = data["ous"], data["users"], data["groups"]
computers, domains, gpos, containers = data["computers"], data["domains"], data["gpos"], data["containers"]

# -------------------- build graph --------------------
G = nx.DiGraph()

def add_node_from_obj(obj, ntype: str):
    dn   = prop(obj, "distinguishedname")
    name = prop(obj, "name") or dn or ntype
    if not dn:
        return None
    if dn not in G:
        G.add_node(dn, label=name, type=ntype)
    return dn

for d in domains:    add_node_from_obj(d, "Domain")
for ou in ous:       add_node_from_obj(ou, "OU")
for ct in containers:add_node_from_obj(ct, "Container")
for u in users:      add_node_from_obj(u, "User")
for g in groups:     add_node_from_obj(g, "Group")
for gp in gpos:      add_node_from_obj(gp, "GPO")   # ✅ GPOs now added
for c in computers:
    dn   = prop(c, "distinguishedname")
    name = prop(c, "name") or dn or "Computer"
    ntype = "DC" if dn and "OU=Domain Controllers" in dn else "Computer"
    if dn and dn not in G:
        G.add_node(dn, label=name, type=ntype)

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
# -------------------- build graph --------------------
G = nx.DiGraph()

def add_node_from_obj(obj, ntype: str):
    dn   = prop(obj, "distinguishedname")
    name = prop(obj, "name") or dn or ntype
    if not dn:
        return None
    if dn not in G:
        G.add_node(dn, label=name, type=ntype)
    return dn

# Add nodes
for d in domains:    add_node_from_obj(d, "Domain")
for ou in ous:       add_node_from_obj(ou, "OU")
for ct in containers:add_node_from_obj(ct, "Container")
for u in users:      add_node_from_obj(u, "User")
for g in groups:     add_node_from_obj(g, "Group")
for gp in gpos:      add_node_from_obj(gp, "GPO")
for c in computers:
    dn   = prop(c, "distinguishedname")
    name = prop(c, "name") or dn or "Computer"
    ntype = "DC" if dn and "OU=Domain Controllers" in dn else "Computer"
    if dn and dn not in G:
        G.add_node(dn, label=name, type=ntype)

# Containment edges (OU/Container hierarchy)
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

for coll in (domains, ous, containers, users, groups, computers):
    add_containment_edges(coll)

# --- Extra relationship edges ---

# Group memberships
for g in groups:
    g_dn = prop(g, "distinguishedname")
    members = (g.get("Properties") or {}).get("member", [])
    if isinstance(members, str):
        members = [members]
    for m in members:
        if g_dn and m in G:
            G.add_edge(g_dn, m, relationship="member")

# GPO links (OU <-> GPO via gplink)
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


# -------------------- filter by toggles --------------------
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

# -------------------- Summary KPIs --------------------
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

def kpi_card(col, icon, label, value, color, items, key_name="name"):
    with col:
        if st.button(
            f"{icon}\n{value}\n{label}",
            key=f"btn_{label}",
            use_container_width=True
        ):
            st.session_state.toggles[label] = not st.session_state.toggles[label]

        if st.session_state.toggles[label]:
            clean_list = [
                (obj.get("Properties") or {}).get(key_name, str(obj)) for obj in items
            ]

            # Build full HTML list with tooltips
            list_html = "".join(
                f"<div style='padding:2px 0; white-space:normal; word-wrap:break-word;' "
                f"title='{val}'>{val}</div>"
                for val in clean_list
            )

            st.markdown(
                f"""
                <div style='background:#1e293b;
                            color:#f1f5f9;
                            padding:10px;
                            border-radius:10px;
                            margin-top:8px;
                            text-align:left;
                            font-size:13px;
                            line-height:1.4;'>
                    {list_html}
                </div>
                """,
                unsafe_allow_html=True,
            )

col1, col2, col3, col4, col5, col6 = st.columns(6)

kpi_card(col1, "🌐", "Domains", len(domains), "#2563eb", domains)
kpi_card(col2, "👥", "Users", len(users), "#dc2626", users)
kpi_card(col3, "📂", "Groups", len(groups), "#f59e0b", groups)
kpi_card(col4, "🖥️", "Computers", len(computers), "#9333ea", computers)
kpi_card(col5, "🏢", "OUs", len(ous), "#16a34a", ous)
kpi_card(col6, "📜", "GPOs", len(gpos), "#ec4899", gpos)

# -------------------- Visualize Domain Graph --------------------
st.markdown("## 🌐 Domain Map")
st.caption("Drag nodes • Zoom with mouse wheel • Use sidebar filters to refine view")

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
        <span style='color:#94a3b8;'>DN:</span> {n[:100]}...
    </div>
    """

    if search_text and search_text.lower() in label.lower():
        color = {
            "background": "#facc15",
            "border": "#fef08a",
            "highlight": {"background": "#fde047", "border": "#facc15"}
        }
        size = 28
    else:
        base = color_map.get(ntype, "#94a3b8")
        color = {
            "background": base,
            "border": "#e2e8f0",
            "highlight": {"background": base, "border": "#f9fafb"}
        }
        size = 20

    net.add_node(
        n,
        label=label,
        title=title,
        color=color,
        size=size,
        borderWidth=2,
    )

for u, v, a in SG.edges(data=True):
    rel = a.get("relationship", "rel")
    net.add_edge(u, v, title=rel)

html_str = net.generate_html(notebook=False)
html(html_str, height=800, scrolling=True)

# -------------------- Risk Dashboard --------------------
st.title("⚠️ Risk Assessment")

reports, summaries = [], []

for cat_func, title in [
    (run_category1, "Password & Account Policy Checks"),
    (run_category2, "Optional Feature & Domain Configuration"),
    (run_category3, "Privileged Accounts & Group Membership"),
    (run_category4, "Administrator Account Restrictions – Workstations & Member Servers"),
    (run_category6, "Enterprise Admins Group Restrictions"),
    (run_category7, "Domain Controller & Service Health"),
    (run_category9, "Account & Audit Monitoring"),
    (run_category10, "Group Policy & Security Settings"),
    (run_category12, "Computer & Domain Management"),
    (run_category13, "Privilege & Trust Management"),
]:
    try:
        report_text, summary = cat_func(INPUT_DIR)
    except Exception as e:
        report_text, summary = f"Error in {title}: {e}", {"Category": title, "RiskScore": 0, "TotalFails": 0}
    reports.append((f"Category: {title}", report_text))
    summaries.append({"Category": title, **summary})

if summaries:
    df_summary = pd.DataFrame(summaries)

    EXPECTED_TOTAL_CHECKS = 120
    total_fails    = int(df_summary["TotalFails"].sum())
    total_unknowns = int(df_summary["Unknown"].sum()) if "Unknown" in df_summary else 0
    overall_risk_raw = float(df_summary["RiskScore"].sum())

    has_maxscore_col = "MaxScore" in df_summary.columns and df_summary["MaxScore"].fillna(0).sum() > 0
    if has_maxscore_col:
        total_max_score = float(df_summary["MaxScore"].fillna(0).sum())
        overall_score_pct = round((overall_risk_raw / total_max_score) * 100, 2)
        gauge_title = "Overall Weighted Risk (0–100%)"
    else:
        failure_rate = (total_fails + total_unknowns) / max(1, EXPECTED_TOTAL_CHECKS)
        overall_score_pct = round(failure_rate * 100, 2)
        gauge_title = "Overall Failure Rate (0–100%)"

    critical_row = df_summary.loc[df_summary["RiskScore"].idxmax()]
    critical_cat = str(critical_row["Category"])
    critical_score = float(critical_row["RiskScore"])


    st.subheader("📊 Global Overview Metrics")
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric("Total Checks", EXPECTED_TOTAL_CHECKS)
    kpi2.metric("Total Failures", total_fails)
    kpi3.metric("Overall Risk Score", f"{overall_score_pct}%")
    kpi4.metric("Most Critical Category", critical_cat, f"Score {int(critical_score)}")
 

# Sort categories by risk contribution
# --- What-if Scenarios ---
st.subheader("💡 What-if ")

df_sorted = df_summary.sort_values("RiskScore", ascending=False).head(3)
narratives = []
new_overall = overall_score_pct

for _, row in df_sorted.iterrows():
    cat = row["Category"]
    score = float(row["RiskScore"])
    fail_count = int(row["TotalFails"])
    high_count = int(row.get("High", 0))

    # Assume fixing a category reduces overall risk by its contribution %
    if has_maxscore_col:
        total_max_score = float(df_summary["MaxScore"].fillna(0).sum())
        reduction_pct = round((score / total_max_score) * 100, 2)
    else:
        reduction_pct = round((fail_count / EXPECTED_TOTAL_CHECKS) * 100, 2)

    new_overall = max(0, round(new_overall - reduction_pct, 2))

    narrative = (
        f"- **{cat}** had {fail_count} failed checks "
        f"({high_count} high severity). If remediated, "
        f"the overall risk score would drop by ~{reduction_pct}% "
        f"to **{new_overall}%**."
    )
    narratives.append(narrative)

st.markdown(
    "These scenarios simulate the direct impact of remediating the top 3 most critical misconfigurations:\n\n"
    + "\n".join(narratives)
)

st.info("📌 Use this to prioritise remediation — the biggest drops in risk score "
        "show where fixes will have the greatest effect.")

st.markdown("---")


st.subheader("🕸️ Category Counterfeit")
radar_fig = go.Figure()
radar_fig.add_trace(go.Scatterpolar(
    r=df_summary["RiskScore"],
    theta=df_summary["Category"],
    fill="toself",
    name="Risk Score"
))
max_r = max(10, float(df_summary["RiskScore"].max()) + 20)
radar_fig.update_layout(
    polar=dict(radialaxis=dict(visible=True, range=[0, max_r])),
    showlegend=False,
    title="Risk Score Comparison by Category"
)
st.plotly_chart(radar_fig, use_container_width=True, key="radar_chart_main")

df_melt = df_summary.melt(
    id_vars="Category", value_vars=["High", "Medium", "Low"],
    var_name="Severity", value_name="Count"
)
st.subheader("📊 Severity Breakdown")
fig = px.bar(
    df_melt, x="Category", y="Count", color="Severity",
    barmode="group", text="Count", title="Failed Checks by Category & Severity"
)
fig.update_layout(xaxis_tickangle=-30)
st.plotly_chart(fig, use_container_width=True, key="severity_chart_main")

st.subheader("📈 Threat Posture Briefing")
st.dataframe(
    df_summary[["Category", "High", "Medium", "Low", "TotalFails", "RiskScore"]],
    use_container_width=True,
    key="threat_posture_table_main"
)


st.subheader("""📂 Detailed Reports 
 Here’s where the detective work pays off! 🕵️‍♂️
Each expandable report uncovers the behind-the-scenes checks that shaped your risk score – from weak passwords and oversized admin groups to those sneaky GPO mischiefs. 
Dive in if for the details of what’s really happening in your Domain, or just peek when you’re ready to face the truth.""")

for title, text in reports:
    with st.expander(title, expanded=False):
        st.code(text, language="text")

