# app.py
import json
from pathlib import Path
from typing import Dict, Any, List

import streamlit as st
from streamlit.components.v1 import html
import pandas as pd
import networkx as nx
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

st.markdown("""
# 💂🏻‍♂️ TrustScope – Trust into verified security  
Welcome to the **TrustScope Dashboard** – your **X-ray vision for Active Directory**.
""")

# -------------------- helpers --------------------
def load_json_list(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        obj = json.load(f)
    if isinstance(obj, dict):
        if "data" in obj and isinstance(obj["data"], list):
            return obj["data"]
        if "results" in obj and isinstance(obj["results"], list):
            return obj["results"]
    if isinstance(obj, list):
        return obj
    return []

def prop(o: Dict[str, Any], key: str, default=None):
    return (o.get("Properties") or {}).get(key, default)

def dn_parent(dn: str) -> str:
    if not dn or "," not in dn:
        return ""
    return dn.split(",", 1)[1]

# -------------------- Load Data --------------------
data_dir = Path(INPUT_DIR)
data = {}
for k, fname in FILES.items():
    data[k] = load_json_list(data_dir / fname)

domains, ous, users, groups, computers, gpos, containers = \
    data["domains"], data["ous"], data["users"], data["groups"], data["computers"], data["gpos"], data["containers"]

# Domain name for header
domain_name = "Unknown Domain"
if domains:
    domain_name = prop(domains[0], "name") or prop(domains[0], "dnsroot") or domain_name
st.title(f"DOMAIN – {domain_name.upper()}")

# -------------------- Build Graph --------------------
G = nx.DiGraph()

def add_node_from_obj(obj, ntype: str):
    dn = prop(obj, "distinguishedname")
    # Domain fallback
    if not dn and ntype == "Domain":
        dn = prop(obj, "dnsroot") or prop(obj, "name")
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
    dn = prop(c, "distinguishedname")
    name = prop(c, "name") or dn or "Computer"
    ntype = "DC" if dn and "OU=Domain Controllers" in dn else "Computer"
    if dn and dn not in G:
        G.add_node(dn, label=name, type=ntype)

# Add containment edges
def add_containment_edges(coll):
    for obj in coll:
        child_dn = prop(obj, "distinguishedname")
        if not child_dn or child_dn not in G:
            continue
        parent_dn = dn_parent(child_dn)
        if parent_dn and parent_dn in G:
            G.add_edge(parent_dn, child_dn, relationship="contains")

for coll in (domains, ous, containers, users, groups, computers):
    add_containment_edges(coll)

# Add group memberships
for g in groups:
    g_dn = prop(g, "distinguishedname")
    members = (g.get("Properties") or {}).get("member", [])
    if isinstance(members, str):
        members = [members]
    for m in members:
        if g_dn and m in G:
            G.add_edge(g_dn, m, relationship="member")

# Add GPO links
for ou in ous:
    ou_dn = prop(ou, "distinguishedname")
    gplink = (ou.get("Properties") or {}).get("gplink", "")
    if gplink and ou_dn:
        for gp in gpos:
            gp_dn = prop(gp, "distinguishedname")
            gp_name = prop(gp, "name")
            if gp_name and gp_name in gplink and gp_dn in G:
                G.add_edge(ou_dn, gp_dn, relationship="gplink")

# Add domain trusts safely
domain_names = {prop(d, "name"): prop(d, "distinguishedname") for d in domains}
for d in domains:
    d_dn = prop(d, "distinguishedname") or prop(d, "dnsroot")
    trust_partner = (d.get("Properties") or {}).get("trustpartner")
    if d_dn and trust_partner and trust_partner in domain_names:
        G.add_edge(d_dn, domain_names[trust_partner], relationship="trust")

# -------------------- Sidebar Toggles --------------------
st.sidebar.header("Node Types")
show_domain    = st.sidebar.checkbox("Domain", True)
show_ou        = st.sidebar.checkbox("OU", True)
show_container = st.sidebar.checkbox("Container", False)
show_user      = st.sidebar.checkbox("User", False)
show_group     = st.sidebar.checkbox("Group", False)
show_computer  = st.sidebar.checkbox("Computer", True)
show_gpo       = st.sidebar.checkbox("GPO", True)

st.sidebar.subheader("Graph Layout")
use_physics = st.sidebar.checkbox("Free-Form", True)
hierarchical = st.sidebar.checkbox("Hierarchical", False)
level_sep = st.sidebar.slider("Level separation", 100, 500, 220)
node_dist = st.sidebar.slider("Node distance", 50, 400, 180)
search_text = st.sidebar.text_input("Highlight nodes containing...", "")

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

# -------------------- KPIs --------------------
st.markdown("## 📊 Overview")

def kpi_card(col, icon, label, value, items, key_name="name"):
    with col:
        st.metric(label=f"{icon} {label}", value=value)

col1, col2, col3, col4, col5, col6 = st.columns(6)
kpi_card(col1, "🌐", "Domains", len(domains), domains)
kpi_card(col2, "👥", "Users", len(users), users)
kpi_card(col3, "📂", "Groups", len(groups), groups)
kpi_card(col4, "🖥️", "Computers", len(computers), computers)
kpi_card(col5, "🏢", "OUs", len(ous), ous)
kpi_card(col6, "📜", "GPOs", len(gpos), gpos)

# -------------------- Domain Graph --------------------
st.markdown("## 🌐 Domain Map")
st.caption("Drag nodes • Zoom • Use sidebar filters")

net = Network(height="780px", width="100%", bgcolor="#0d1117", font_color="#e6edf3", directed=True)
color_map = {
    "Domain": "#3b82f6",
    "OU": "#22c55e",
    "Container": "#14b8a6",
    "User": "#ef4444",
    "Group": "#f59e0b",
    "Computer": "#8b5cf6",
    "DC": "#a855f7",
    "GPO": "#ec4899",
}

for n, a in SG.nodes(data=True):
    ntype = a.get("type", "Node")
    label = a.get("label", n)
    base = color_map.get(ntype, "#94a3b8")
    color = {"background": base, "border": "#e2e8f0", "highlight": {"background": base, "border": "#f9fafb"}}
    size = 28 if search_text.lower() in label.lower() else 20
    net.add_node(n, label=label, title=label, color=color, size=size)

for u, v, a in SG.edges(data=True):
    net.add_edge(u, v, title=a.get("relationship", ""))

html_str = net.generate_html(notebook=False)
html(html_str, height=800, scrolling=True)

# -------------------- Risk Dashboard --------------------
st.title("⚠️ Risk Assessment")
summaries = []

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
        _, summary = cat_func(INPUT_DIR)
    except Exception:
        summary = {"Category": title, "RiskScore": 0, "TotalFails": 0}
    summaries.append(summary)

if summaries:
    df_summary = pd.DataFrame(summaries)

    # Ensure severity columns exist
    for col in ["High", "Medium", "Low"]:
        if col not in df_summary.columns:
            df_summary[col] = 0
    df_summary[["High", "Medium", "Low"]] = df_summary[["High", "Medium", "Low"]].fillna(0).astype(int)

    # Severity Breakdown
    df_melt = df_summary.melt(id_vars="Category", value_vars=["High", "Medium", "Low"], var_name="Severity", value_name="Count")
    st.subheader("📊 Severity Breakdown")
    fig = px.bar(df_melt, x="Category", y="Count", color="Severity", barmode="group", text="Count")
    fig.update_layout(xaxis_tickangle=-30)
    st.plotly_chart(fig, use_container_width=True)

st.info("✅ Dashboard loaded successfully with corrected domains, graph, and severity charts.")
