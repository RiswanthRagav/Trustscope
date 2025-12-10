#!/usr/bin/env python3
# app.py — Streamlit Cloud–ready (repo-relative data path), category analysis removed
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

# ==================== CONFIG: DATA PATH ====================
OBJECTS_DIR = Path(__file__).resolve().parents[1]
CANDIDATE_DIRS = [
    OBJECTS_DIR / "Domain Data",
    OBJECTS_DIR / "DomainData",
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
st.set_page_config(page_title="Trust Scope Visualiser", layout="wide")

st.markdown(
    """
    # 💂🏻‍♂️ TrustScope – Trust Visualisation Only  

    This interface provides a graphical map of your **Active Directory structure**.  
    All category-based risk checks have been disabled for this version.

    Features included:
    - 🌐 **Domain Map** – interactive AD visualisation  
    - 📊 **Overview Cards** – counts of objects  
    - 🎛️ **Node Filters & Layout Controls**
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
                f"<div style='padding:2px 0; white-space:normal;'>{val}</div>" 
                for val in clean_list
            )
            st.markdown(
                f"""
                <div style='background:#1e293b;color:#f1f5f9;padding:10px;border-radius:10px;margin-top:8px;'>
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
    dn = prop(c, "distinguishedname")
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

# GPO links
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

# Filter
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

# ==================== GRAPH VISUALISATION ====================
st.markdown("## 🌐 Domain Map")
st.caption("Drag, zoom, filter nodes from sidebar.")

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
        "edges": {"arrows": {"to": {"enabled": True}}},
        "physics": {"enabled": use_physics, "barnesHut": {"springLength": node_dist}},
        "layout": {"hierarchical": {"enabled": hierarchical, "levelSeparation": level_sep, "direction": "LR"}},
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
        label = a.get("label", n)
        ntype = a.get("type")
        base = color_map.get(ntype, "#94a3b8")
        net.add_node(n, label=label, color=base)

    for u, v, a in SG.edges(data=True):
        net.add_edge(u, v, title=a.get("relationship", "rel"))

    html(net.generate_html(notebook=False), height=800, scrolling=True)

else:
    st.warning("PyVis not installed. Showing edges:")
    st.dataframe(
        pd.DataFrame([{"from": u, "to": v, "rel": a.get("relationship")} for u, v, a in SG.edges(data=True)])
    )
