# app.py  — self-healing imports + correct data path from Objects/Code -> Objects/Domain Data
import json
import sys, subprocess, importlib
from pathlib import Path
from typing import Dict, Any, List

import streamlit as st
from streamlit.components.v1 import html
import pandas as pd

def ensure_pkg(pip_name: str, import_name: str | None = None, version: str | None = None):
    """Import a package; if missing, pip install it and import again."""
    mod_name = import_name or pip_name
    try:
        return importlib.import_module(mod_name)
    except Exception:
        try:
            pkg_spec = f"{pip_name}=={version}" if version else pip_name
            with st.spinner(f"Installing {pkg_spec}..."):
                subprocess.check_call([sys.executable, "-m", "pip", "install", pkg_spec])
            return importlib.import_module(mod_name)
        except Exception as e:
            st.error(f"Failed to import or install {pip_name}: {e}")
            raise

# Ensure critical deps (works even if requirements.txt wasn't picked up)
nx = ensure_pkg("networkx")                           # import networkx as nx
px = ensure_pkg("plotly")                              # plotly base
_ = ensure_pkg("plotly-express", "plotly.express")     # ensure plotly.express is present
_ = ensure_pkg("plotly", "plotly.graph_objects")       # ensure plotly.graph_objects is present

# Try pyvis (optional)
try:
    pyvis_mod = ensure_pkg("pyvis")
    from pyvis.network import Network
    _PYVIS_AVAILABLE = True
except Exception:
    _PYVIS_AVAILABLE = False

import plotly.express as px
import plotly.graph_objects as go
import networkx as nx  # type: ignore

# ---- Import your category runners (must be importable from this folder)
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

# ---- CONFIG: resolve data at trustscope/Objects/Domain Data/ from Objects/Code/app.py
OBJECTS_DIR = Path(__file__).resolve().parents[1]   # .../Objects
CANDIDATE_DIRS = [
    OBJECTS_DIR / "Domain Data",   # canonical
    OBJECTS_DIR / "DomainData",    # fallback
    OBJECTS_DIR / "domain data",   # fallback
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

st.set_page_config(page_title="Trust Scope Risk Assessment", layout="wide")

st.markdown(
    """
    # 💂🏻‍♂️ TrustScope – Trust into verified security  

    Welcome to the **TrustScope Dashboard** – your **X-ray vision for Active Directory**.  
    We scan **domains, users, groups, OUs, and trust paths** inside `nexora.local`.

    What you’ll find here:  
    - 🌐 **Domain Map** – Visualize AD relationships  
    - ⚠️ **Risk Scores** – Quantified misconfigurations  
    - 📊 **Insights** – Identify critical areas  
    - 💡 **What-if Scenarios** – Simulate remediation impact  
    """
)

# -------------------- Load domain name --------------------
domains_file = INPUT_DIR / "nexora.local_domains.json"
domain_name = "Unknown Domain"
if domains_file.exists():
    with open(domains_file, "r", encoding="utf-8") as f:
        domains_data = json.load(f)
    if isinstance(domains_data, dict) and "data" in domains_data:
        domains_data = domains_data["data"]
    if isinstance(domains_data, list) and len(domains_data) > 0:
        domain_name = (
            domains_data[0].get("Properties", {}).get("name")
            or domains_data[0].get("Properties", {}).get("dnsroot")
            or domain_name
        )
st.title(f"DOMAIN – {domain_name.upper()}")

# -------------------- Helper functions --------------------
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

# -------------------- Sidebar --------------------
st.sidebar.header("Configuration")

# Risk meter (placeholder before data)
overall_score_pct = 0
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

# Graph layout options
st.sidebar.subheader("Graph Layout")
use_physics  = st.sidebar.checkbox("Free-Form", True)
hierarchical = st.sidebar.checkbox("Hierarchical", False)
level_sep    = st.sidebar.slider("Level separation", 100, 500, 220)
node_dist    = st.sidebar.slider("Node distance", 50, 400, 180)
search_text  = st.sidebar.text_input("Highlight nodes containing...", "")
build_btn    = st.sidebar.button("Build / Refresh graph")

# -------------------- Load all JSON data --------------------
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
computers, domains, gpos, containers = (
    data["computers"], data["domains"], data["gpos"], data["containers"]
)

# -------------------- Build the graph --------------------
if not _NX_AVAILABLE:
    st.error("⚠️ `networkx` is not installed. Please confirm `requirements.txt` is at the repo root and includes `networkx>=3.3`.")
else:
    G = nx.DiGraph()

    def add_node_from_obj(obj, ntype: str):
        dn = prop(obj, "distinguishedname")
        name = prop(obj, "name") or dn or ntype
        if not dn:
            return None
        if dn not in G:
            G.add_node(dn, label=name, type=ntype)
        return dn

    for d in domains: add_node_from_obj(d, "Domain")
    for ou in ous: add_node_from_obj(ou, "OU")
    for ct in containers: add_node_from_obj(ct, "Container")
    for u in users: add_node_from_obj(u, "User")
    for g in groups: add_node_from_obj(g, "Group")
    for gp in gpos: add_node_from_obj(gp, "GPO")
    for c in computers:
        dn = prop(c, "distinguishedname")
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

    # Filter toggles
    allowed_types = set()
    if show_domain: allowed_types.add("Domain")
    if show_ou: allowed_types.add("OU")
    if show_container: allowed_types.add("Container")
    if show_user: allowed_types.add("User")
    if show_group: allowed_types.add("Group")
    if show_computer: allowed_types.update(["Computer", "DC"])
    if show_gpo: allowed_types.add("GPO")

    nodes_to_keep = [n for n, a in G.nodes(data=True) if a.get("type") in allowed_types]
    SG = G.subgraph(nodes_to_keep).copy()

    # -------------------- Visualize Domain Graph --------------------
    # -------------------- Visualize Domain Graph --------------------
st.markdown("## 🌐 Domain Map")
st.caption("Drag nodes • Zoom with mouse wheel • Use sidebar filters to refine view")

if _PYVIS_AVAILABLE:
    net = Network(
        height="780px",
        width="100%",
        bgcolor="#0d1117",
        font_color="#e6edf3",
        directed=True,
    )
    color_map = {
        "Domain": "#3b82f6", "OU": "#22c55e", "Container": "#14b8a6",
        "User": "#ef4444", "Group": "#f59e0b", "Computer": "#8b5cf6",
        "DC": "#a855f7", "GPO": "#ec4899",
    }
    for n, a in SG.nodes(data=True):
        ntype = a.get("type", "Node")
        label = a.get("label", n)
        size = 25 if (search_text and search_text.lower() in label.lower()) else 18
        net.add_node(n, label=label, color=color_map.get(ntype, "#94a3b8"), size=size)
    for u, v, a in SG.edges(data=True):
        net.add_edge(u, v, title=a.get("relationship", "rel"))
    net.show_buttons(filter_=["physics"])
    html(net.generate_html(notebook=False), height=800, scrolling=True)
else:
    st.warning("PyVis not available. Add `pyvis` to requirements.txt for interactive graph. Showing edge list instead.")
    import pandas as pd
    st.dataframe(
        pd.DataFrame(
            [{"from": u, "to": v, "rel": a.get("relationship", "rel")} for u, v, a in SG.edges(data=True)]
        ),
        use_container_width=True,
    )


# -------------------- Risk Analysis --------------------
st.markdown("---")
st.title("⚠️ Risk Assessment Dashboard")

# Run category analyses
reports, summaries = [], []
for cat_func, title in [
    (run_category1, "Password & Account Policy Checks"),
    (run_category2, "Optional Feature & Domain Configuration"),
    (run_category3, "Privileged Accounts & Group Membership"),
    (run_category4, "Administrator Account Restrictions"),
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
    reports.append((title, report_text))
    summaries.append({"Category": title, **summary})

if summaries:
    df_summary = pd.DataFrame(summaries)
    st.dataframe(df_summary, use_container_width=True)
else:
    st.warning("No summary data found — check your JSON files in 'Objects/Domain Data' folder.")

