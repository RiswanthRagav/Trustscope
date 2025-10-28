#!/usr/bin/env python3
# cat_6.py — Enterprise Admins Group Restrictions (auto path + import-safe)
from __future__ import annotations

import os, json
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from collections import Counter, defaultdict

# ========= Risk model (Category 6) =========
CHECK_META = {
    "only_admin_in_ea":   {"title": "Only Administrator allowed in Enterprise Admins",   "severity": "High", "score": 100},
    "deny_network":       {"title": "Deny access from network not enabled",              "severity": "High", "score": 100},
    "deny_service":       {"title": "Deny log on as service not enabled",                "severity": "High", "score": 100},
    "deny_locally":       {"title": "Deny log on locally not enabled",                   "severity": "High", "score": 100},
    "deny_rdp":           {"title": "Deny RDP not enabled",                              "severity": "High", "score": 100},
    "deny_batch":         {"title": "Deny log on as a batch job not enabled",            "severity": "High", "score": 64},
}

# Filenames we expect in the data directory
USERS_FILE     = "nexora.local_users.json"
GROUPS_FILE    = "nexora.local_groups.json"
COMPUTERS_FILE = "nexora.local_computers.json"

PRINT_MAX_DETAILS = 10

# ========= path helpers (no top-level I/O) =========
def _resolve_input_dir_prefer_domain_data(base_hint: Optional[str | Path]) -> Path:
    """
    Resolve the folder that contains your exported JSON dumps.
    Priority:
      1) base_hint if it exists
      2) this file's .../Objects/Domain Data (and fallbacks)
      3) .../Objects/data
      4) .../Objects
    """
    if base_hint:
        p = Path(base_hint)
        if p.is_dir():
            return p
        if p.is_file():
            return p.parent

    code_dir = Path(__file__).resolve().parent   # .../Objects/Code
    objects_dir = code_dir.parent                # .../Objects

    candidates = [
        objects_dir / "Domain Data",
        objects_dir / "DomainData",
        objects_dir / "domain data",
        objects_dir / "data",
        objects_dir,
    ]
    for c in candidates:
        if c.exists() and c.is_dir():
            return c
    return objects_dir

# ========= helpers =========
def _load_json_list(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
        return data["data"]
    return data if isinstance(data, list) else []

def prop(d: Dict[str, Any] | None, key: str, default=None):
    if not isinstance(d, dict):
        return default
    return (d.get("Properties") or {}).get(key, default)

# ========= Checks =========
def check_only_admin_in_enterprise_admins(users: List[Dict[str, Any]], groups: List[Dict[str, Any]]):
    # find Enterprise Admins group by name (robust to case)
    group = next(
        (g for g in groups if "enterprise admins" in (prop(g, "name", "") or "").lower()
                           or "enterprise admins" in (prop(g, "samaccountname", "") or "").lower()),
        None
    )
    # find built-in Administrator user (try SAM then UPN/name)
    admin = next(
        (
            u for u in users
            if (prop(u, "samaccountname", "") or "").lower() == "administrator"
            or (prop(u, "userprincipalname", "") or "").lower().startswith("administrator@")
            or (prop(u, "name", "") or "").lower().startswith("administrator@")
            or (prop(u, "name", "") or "").lower() == "administrator"
        ),
        None
    )

    if not group or not admin:
        return ("FAIL", [{"Object":"Directory","Detail":"Enterprise Admins group or Administrator not found"}], True)

    admin_sid = admin.get("ObjectIdentifier")
    members = [m.get("ObjectIdentifier") for m in (group.get("Members") or []) if isinstance(m, dict)]
    extra = [sid for sid in members if sid != admin_sid]

    if extra:
        return ("FAIL", [{"Object":"Enterprise Admins","Detail":f"Extra members present (SIDs)={extra}"}], False)
    return ("PASS", [], False)

def check_deny_rights(users, groups, computers, right_display_name: str, key: str):
    """
    We expect the Enterprise Admins SID to appear in an ACE on each computer
    with AceType='deny' and RightName=<right_display_name>.
    Note: This relies on your export including a per-computer 'Aces' structure.
    """
    group = next(
        (g for g in groups if "enterprise admins" in (prop(g, "name", "") or "").lower()
                           or "enterprise admins" in (prop(g, "samaccountname", "") or "").lower()),
        None
    )
    if not group:
        return ("FAIL", [{"Object":"Directory","Detail":"Enterprise Admins group not found"}], True)

    group_sid = group.get("ObjectIdentifier")
    issues=[]
    for comp in computers:
        comp_name = prop(comp, "name", "<computer>")
        found = False
        for ace in comp.get("Aces", []) or []:
            if not isinstance(ace, dict):
                continue
            if (
                ace.get("PrincipalSID") == group_sid and
                (ace.get("RightName") or "").strip().lower() == right_display_name.strip().lower() and
                (ace.get("AceType", "") or "").lower() == "deny"
            ):
                found = True
                break
        if not found:
            issues.append({"Object": comp_name, "Detail": f"Missing deny right: {right_display_name}"})
    if issues:
        return ("FAIL", issues, False)
    return ("PASS", [], False)

# ========= Global CHECKS builder =========
def build_checks(users, groups, computers):
    return [
        ("only_admin_in_ea", lambda: check_only_admin_in_enterprise_admins(users, groups)),
        ("deny_network",     lambda: check_deny_rights(users, groups, computers, "Deny access to this computer from the network", "deny_network")),
        ("deny_service",     lambda: check_deny_rights(users, groups, computers, "Deny log on as a service", "deny_service")),
        ("deny_locally",     lambda: check_deny_rights(users, groups, computers, "Deny log on locally", "deny_locally")),
        ("deny_rdp",         lambda: check_deny_rights(users, groups, computers, "Deny log on through Remote Desktop Services", "deny_rdp")),
        ("deny_batch",       lambda: check_deny_rights(users, groups, computers, "Deny log on as a batch job", "deny_batch")),
    ]

# ========= Runtime entry (public API) =========
def run_category6(input_dir: str | Path | None):
    """
    Enterprise Admins Group Restrictions
    - Auto-resolves `input_dir` to .../Objects/Domain Data (with fallbacks) if None/invalid
    - Loads users/groups/computers JSON from that folder
    Returns: (report_text, summary_dict)
    """
    base = _resolve_input_dir_prefer_domain_data(input_dir)

    users      = _load_json_list(base / USERS_FILE)
    groups     = _load_json_list(base / GROUPS_FILE)
    computers  = _load_json_list(base / COMPUTERS_FILE)

    CHECKS = build_checks(users, groups, computers)

    results=[]
    failed_by_sev={"High":[],"Medium":[],"Low":[]}
    unknown_items=[]

    for key,fn in CHECKS:
        status,details,is_unknown=fn()
        meta=CHECK_META[key]
        rec={
            "key":key,"title":meta["title"],
            "severity":meta["severity"],
            "score":meta["score"],
            "status":status,
            "fail_items":len(details),
            "details":details,
        }
        results.append(rec)
        if status=="FAIL":
            failed_by_sev[meta["severity"]].append(rec)
        if is_unknown:
            unknown_items.append(rec)

    total=len(results)
    failed_total=sum(1 for r in results if r["status"]=="FAIL")
    unknown_total=len(unknown_items)

    category_risk_total=sum(r["score"] for r in results if r["status"]=="FAIL")
    risk_by_severity=defaultdict(int)
    for r in results:
        if r["status"]=="FAIL":
            risk_by_severity[r["severity"]]+=r["score"]

    # ====== Console-like report text ======
    lines=[]
    lines.append("=== Category 6: Enterprise Admins Group Restrictions (Runtime Report) ===")
    lines.append(f"Checks evaluated: {total}")
    lines.append(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    lines.append(f"Category 6 Total Risk Score: {category_risk_total}")
    lines.append(f"  - High risk points:   {risk_by_severity['High']}")
    lines.append(f"  - Medium risk points: {risk_by_severity['Medium']}")
    lines.append(f"  - Low risk points:    {risk_by_severity['Low']}\n")
    lines.append("Failures by severity:")
    lines.append(f"  High  : {len(failed_by_sev['High'])}")
    lines.append(f"  Medium: {len(failed_by_sev['Medium'])}")
    lines.append(f"  Low   : {len(failed_by_sev['Low'])}\n")

    for sev in ["High","Medium","Low"]:
        items=failed_by_sev[sev]
        if not items:
            lines.append(f"{sev}: (none)")
            continue
        lines.append(f"{sev}:")
        for r in items:
            lines.append(f"  - {r['title']}  (Score {r['score']})  -> {r['fail_items']} item(s)")
            for d in r["details"][:PRINT_MAX_DETAILS]:
                lines.append(f"      • {d.get('Object')} - {d.get('Detail')}")
        lines.append("")

    lines.append("Non-passing (UNKNOWN) checks:")
    for r in unknown_items:
        lines.append(f"  - {r['title']} ({r['severity']}, Score {r['score']}) -> needs additional data")

    report_text="\n".join(lines)

    summary={
        "High":len(failed_by_sev["High"]),
        "Medium":len(failed_by_sev["Medium"]),
        "Low":len(failed_by_sev["Low"]),
        "TotalFails":failed_total,
        "RiskScore":category_risk_total,
        "Unknown":unknown_total,
    }
    return report_text, summary

# Optional CLI test
if __name__=="__main__":
    txt, summary = run_category6(None)  # auto-resolve data folder
    print(txt)
    print("\nSummary:", summary)
