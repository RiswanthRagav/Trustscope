#!/usr/bin/env python3
import os, json
from typing import Dict, List, Any
from collections import Counter, defaultdict

# ========= CONFIG =========
INPUT_DIR = r"C:\Users\LENOVO\OneDrive\Desktop\dissertation\Nexora.local"

USERS_FILE     = "nexora.local_users.json"
GROUPS_FILE    = "nexora.local_groups.json"
COMPUTERS_FILE = "nexora.local_computers.json"

PRINT_MAX_DETAILS = 10

# ========= Risk model (Category 6) =========
CHECK_META = {
    "only_admin_in_ea":   {"title": "Only Administrator allowed in Enterprise Admins",   "severity": "High", "score": 100},
    "deny_network":       {"title": "Deny access from network not enabled",              "severity": "High", "score": 100},
    "deny_service":       {"title": "Deny log on as service not enabled",                "severity": "High", "score": 100},
    "deny_locally":       {"title": "Deny log on locally not enabled",                   "severity": "High", "score": 100},
    "deny_rdp":           {"title": "Deny RDP not enabled",                              "severity": "High", "score": 100},
    "deny_batch":         {"title": "Deny log on as batch job not enabled",              "severity": "High", "score": 64},
}

# ========= helpers =========
def load_json(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if isinstance(data, dict) and "data" in data:
        return data["data"]
    return data if isinstance(data, list) else []

def prop(d: Dict[str, Any], key: str, default=None):
    return (d.get("Properties") or {}).get(key, default)

# ========= Checks =========
def check_only_admin_in_enterprise_admins(users, groups):
    group = next((g for g in groups if "enterprise admins" in prop(g,"name","").lower()), None)
    admin = next((u for u in users if prop(u,"name","").lower()=="administrator@nexora.local"), None)

    if not group or not admin:
        return ("FAIL", [{"Object":"Domain","Detail":"Enterprise Admins group or Administrator not found"}], True)

    admin_sid = admin.get("ObjectIdentifier")
    members = [m.get("ObjectIdentifier") for m in group.get("Members",[])]
    extra = [sid for sid in members if sid != admin_sid]

    if extra:
        return ("FAIL", [{"Object":"Enterprise Admins","Detail":f"Extra members={extra}"}], False)
    return ("PASS", [], False)

def check_deny_rights(users, groups, computers, right_name, key):
    group = next((g for g in groups if "enterprise admins" in prop(g,"name","").lower()), None)
    if not group:
        return ("FAIL", [{"Object":"Domain","Detail":"Enterprise Admins group not found"}], True)

    group_sid = group.get("ObjectIdentifier")
    issues=[]
    for comp in computers:
        found = False
        for ace in comp.get("Aces",[]):
            if (ace.get("PrincipalSID")==group_sid and 
                ace.get("RightName")==right_name and 
                ace.get("AceType","").lower()=="deny"):
                found = True
                break
        if not found:
            issues.append({"Object":prop(comp,"name"),"Detail":f"Missing={right_name}"})
    if issues:
        return ("FAIL", issues, False)
    return ("PASS", [], False)

# ========= Global CHECKS =========
def build_checks(users, groups, computers):
    return [
        ("only_admin_in_ea", lambda: check_only_admin_in_enterprise_admins(users,groups)),
        ("deny_network",     lambda: check_deny_rights(users,groups,computers,"Deny access to this computer from the network","deny_network")),
        ("deny_service",     lambda: check_deny_rights(users,groups,computers,"Deny log on as a service","deny_service")),
        ("deny_locally",     lambda: check_deny_rights(users,groups,computers,"Deny log on locally","deny_locally")),
        ("deny_rdp",         lambda: check_deny_rights(users,groups,computers,"Deny log on through Remote Desktop Services","deny_rdp")),
        ("deny_batch",       lambda: check_deny_rights(users,groups,computers,"Deny log on as a batch job","deny_batch")),
    ]

# ========= Runtime entry =========
def run_category6(input_dir: str):
    users = load_json(os.path.join(input_dir, USERS_FILE))
    groups = load_json(os.path.join(input_dir, GROUPS_FILE))
    computers = load_json(os.path.join(input_dir, COMPUTERS_FILE))
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
    }
    return report_text, summary

if __name__=="__main__":
    txt,summary=run_category6(INPUT_DIR)
    print(txt)
    print("\nSummary:",summary)
