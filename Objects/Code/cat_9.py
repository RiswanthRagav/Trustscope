#!/usr/bin/env python3
import os, json
from typing import Any, Dict, List
from datetime import datetime
from collections import Counter, defaultdict

# ========= CONFIG =========
INPUT_DIR = r"C:\Users\LENOVO\OneDrive\Desktop\dissertation\Nexora.local"
USERS_FILE = "nexora.local_users.json"
GPO_FILE   = "nexora.local_gpos.json"
AUDIT_FILE = None   # optional future JSON

PRINT_MAX_DETAILS = 10
INACTIVITY_DAYS_THRESHOLD = 90

# ========= Risk model (Category 9) =========
CHECK_META = {
    # High risks
    "audit_policy_misconfig":   {"title": "Audit policy misconfigured",              "severity": "High",   "score": 32},
    "audit_mgmt_issues":        {"title": "Audit & policy management issues",        "severity": "High",   "score": 32},
    "default_pw_policy_bad":    {"title": "Default password policy misconfig",       "severity": "High",   "score": 32},
    "weak_pw_gpo":              {"title": "Weak GPO with password settings",         "severity": "High",   "score": 32},
    # Medium risks
    "inactive_accounts":        {"title": f"Inactive accounts > {INACTIVITY_DAYS_THRESHOLD} days", "severity": "Medium", "score": 24},
    "gpo_misconfig_ou":         {"title": "GPO misconfig by OU",                     "severity": "Medium", "score": 18},
    # Low risks
    "locked_accounts":          {"title": "Locked accounts",                         "severity": "Low",    "score": 12},
}

# ========= helpers =========
def load_json(path: str) -> List[Dict[str, Any]]:
    with open(path,"r",encoding="utf-8-sig") as f:
        data=json.load(f)
    if isinstance(data,dict) and "data" in data: return data["data"]
    return data if isinstance(data,list) else []

def prop(d: Dict[str,Any], key: str, default=None):
    return (d.get("Properties") or {}).get(key,default)

# ========= checks =========
def check_locked_accounts(users):
    bad=[{"Object":prop(u,"name","<user>"),"Detail":"lockedout=True"}
         for u in users if prop(u,"lockedout",False)]
    return ("FAIL",bad,False) if bad else ("PASS",[],False)

def check_inactive_accounts(users):
    now_ts=datetime.now().timestamp()
    threshold=now_ts - (INACTIVITY_DAYS_THRESHOLD*24*3600)
    bad=[]
    for u in users:
        ts=prop(u,"lastlogontimestamp",0)
        if ts and ts<threshold:
            bad.append({"Object":prop(u,"name","<user>"),"Detail":f"Inactive > {INACTIVITY_DAYS_THRESHOLD} days"})
    return ("FAIL",bad,False) if bad else ("PASS",[],False)

def check_audit_policy(audit_data):
    if audit_data is None:
        return ("UNKNOWN",[],True)
    if audit_data.get("misconfigured"):
        return ("FAIL",[{"Object":"AuditPolicy","Detail":"Audit policy misconfigured"}],False)
    return ("PASS",[],False)

def check_default_pw_policy(gpos):
    bad=[]
    found=False
    for g in gpos:
        name=prop(g,"name","").lower()
        if "password" in name or "pwd" in name:
            found=True
            if "weak" in name:
                bad.append({"Object":prop(g,"name"),"Detail":"Weak password GPO"})
    if not found: return ("UNKNOWN",[],True)
    return ("FAIL",bad,False) if bad else ("PASS",[],False)

def check_gpo_misconfig_ou(gpos):
    bad=[]
    for g in gpos:
        ou=prop(g,"distinguishedname","")
        if "ou=" in ou.lower() and "misconfig" in prop(g,"name","").lower():
            bad.append({"Object":ou,"Detail":f"GPO {prop(g,'name')} flagged as misconfig"})
    return ("FAIL",bad,False) if bad else ("PASS",[],False)

# ========= MAIN (console run) =========
def main():
    users=load_json(os.path.join(INPUT_DIR,USERS_FILE))
    gpos=load_json(os.path.join(INPUT_DIR,GPO_FILE))
    audit_data=None
    if AUDIT_FILE and os.path.exists(AUDIT_FILE):
        with open(AUDIT_FILE,"r",encoding="utf-8-sig") as f:
            audit_data=json.load(f)

    CHECKS=[
        ("locked_accounts",       lambda: check_locked_accounts(users)),
        ("inactive_accounts",     lambda: check_inactive_accounts(users)),
        ("audit_policy_misconfig",lambda: check_audit_policy(audit_data)),
        ("audit_mgmt_issues",     lambda: check_audit_policy(audit_data)),
        ("default_pw_policy_bad", lambda: check_default_pw_policy(gpos)),
        ("weak_pw_gpo",           lambda: check_default_pw_policy(gpos)),
        ("gpo_misconfig_ou",      lambda: check_gpo_misconfig_ou(gpos)),
    ]

    results, failed_by_sev, unknown_items = run_checks(CHECKS)
    print_report("Category 9: Account & Audit Monitoring", results, failed_by_sev, unknown_items)

# ========= Shared runner =========
def run_checks(CHECKS):
    results=[]
    failed_by_sev={"High":[],"Medium":[],"Low":[]}
    unknown_items=[]

    for key,fn in CHECKS:
        status,details,is_unknown=fn()
        meta=CHECK_META[key]
        rec={
            "key":key,"title":meta["title"],"severity":meta["severity"],
            "score":meta["score"],"status":status,"unknown":is_unknown,
            "fail_items":len(details),"details":details
        }
        results.append(rec)

        # Treat FAIL + UNKNOWN as "failures"
        if status=="FAIL" or is_unknown:
            failed_by_sev[meta["severity"]].append(rec)
        if is_unknown:
            unknown_items.append(rec)

    return results,failed_by_sev,unknown_items

def print_report(title, results, failed_by_sev, unknown_items):
    total=len(results)
    failed_total=sum(1 for r in results if r["status"]=="FAIL" or r.get("unknown"))
    unknown_total=len(unknown_items)
    by_sev_counts=Counter(r["severity"] for r in results if r["status"]=="FAIL" or r.get("unknown"))
    category_risk_total=sum(r["score"] for r in results if r["status"]=="FAIL") # risk only for true FAILs
    risk_by_severity=defaultdict(int)
    for r in results:
        if r["status"]=="FAIL":
            risk_by_severity[r["severity"]]+=r["score"]

    print(f"\n=== {title} (Runtime Report) ===")
    print(f"Checks evaluated: {total}")
    print(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    print(f"Category 9 Total Risk Score: {category_risk_total}")
    print(f"  - High risk points:   {risk_by_severity['High']}")
    print(f"  - Medium risk points: {risk_by_severity['Medium']}")
    print(f"  - Low risk points:    {risk_by_severity['Low']}\n")

    print("Failures by severity:")
    print(f"  High  : {by_sev_counts.get('High',0)}")
    print(f"  Medium: {by_sev_counts.get('Medium',0)}")
    print(f"  Low   : {by_sev_counts.get('Low',0)}\n")

    for sev in ["High","Medium","Low"]:
        items=failed_by_sev[sev]
        if not items: 
            print(f"{sev}: (none)")
            continue
        print(f"{sev}:")
        for r in items:
            note=" -> needs additional data" if r.get("unknown") else ""
            print(f"  - {r['title']} (Score {r['score']}) -> {r['fail_items']} item(s){note}")
            for d in r["details"][:PRINT_MAX_DETAILS]:
                print(f"      • {d['Object']} - {d['Detail']}")
        print("")

# ========= Streamlit wrapper =========
def run_category9(input_dir: str):
    users=load_json(os.path.join(input_dir,USERS_FILE))
    gpos=load_json(os.path.join(input_dir,GPO_FILE))
    audit_data=None
    if AUDIT_FILE and os.path.exists(AUDIT_FILE):
        with open(AUDIT_FILE,"r",encoding="utf-8-sig") as f:
            audit_data=json.load(f)

    CHECKS=[
        ("locked_accounts",       lambda: check_locked_accounts(users)),
        ("inactive_accounts",     lambda: check_inactive_accounts(users)),
        ("audit_policy_misconfig",lambda: check_audit_policy(audit_data)),
        ("audit_mgmt_issues",     lambda: check_audit_policy(audit_data)),
        ("default_pw_policy_bad", lambda: check_default_pw_policy(gpos)),
        ("weak_pw_gpo",           lambda: check_default_pw_policy(gpos)),
        ("gpo_misconfig_ou",      lambda: check_gpo_misconfig_ou(gpos)),
    ]

    results, failed_by_sev, unknown_items = run_checks(CHECKS)

    # Build report text
    lines=[]
    lines.append("=== Category 9: Account & Audit Monitoring (Runtime Report) ===")
    lines.append(f"Checks evaluated: {len(results)}")
    lines.append(f"FAILED: {sum(1 for r in results if r['status']=='FAIL' or r.get('unknown'))} | UNKNOWN: {len(unknown_items)}")
    lines.append(f"Category 9 Total Risk Score: {sum(r['score'] for r in results if r['status']=='FAIL')}\n")

    for sev in ["High","Medium","Low"]:
        items=failed_by_sev[sev]
        if not items:
            lines.append(f"{sev}: (none)")
            continue
        lines.append(f"{sev}:")
        for r in items:
            note=" -> needs additional data" if r.get("unknown") else ""
            lines.append(f"  - {r['title']} (Score {r['score']}) -> {r['fail_items']} item(s){note}")
        lines.append("")

    report_text="\n".join(lines)

    # Summary dict
    summary={
        "High":len(failed_by_sev["High"]),
        "Medium":len(failed_by_sev["Medium"]),
        "Low":len(failed_by_sev["Low"]),
        "TotalFails":sum(1 for r in results if r["status"]=="FAIL" or r.get("unknown")),
        "RiskScore":sum(r["score"] for r in results if r["status"]=="FAIL"),
    }

    return report_text, summary

if __name__=="__main__":
    main()
