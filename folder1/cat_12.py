#!/usr/bin/env python3
import os, json
from datetime import datetime, timezone
from collections import Counter, defaultdict
from typing import List, Dict, Any

# ========= CONFIG =========
INPUT_DIR = r"C:\Users\LENOVO\OneDrive\Desktop\dissertation\Nexora.local"
COMPUTERS_FILE = "nexora.local_computers.json"
DOMAINS_FILE   = "nexora.local_domains.json"

PRINT_MAX_DETAILS = 10

# ========= Risk model (Category 12) =========
CHECK_META = {
    "computers_with_bitlocker":      {"title": "Computers with BitLocker keys",              "severity": "Info",   "score": 0},
    "domain_controllers":            {"title": "Domain Controllers identified",              "severity": "Info",   "score": 0},
    "kerberos_config":               {"title": "Kerberos configuration present",             "severity": "Medium", "score": 24},
    "non_admins_can_add_computers":  {"title": "Non-admin users can add computers to domain","severity": "Medium", "score": 24},
    "recently_backed_up":            {"title": "Computers backed up within 7 days",          "severity": "Low",    "score": 12},
    "up_to_date_computers":          {"title": "Computers up-to-date within 30 days",        "severity": "Low",    "score": 12},
    "smb_signing_required":          {"title": "SMB signing required",                       "severity": "Medium", "score": 24},
    "spooler_enabled":               {"title": "Spooler service enabled on computers",       "severity": "Medium", "score": 18},
    "ldap_signature_required":       {"title": "LDAP signature required",                    "severity": "Medium", "score": 24},
    "channel_binding_enforced":      {"title": "Channel binding enforced",                   "severity": "Medium", "score": 24},
}

# ========= Helpers =========
def load_json_list(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path): return []
    with open(path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
        return data["data"]
    if isinstance(data, list): return data
    return []

def prop(d: Dict[str, Any], key: str, default=None):
    return (d.get("Properties") or {}).get(key, default)

# ========= Checks =========
def check_computers_with_bitlocker(computers):
    bad = []
    for comp in computers:
        if prop(comp, "bitlockerkeys"):
            bad.append({"Object": prop(comp,"name"), "Detail":"BitLocker key present"})
    return ("PASS", bad) if bad else ("UNKNOWN", [])

def check_domain_controllers(computers):
    dcs = []
    for comp in computers:
        dn = prop(comp,"distinguishedname","").lower()
        if "domain controllers" in dn:
            dcs.append({"Object":prop(comp,"name"), "Detail":"Domain Controller OU"})
    return ("PASS", dcs) if dcs else ("UNKNOWN", [])

def check_kerberos_config(kerberos_config=None):
    if kerberos_config is None:
        return ("UNKNOWN", [])
    return ("PASS", [{"Object":"Domain","Detail":"Kerberos config provided"}])

def check_non_admins_can_add_computers(domains):
    for d in domains:
        for ace in d.get("Aces",[]):
            rn = ace.get("RightName","").lower()
            principal = ace.get("PrincipalSID","").lower()
            if rn == "add workstation to domain" and ("authenticated users" in principal or "users" in principal):
                return ("FAIL",[{"Object":"Domain","Detail":f"ACE grants {rn} to {principal}"}])
    return ("PASS", [])

def check_recently_backed_up(computers):
    bad=[]
    now = datetime.now(timezone.utc).timestamp()
    threshold = now - 7*24*3600
    for comp in computers:
        lb = prop(comp,"lastbackup",0)
        if lb and lb > threshold:
            bad.append({"Object":prop(comp,"name"),"Detail":"Recent backup"})
    return ("PASS", bad) if bad else ("FAIL", [])

def check_up_to_date(computers):
    bad=[]
    now = datetime.now(timezone.utc).timestamp()
    threshold = now - 30*24*3600
    for comp in computers:
        lu = prop(comp,"lastupdate",0)
        if lu and lu > threshold:
            bad.append({"Object":prop(comp,"name"),"Detail":"Up to date"})
    return ("PASS", bad) if bad else ("FAIL", [])

def check_smb_signing(domains):
    for d in domains:
        for ace in d.get("Aces",[]):
            if ace.get("RightName","").lower() == "require smb signing":
                return ("PASS",[{"Object":"Domain","Detail":"Require SMB signing ACE present"}])
    return ("FAIL", [])

def check_spooler_enabled(computers):
    bad=[]
    for comp in computers:
        for svc in comp.get("Services",[]):
            if svc.get("Name","").lower()=="spooler" and svc.get("StartMode","").lower()=="automatic":
                bad.append({"Object":prop(comp,"name"),"Detail":"Spooler service Automatic"})
    return ("FAIL",bad) if bad else ("PASS", [])

def check_ldap_signature(domains):
    for d in domains:
        for ace in d.get("Aces",[]):
            if ace.get("RightName","").lower()=="require ldap signature":
                return ("PASS",[{"Object":"Domain","Detail":"LDAP signature required"}])
    return ("FAIL", [])

def check_channel_binding(domains):
    for d in domains:
        for ace in d.get("Aces",[]):
            if ace.get("RightName","").lower()=="enforce channel binding":
                return ("PASS",[{"Object":"Domain","Detail":"Channel binding enforced"}])
    return ("FAIL", [])

# ========= Run Category 12 =========
def run_category12(input_dir: str):
    computers = load_json_list(os.path.join(input_dir, COMPUTERS_FILE))
    domains   = load_json_list(os.path.join(input_dir, DOMAINS_FILE))

    CHECKS = [
        ("computers_with_bitlocker",      lambda: check_computers_with_bitlocker(computers)),
        ("domain_controllers",            lambda: check_domain_controllers(computers)),
        ("kerberos_config",               lambda: check_kerberos_config(None)),  # replace None with kerberos_config
        ("non_admins_can_add_computers",  lambda: check_non_admins_can_add_computers(domains)),
        ("recently_backed_up",            lambda: check_recently_backed_up(computers)),
        ("up_to_date_computers",          lambda: check_up_to_date(computers)),
        ("smb_signing_required",          lambda: check_smb_signing(domains)),
        ("spooler_enabled",               lambda: check_spooler_enabled(computers)),
        ("ldap_signature_required",       lambda: check_ldap_signature(domains)),
        ("channel_binding_enforced",      lambda: check_channel_binding(domains)),
    ]

    results = []
    failed_by_sev = {"High": [], "Medium": [], "Low": [], "Info": []}
    unknown_items = []

    for key, fn in CHECKS:
        status, details = fn()
        meta = CHECK_META[key]
        rec = {
            "key": key,
            "title": meta["title"],
            "severity": meta["severity"],
            "score": meta["score"],
            "status": status,
            "fail_items": len(details),
            "details": details,
        }
        results.append(rec)
        if status in ("FAIL", "UNKNOWN"):
            failed_by_sev.setdefault(meta["severity"], []).append(rec)
            if status == "UNKNOWN":
                unknown_items.append(rec)

    total = len(results)
    failed_total = sum(1 for r in results if r["status"] == "FAIL")
    unknown_total = len(unknown_items)

    # Risk score only from FAIL + UNKNOWN, but Info has score=0 anyway
    category_risk_total = sum(r["score"] for r in results if r["status"] in ("FAIL","UNKNOWN"))
    risk_by_severity = {"High":0,"Medium":0,"Low":0,"Info":0}
    for r in results:
        if r["status"] in ("FAIL","UNKNOWN"):
            risk_by_severity[r["severity"]] += r["score"]

    # Build report text
    lines = []
    lines.append("=== Category 12: Computer & Domain Management (Runtime Report) ===")
    lines.append(f"Checks evaluated: {total}")
    lines.append(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    lines.append(f"Category 12 Total Risk Score: {category_risk_total}")
    lines.append(f"  - High risk points:   {risk_by_severity['High']}")
    lines.append(f"  - Medium risk points: {risk_by_severity['Medium']}")
    lines.append(f"  - Low risk points:    {risk_by_severity['Low']}")
    lines.append(f"  - Info:               {len(failed_by_sev['Info'])}\n")

    for sev in ["High","Medium","Low","Info"]:
        items = failed_by_sev[sev]
        if not items:
            lines.append(f"{sev}: (none)")
            continue
        lines.append(f"{sev}:")
        for r in items:
            lines.append(f"  - {r['title']} (Score {r['score']}) -> {r['fail_items']} item(s)")
            for d in r["details"][:PRINT_MAX_DETAILS]:
                lines.append(f"      • {d.get('Object')} - {d.get('Detail')}")
        lines.append("")

    if unknown_items:
        lines.append("Non-passing (UNKNOWN) checks (counted as FAIL):")
        for r in unknown_items:
            lines.append(f"  - {r['title']} ({r['severity']}, Score {r['score']}) -> needs additional data")

    report_text = "\n".join(lines)

    summary = {
        "High": len(failed_by_sev["High"]),
        "Medium": len(failed_by_sev["Medium"]),
        "Low": len(failed_by_sev["Low"]),
        "Info": len(failed_by_sev["Info"]),
        "TotalFails": failed_total,
        "Unknown": unknown_total,
        "RiskScore": category_risk_total,
    }

    return report_text, summary
