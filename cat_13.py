#!/usr/bin/env python3
# Category 13 – Privilege & Trust Management (Runtime Report)
# Refined checks for:
#  - Authentication policy silos misconfigured
#  - Trust accounts for delegation misused
#  - GPO folder/file rights misconfigured
# Plus: registry rights, container control delegations, Se* privileges, RBAC, DNS create rights, constrained delegation

import os, json, re
from typing import Any, Dict, List, Tuple
from collections import Counter, defaultdict

# ======== CONFIG ========
INPUT_DIR       = r"C:\Users\LENOVO\OneDrive\Desktop\dissertation\Nexora.local"  # change if needed
CONTAINERS_FILE = "nexora.local_containers.json"
USERS_FILE      = "nexora.local_users.json"
GROUPS_FILE     = "nexora.local_groups.json"
COMPUTERS_FILE  = "nexora.local_computers.json"
GPOS_FILE       = "nexora.local_gpos.json"
DOMAINS_FILE    = "nexora.local_domains.json"

PRINT_MAX_DETAILS = 10  # 0 = unlimited

# Heuristics for “safe” vs “risky” principals
ALLOWED_ADMIN_TOKENS = [
    "domain admins", "enterprise admins", "administrators", "schema admins",
    "system", "exchange organization administrators", "group policy creator owners"
]
RISKY_PRINCIPAL_TOKENS = [
    "authenticated users", "domain users", "users", "everyone",
    "guests", "pre-windows 2000", "anonymous", "remote desktop users"
]

# SID patterns
ADMIN_SID_PATTERNS = [
    r"^S-1-5-32-544$",               # Builtin Administrators
    r".*-512$",                      # Domain Admins
    r".*-519$",                      # Enterprise Admins
    r".*-518$",                      # Schema Admins
]
RISKY_SID_PATTERNS = [
    r"^S-1-1-0$",                    # Everyone
    r"^S-1-5-11$",                   # Authenticated Users
    r"^S-1-5-7$",                    # Anonymous
    r"^S-1-5-32-545$",               # Users
    r"^S-1-5-32-546$",               # Guests
    r".*-513$",                      # Domain Users
]

# ======== Risk model (scores) ========
CHECK_META = {
    "registry_rights_misconfig":     {"title":"Registry access rights misconfigured",                 "severity":"Medium", "score":24},
    "container_delegations_insecure":{"title":"Control delegations by container insecure",            "severity":"High",   "score":40},
    "privilege_rights_excessive":    {"title":"Privilege rights (SeDebug, SeBackup, etc.) excessive", "severity":"High",   "score":40},
    "auth_policy_silos_misconfig":   {"title":"Authentication policy silos misconfigured",            "severity":"Medium", "score":24},
    "trust_accounts_misused":        {"title":"Trust accounts for delegation misused",                "severity":"High",   "score":40},
    "rbac_misconfigured":            {"title":"Computers with RBAC misconfigured",                    "severity":"Medium", "score":18},
    "dns_create_unauthorized":       {"title":"User can create DNS records (unauthorized)",           "severity":"Medium", "score":24},
    "constrained_delegation_issues": {"title":"Computers with constrained delegation issues",         "severity":"High",   "score":40},
    "gpo_folder_file_rights_misconf":{"title":"Group policy folder/file rights misconfigured",        "severity":"High",   "score":40},
}

# ======== helpers ========
def pjoin(*a): return os.path.join(*a)

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

def any_text(s) -> str:
    return (s or "").strip()

def match_any_token(s: str, tokens: List[str]) -> bool:
    ls = s.lower()
    return any(tok in ls for tok in tokens)

def match_sid_patterns(s: str, patterns: List[str]) -> bool:
    for pat in patterns:
        if re.search(pat, s, flags=re.IGNORECASE):
            return True
    return False

def principal_is_admin(principal: str) -> bool:
    if match_any_token(principal, ALLOWED_ADMIN_TOKENS): return True
    if match_sid_patterns(principal, ADMIN_SID_PATTERNS): return True
    return False

def principal_is_risky(principal: str) -> bool:
    if match_any_token(principal, RISKY_PRINCIPAL_TOKENS): return True
    if match_sid_patterns(principal, RISKY_SID_PATTERNS): return True
    return False

def collect_aces(objs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for o in objs:
        for ace in o.get("Aces", []) or []:
            out.append(ace)
    return out

# ======== load data ========
containers = load_json_list(pjoin(INPUT_DIR, CONTAINERS_FILE))
users      = load_json_list(pjoin(INPUT_DIR, USERS_FILE))
groups     = load_json_list(pjoin(INPUT_DIR, GROUPS_FILE))
computers  = load_json_list(pjoin(INPUT_DIR, COMPUTERS_FILE))
gpos       = load_json_list(pjoin(INPUT_DIR, GPOS_FILE))
domains    = load_json_list(pjoin(INPUT_DIR, DOMAINS_FILE))

gpo_aces       = collect_aces(gpos)
container_aces = collect_aces(containers)

# ======== checks ========
def check_registry_rights_misconfig() -> Tuple[str, List[Dict[str,str]]]:
    """Flag if registry-related rights in GPOs/containers are granted to risky principals."""
    hits = []
    seen = False
    for ace in (gpo_aces + container_aces):
        rn = any_text(ace.get("RightName",""))
        pr = any_text(ace.get("PrincipalSID") or ace.get("PrincipalName") or "")
        if "registry" in rn.lower():
            seen = True
            if principal_is_risky(pr):
                hits.append({"Object":"Registry Right", "Detail": f"{rn} granted to {pr}"})
    if not seen:
        return ("UNKNOWN", [])
    return ("FAIL", hits) if hits else ("PASS", [])

def check_container_delegations_insecure() -> Tuple[str, List[Dict[str,str]]]:
    """Flag GenericAll/GenericWrite/WriteOwner/WriteDacl on containers by non-admins."""
    dangerous = {"genericall","genericwrite","writeowner","writedacl","writeproperty"}
    hits = []
    seen = False
    for cont in containers:
        name = prop(cont, "name", "<container>")
        for ace in cont.get("Aces", []) or []:
            rn = any_text(ace.get("RightName",""))
            pr = any_text(ace.get("PrincipalSID") or ace.get("PrincipalName") or "")
            if rn and rn.lower() in dangerous:
                seen = True
                if not principal_is_admin(pr):
                    hits.append({"Object": name, "Detail": f"{rn} granted to {pr}"})
    if not seen:
        return ("UNKNOWN", [])
    return ("FAIL", hits) if hits else ("PASS", [])

def check_privilege_rights_excessive() -> Tuple[str, List[Dict[str,str]]]:
    """Flag Se*Privilege granted to risky principals (domain/group ACEs)."""
    hits = []
    seen = False
    scan_objs = domains + groups
    for obj in scan_objs:
        objname = prop(obj, "name", "<object>")
        for ace in obj.get("Aces", []) or []:
            rn = any_text(ace.get("RightName",""))
            pr = any_text(ace.get("PrincipalSID") or ace.get("PrincipalName") or "")
            if rn.startswith("Se") and rn.endswith("Privilege"):
                seen = True
                if principal_is_risky(pr) and not principal_is_admin(pr):
                    hits.append({"Object": objname, "Detail": f"{rn} assigned to {pr}"})
    if not seen:
        return ("UNKNOWN", [])
    return ("FAIL", hits) if hits else ("PASS", [])

def check_auth_policy_silos_misconfig() -> Tuple[str, List[Dict[str,str]]]:
    """
    Heuristic:
      - If there are admin users (admincount=True) and NONE have AuthenticationPolicySilo -> FAIL.
      - If at least one admin has a silo -> PASS.
      - If there are no admin users in data -> UNKNOWN.
    """
    admins = [u for u in users if bool(prop(u,"admincount", False))]
    if not admins:
        return ("UNKNOWN", [])
    admins_with_silo = [prop(u,"name","<user>") for u in admins if any_text(prop(u,"AuthenticationPolicySilo"))]
    if admins_with_silo:
        return ("PASS", [])
    return ("FAIL", [{"Object":"Users","Detail":"Admin users present but no AuthenticationPolicySilo assigned"}])

def _get_trust_field(trust: Dict[str,Any], key: str):
    # case-insensitive getter for common trust fields
    for k,v in trust.items():
        if k.lower() == key.lower():
            return v
    return None

def check_trust_accounts_misused() -> Tuple[str, List[Dict[str,str]]]:
    """
    Heuristic for misuse:
      - Trust is External/Forest (or any) AND (SelectiveAuthentication is False/0/No OR SID filtering disabled)
      - Direction is inbound or bidirectional
    If no trust data -> UNKNOWN
    """
    trusts = []
    for d in domains:
        trusts.extend(d.get("Trusts", []) or [])
    if not trusts:
        return ("UNKNOWN", [])

    hits = []
    for t in trusts:
        tname = (_get_trust_field(t,"TrustingName") or _get_trust_field(t,"TrustedName") or prop(t,"name","<trust>"))
        ttype = str(_get_trust_field(t,"TrustType") or "").lower()
        tdir  = str(_get_trust_field(t,"TrustDirection") or "").lower()
        sel   = _get_trust_field(t,"SelectiveAuthentication")
        sidf  = _get_trust_field(t,"SIDFilteringEnabled")

        # normalize booleans (True/False/"true"/1)
        def to_bool(x):
            if isinstance(x, bool): return x
            s = str(x).strip().lower()
            if s in ("true","1","yes","enabled"): return True
            if s in ("false","0","no","disabled"): return False
            return None

        sel_b  = to_bool(sel)
        sidf_b = to_bool(sidf)

        direction_risky = (tdir in ("two-way","bidirectional","both","inbound"))
        type_risky = True if not ttype else ("external" in ttype or "forest" in ttype or "realm" in ttype or "parent" in ttype)

        # Any explicit disablement of selective auth or SID filtering is risky
        selective_bad = (sel_b is False)
        sidfilter_bad = (sidf_b is False)

        if direction_risky and type_risky and (selective_bad or sidfilter_bad):
            reason = []
            if selective_bad: reason.append("SelectiveAuthentication=Disabled")
            if sidfilter_bad: reason.append("SIDFilteringEnabled=Disabled")
            hits.append({"Object": tname or "<trust>", "Detail": f"Type={ttype or 'unknown'}, Direction={tdir or 'unknown'}; " + ", ".join(reason)})

    return ("FAIL", hits) if hits else ("PASS", [])

def check_rbac_misconfigured() -> Tuple[str, List[Dict[str,str]]]:
    """
    If any computer explicitly has RBAC flag and it's False -> FAIL for that computer.
    If at least one has RBAC=True and none False -> PASS.
    If no computer has an explicit RBAC flag -> UNKNOWN.
    """
    any_flag = False
    bad = []
    for c in computers:
        name = prop(c,"name","<computer>")
        if "rbac" in (c.get("Properties") or {}):
            any_flag = True
            if not bool(prop(c,"rbac")):
                bad.append({"Object": name, "Detail":"RBAC=False"})
    if not any_flag:
        return ("UNKNOWN", [])
    return ("FAIL", bad) if bad else ("PASS", [])

def check_dns_create_unauthorized() -> Tuple[str, List[Dict[str,str]]]:
    """Flag users who have ACE 'Create DNS Record' (or similar). Unknown if no ACEs present anywhere."""
    seen_any_aces = False
    bad = []
    for u in users:
        uname = prop(u,"name","<user>")
        for ace in u.get("Aces", []) or []:
            seen_any_aces = True
            rn = any_text(ace.get("RightName",""))
            if "create dns record" in rn.lower():
                bad.append({"Object": uname, "Detail": f"{rn}"})
                break
    if not seen_any_aces:
        return ("UNKNOWN", [])
    return ("FAIL", bad) if bad else ("PASS", [])

def check_constrained_delegation_issues() -> Tuple[str, List[Dict[str,str]]]:
    """
    Heuristic:
      - If a computer has msDS-AllowedToDelegateTo (non-empty) -> flag (potential risk)
      - If TrustedToAuthForDelegation is True -> flag (protocol transition)
    UNKNOWN if no computers expose any of these attributes.
    """
    saw_attr = False
    hits = []
    for c in computers:
        name = prop(c,"name","<computer>")
        props = c.get("Properties") or {}
        atd = props.get("msds-allowedtodelegateto") or props.get("msDS-AllowedToDelegateTo")
        t2a = props.get("trustedtoauthfordelegation") or props.get("TrustedToAuthForDelegation")
        cdel= props.get("constraineddelegation") or props.get("ConstrainedDelegation")

        if atd is not None or t2a is not None or cdel is not None:
            saw_attr = True

        details = []
        if atd: details.append(f"AllowedToDelegateTo count={len(atd) if isinstance(atd,list) else 1}")
        if t2a: details.append("TrustedToAuthForDelegation=True")
        if cdel: details.append("ConstrainedDelegation=True")

        if details:
            hits.append({"Object": name, "Detail": ", ".join(details)})

    if not saw_attr:
        return ("UNKNOWN", [])
    return ("FAIL", hits) if hits else ("PASS", [])

def check_gpo_folder_file_rights_misconf() -> Tuple[str, List[Dict[str,str]]]:
    """
    Flag suspicious write/modify rights on GPO objects assigned to non-admin principals.
    We look for rights like: GenericAll, GenericWrite, WriteDacl, WriteOwner, Write, Modify.
    UNKNOWN if there are no GPO ACEs.
    """
    if not gpo_aces:
        return ("UNKNOWN", [])
    suspicious = {"genericall","genericwrite","writedacl","writeowner","write","modify","writeproperty","addmember"}
    hits = []
    for g in gpos:
        gname = prop(g,"name","<GPO>")
        for ace in g.get("Aces", []) or []:
            rn = any_text(ace.get("RightName",""))
            pr = any_text(ace.get("PrincipalSID") or ace.get("PrincipalName") or "")
            if rn and rn.lower() in suspicious and not principal_is_admin(pr):
                hits.append({"Object": gname, "Detail": f"{rn} granted to {pr}"})
    return ("FAIL", hits) if hits else ("PASS", [])

# ======== run & report ========
CHECKS = [
    ("registry_rights_misconfig",     check_registry_rights_misconfig),
    ("container_delegations_insecure",check_container_delegations_insecure),
    ("privilege_rights_excessive",    check_privilege_rights_excessive),
    ("auth_policy_silos_misconfig",   check_auth_policy_silos_misconfig),
    ("trust_accounts_misused",        check_trust_accounts_misused),
    ("rbac_misconfigured",            check_rbac_misconfigured),
    ("dns_create_unauthorized",       check_dns_create_unauthorized),
    ("constrained_delegation_issues", check_constrained_delegation_issues),
    ("gpo_folder_file_rights_misconf",check_gpo_folder_file_rights_misconf),
]

def main():
    results: List[Dict[str, Any]] = []
    failed_by_sev: Dict[str, List[Dict[str, Any]]] = {"High": [], "Medium": [], "Low": []}

    for key, fn in CHECKS:
        status, details = fn()
        meta = CHECK_META[key]
        rec = {
            "key": key,
            "title": meta["title"],
            "severity": meta["severity"],
            "score": meta["score"],
            "status": status,                 # PASS / FAIL / UNKNOWN
            "fail_items": len(details),
            "details": details,
        }
        results.append(rec)
        if status == "FAIL":
            failed_by_sev[meta["severity"]].append(rec)

    # ===== summary =====
    total         = len(results)
    failed_total  = sum(1 for r in results if r["status"] == "FAIL")
    unknown_total = sum(1 for r in results if r["status"] == "UNKNOWN")

    by_sev_counts = Counter()
    for r in results:
        if r["status"] == "FAIL":
            by_sev_counts[r["severity"]] += 1

    category_risk_total = sum(r["score"] for r in results if r["status"] == "FAIL")
    risk_by_severity = defaultdict(int)
    for r in results:
        if r["status"] == "FAIL":
            risk_by_severity[r["severity"]] += r["score"]

    print("\n=== Category 13: Privilege & Trust Management (Runtime Report) ===")
    print(f"Checks evaluated: {total}")
    print(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    print(f"Category 13 Total Risk Score: {category_risk_total}")
    print(f"  - High risk points:   {risk_by_severity['High']}")
    print(f"  - Medium risk points: {risk_by_severity['Medium']}")
    print(f"  - Low risk points:    {risk_by_severity['Low']}\n")

    print("Failures by severity:")
    print(f"  High  : {by_sev_counts.get('High', 0)}")
    print(f"  Medium: {by_sev_counts.get('Medium', 0)}")
    print(f"  Low   : {by_sev_counts.get('Low', 0)}\n")

    def print_failed_block(sev: str, max_details: int = PRINT_MAX_DETAILS):
        items = failed_by_sev.get(sev, [])
        if not items:
            print(f"{sev}: (none)")
            return
        print(f"{sev}:")
        for r in items:
            print(f"  - {r['title']}  (Score {r['score']})  -> {r['fail_items']} item(s)")
            details = r["details"]
            if max_details and len(details) > max_details:
                for d in details[:max_details]:
                    print(f"      • {d.get('Object')} - {d.get('Detail')}")
                print(f"      ... and {len(details)-max_details} more")
            else:
                for d in details:
                    print(f"      • {d.get('Object')} - {d.get('Detail')}")
        print()

    print_failed_block("High")
    print_failed_block("Medium")
    print_failed_block("Low")

    print("Non-passing (UNKNOWN) checks:")
    for r in results:
        if r["status"] == "UNKNOWN":
            print(f"  - {r['title']} ({r['severity']}, Score {r['score']}) -> needs additional data")
    print()

if __name__ == "__main__":
    main()

def run_category13(input_dir: str):
    """
    Wrapper for Category 13: Privilege & Trust Management
    Returns (report_text, summary_dict)
    """
    results: List[Dict[str, Any]] = []
    failed_by_sev: Dict[str, List[Dict[str, Any]]] = {"High": [], "Medium": [], "Low": []}
    unknown_items: List[Dict[str, Any]] = []

    for key, fn in CHECKS:
        status, details = fn()
        meta = CHECK_META[key]
        rec = {
            "key": key,
            "title": meta["title"],
            "severity": meta["severity"],
            "score": meta["score"],
            "status": status,  # PASS / FAIL / UNKNOWN
            "fail_items": len(details),
            "details": details,
        }
        results.append(rec)

        if status in ("FAIL", "UNKNOWN"):
            failed_by_sev.setdefault(meta["severity"], []).append(rec)
            if status == "UNKNOWN":
                unknown_items.append(rec)

    # ===== summary =====
    total         = len(results)
    failed_total  = sum(1 for r in results if r["status"] == "FAIL")
    unknown_total = len(unknown_items)

    category_risk_total = sum(r["score"] for r in results if r["status"] in ("FAIL", "UNKNOWN"))
    risk_by_severity = {"High":0, "Medium":0, "Low":0}
    for r in results:
        if r["status"] in ("FAIL", "UNKNOWN"):
            risk_by_severity[r["severity"]] += r["score"]

    # ===== build report text =====
    lines = []
    lines.append("=== Category 13: Privilege & Trust Management (Runtime Report) ===")
    lines.append(f"Checks evaluated: {total}")
    lines.append(f"FAILED: {failed_total} | UNKNOWN: {unknown_total}")
    lines.append(f"Category 13 Total Risk Score: {category_risk_total}")
    lines.append(f"  - High risk points:   {risk_by_severity['High']}")
    lines.append(f"  - Medium risk points: {risk_by_severity['Medium']}")
    lines.append(f"  - Low risk points:    {risk_by_severity['Low']}\n")

    lines.append("Failures by severity:")
    lines.append(f"  High  : {len(failed_by_sev['High'])}")
    lines.append(f"  Medium: {len(failed_by_sev['Medium'])}")
    lines.append(f"  Low   : {len(failed_by_sev['Low'])}\n")

    for sev in ["High","Medium","Low"]:
        items = failed_by_sev[sev]
        if not items:
            lines.append(f"{sev}: (none)")
            continue
        lines.append(f"{sev}:")
        for r in items:
            lines.append(f"  - {r['title']}  (Score {r['score']}) -> {r['fail_items']} item(s)")
            for d in r["details"][:PRINT_MAX_DETAILS]:
                lines.append(f"      • {d.get('Object')} - {d.get('Detail')}")
        lines.append("")

    if unknown_items:
        lines.append("Non-passing (UNKNOWN) checks (counted as FAIL):")
        for r in unknown_items:
            lines.append(f"  - {r['title']} ({r['severity']}, Score {r['score']}) -> needs additional data")

    report_text = "\n".join(lines)

    # ===== summary for Streamlit =====
    summary = {
        "High": len(failed_by_sev["High"]),
        "Medium": len(failed_by_sev["Medium"]),
        "Low": len(failed_by_sev["Low"]),
        "TotalFails": failed_total,
        "Unknown": unknown_total,
        "RiskScore": category_risk_total,
    }

    return report_text, summary
